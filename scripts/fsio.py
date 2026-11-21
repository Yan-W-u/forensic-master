#!/usr/bin/env python3
"""fsio.py —— 安全的证据读取层

设计原则：
  1. 类型即函数：read_hive / read_log / read_text / read_evtx 各自写死上限
     —— 上限不由调用方决定，要放宽就设环境变量（运维动作，不是函数参数）
  2. 截断必须可见：读出半截数据时调用方在**程序里**能知道，不只在 stderr
  3. 枚举原语默认排除已删除项，删除状态放 Entry.deleted，不污染 name
  4. 列出/读出的 name 必须能原样拼回路径再打开（基本契约）

截断的对外语义：返回 (data, truncated)
  - 取证场景半截数据有时仍可用，所以不抛异常
  - 但调用方必须显式处理 truncated，不能不知情地使用
  - 想强制要求完整：check_complete() 包装器
"""
import os
import sys
import datetime
from collections import namedtuple

import pytsk3

# 各类型的读取上限（可用环境变量放宽）
_LIMITS = {
    'text': int(os.environ.get('FSIO_MAX_TEXT', 8 << 20)),     # 普通文本 8 MB
    'log': int(os.environ.get('FSIO_MAX_LOG', 256 << 20)),     # 日志 256 MB
    'hive': int(os.environ.get('FSIO_MAX_HIVE', 512 << 20)),   # 注册表 512 MB
    'evtx': int(os.environ.get('FSIO_MAX_EVTX', 512 << 20)),   # 事件日志 512 MB
}

_ENV = {
    'text': 'FSIO_MAX_TEXT',
    'log': 'FSIO_MAX_LOG',
    'hive': 'FSIO_MAX_HIVE',
    'evtx': 'FSIO_MAX_EVTX',
}

WARN = '!'

# 目录项：name 永远是干净文件名，可直接拼路径
Entry = namedtuple('Entry', 'name size is_dir deleted meta')

# 读取结果：(数据, 是否被截断)
ReadResult = namedtuple('ReadResult', 'data truncated size_expected size_actual')


def warn(msg):
    print('%s %s' % (WARN, msg), file=sys.stderr)


# ============================================================
# 文件状态
# ============================================================
def stat(fs, path):
    """返回 Entry 或 None（失败时打印原因）"""
    try:
        n = fs.open(path)
    except FileNotFoundError:
        warn('文件不存在: %s' % path)
        return None
    except PermissionError:
        warn('权限拒绝: %s' % path)
        return None
    except Exception as e:
        warn('打不开 %s: %s' % (path, e))
        return None
    m = n.info.meta
    if not m:
        warn('无元数据: %s' % path)
        return None
    nm = path.rstrip('/').rsplit('/', 1)[-1] or '/'
    return Entry(nm, m.size or 0,
                 m.type == pytsk3.TSK_FS_META_TYPE_DIR,
                 is_deleted(m), m)


def is_deleted(meta):
    """flags & TSK_FS_META_FLAG_UNALLOC (0x2) = 已删除"""
    if not meta:
        return False
    flags = getattr(meta, 'flags', 0) or 0
    return bool(flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)


# ============================================================
# 内部读取（唯一入口，kind 只用于文案与上限查表）
# ============================================================
def _read(fs, path, kind):
    """读整个文件。返回 ReadResult(data, truncated, size_expected, size_actual)

    kind 只决定上限和提示文案，不参与业务判断。
    """
    limit = _LIMITS.get(kind, _LIMITS['text'])

    try:
        n = fs.open(path)
    except FileNotFoundError:
        warn('文件不存在: %s' % path)
        return ReadResult(b'', True, 0, 0)
    except PermissionError:
        warn('权限拒绝: %s' % path)
        return ReadResult(b'', True, 0, 0)
    except Exception as e:
        warn('打开失败 %s: %s' % (path, e))
        return ReadResult(b'', True, 0, 0)

    m = n.info.meta
    if not m:
        warn('无元数据: %s' % path)
        return ReadResult(b'', True, 0, 0)

    size = m.size or 0
    want = min(size, limit)
    truncated = size > limit

    if truncated:
        warn('%s 大小 %d 超过 %s 上限 %d，只读前 %d（用 %s 放宽）'
             % (os.path.basename(path), size, kind, limit, want, _ENV.get(kind, '')))
        if kind in ('log', 'evtx'):
            warn('  %s 被从头截断 → 丢的是**最新**内容' % kind.upper())

    try:
        data = n.read_random(0, want)
    except Exception as e:
        warn('读取中断 %s @%d: %s' % (path, want, e))
        return ReadResult(b'', True, size, 0)

    if len(data) < want:
        warn('%s 期望 %d 实际 %d（短读）' % (path, want, len(data)))
        truncated = True

    return ReadResult(data, truncated, size, len(data))


def _read_tail(fs, path, nbytes):
    """读尾部 nbytes 字节"""
    st = stat(fs, path)
    if not st:
        return ReadResult(b'', True, 0, 0)
    if st.size <= nbytes:
        return _read(fs, path, 'log')
    try:
        node = fs.open(path)
        data = node.read_random(st.size - nbytes, nbytes)
        return ReadResult(data, st.size > nbytes, st.size, len(data))
    except Exception as e:
        warn('读尾失败 %s: %s' % (path, e))
        return ReadResult(b'', True, st.size, 0)


# ============================================================
# 对外读取接口 —— 上限写死，不接受 limit 参数
# ============================================================
def read_text(fs, path):
    """普通文本。返回 ReadResult。"""
    return _read(fs, path, 'text')


def read_hive(fs, path):
    """注册表 hive。返回 ReadResult。"""
    return _read(fs, path, 'hive')


def read_evtx(fs, path):
    """Windows 事件日志。返回 ReadResult。

    单独一条路径，避免落回 text 的 8 MB —— Security.evtx 动辄几十 MB，
    截断后 EvtxECmd 解析会**缺事件**而不报错。
    """
    return _read(fs, path, 'evtx')


def read_log(fs, path, tail=None):
    """日志。返回 ReadResult。

    tail=N      只读最后 N 字节 → 找「最后一次」「最近」
    tail=None   全量读（到 MAX_LOG）→ 统计「总共多少次」
    """
    if tail:
        r = _read_tail(fs, path, tail)
        # 丢掉可能被截断的首行
        i = r.data.find(b'\n')
        data = r.data[i + 1:] if i > 0 else r.data
        return ReadResult(data, r.truncated, r.size_expected, len(data))
    return _read(fs, path, 'log')


def read_head(fs, path, n=16):
    """只读文件头（判魔数用）。返回 bytes（不需要截断语义）。"""
    try:
        node = fs.open(path)
        return node.read_random(0, n)
    except Exception as e:
        warn('读头失败 %s: %s' % (path, e))
        return b''


# ============================================================
# 便捷包装：要字符串或强制完整的场合
# ============================================================
def text(fs, path):
    """read_text 的字符串版，截断时警告（不抛）。"""
    r = read_text(fs, path)
    return r.data.decode('utf-8', 'replace')


def log_text(fs, path, tail=None):
    """read_log 的字符串版。"""
    r = read_log(fs, path, tail)
    return r.data.decode('utf-8', 'replace')


def check_complete(r, what='数据'):
    """要求完整：截断则抛异常。用于「半截数据不可用」的场合。"""
    if r.truncated:
        raise IOError('%s 被截断：期望 %d 实际 %d'
                      % (what, r.size_expected, r.size_actual))
    return r.data


# ============================================================
# 目录列举 —— 核心 API
# ============================================================
def ls(fs, path, show_deleted=False, root=None):
    """列目录，**默认排除已删除项**。

    参数:
        show_deleted  是否包含已删除项（默认 False）
        root          若给出，Entry.name 变成完整路径

    返回 Entry 列表。Entry.name 永远是干净文件名：
        fs.open(path + '/' + e.name)   ← 契约：能原样拼回路径
    """
    out = []
    try:
        d = fs.open_dir(path)
    except FileNotFoundError:
        warn('目录不存在: %s' % path)
        return out
    except Exception as e:
        warn('列目录失败 %s: %s' % (path, e))
        return out

    base = (root if root is not None else path).rstrip('/')
    for en in d:
        try:
            nm = en.info.name.name.decode('utf-8', 'replace')
        except Exception:
            continue
        if nm in ('.', '..'):
            continue
        m = en.info.meta
        deleted = is_deleted(m)
        if deleted and not show_deleted:
            continue
        isdir = bool(m and m.type == pytsk3.TSK_FS_META_TYPE_DIR)
        full = (base + '/' + nm) if base else nm
        out.append(Entry(full, m.size if m else 0, isdir, deleted, m))
    return out


def ls_all(fs, path, root=None):
    """显式要全部（含已删除）。"""
    return ls(fs, path, show_deleted=True, root=root)


def fmt(entry, width=0):
    """展示用：加 [D] 前缀标记已删除。只用于打印，不用于拼路径。"""
    nm = entry.name
    if width and len(nm) > width:
        nm = nm[:max(0, width - 4)] + '...'
    tag = '[D] ' if entry.deleted else '    '
    return tag + nm


def path_of(entry, parent=None):
    """取可用于 fs.open() 的路径。"""
    if entry.name.startswith('/'):
        return entry.name
    return (parent.rstrip('/') + '/' + entry.name) if parent else entry.name


def count(entries, files_only=False, dirs_only=False):
    """统计辅助：默认只数未删除项"""
    rows = [e for e in entries if not e.deleted]
    if files_only:
        rows = [e for e in rows if not e.is_dir]
    elif dirs_only:
        rows = [e for e in rows if e.is_dir]
    return len(rows)


# ============================================================
# 时间戳（统一口径）
# ============================================================
UTC = datetime.timezone.utc


def ts_epoch(v, label=''):
    """pytsk3 epoch 秒 → 带 tz 的 UTC datetime"""
    if not v:
        return None
    try:
        return datetime.datetime.fromtimestamp(v, UTC)
    except Exception:
        return None


def ts_filetime(ft, label=''):
    """Windows FILETIME（100ns since 1601）→ 带 tz 的 UTC datetime"""
    if not ft:
        return None
    try:
        return (datetime.datetime(1601, 1, 1, tzinfo=UTC)
                + datetime.timedelta(microseconds=ft // 10))
    except Exception:
        return None


def fmt_time(dt, local=False):
    """统一格式化。默认 UTC 并标注，local=True 转本地并标注。"""
    if not dt:
        return '-'
    if local:
        return dt.astimezone().strftime('%Y-%m-%d %H:%M:%S') + ' LCL'
    return dt.astimezone(UTC).strftime('%Y-%m-%d %H:%M:%S') + ' UTC'


def fmt_epoch(v, local=False):
    return fmt_time(ts_epoch(v), local)


def fmt_filetime(ft, local=False):
    return fmt_time(ts_filetime(ft), local)


# ============================================================
# 自检
# ============================================================
if __name__ == '__main__':
    print('fsio 读取层')
    print('=' * 54)
    print('读取上限（类型即函数，调用方不能传 limit）：')
    for k, v in _LIMITS.items():
        print('  read_%-9s %6.0f MB   放宽: %s' % (k, v / 1e6, _ENV[k]))
    print()
    print('截断语义：返回 ReadResult(data, truncated, size_expected, size_actual)')
    print('  r.data        数据')
    print('  r.truncated   True = 读到半截，调用方必须处理')
    print('  check_complete(r)  要求完整，截断则抛异常')
    print()
    print('目录枚举：')
    print('  ls()       默认排除已删除（show_deleted=False）')
    print('  ls_all()   显式包含已删除')
    print('  Entry.name 永远是干净文件名，可直接拼路径')
    print('  fmt(e)     展示时才加 [D] 标记')
    print()
    print('--- Entry 字段 ---')
    print('  %s' % ' '.join(Entry._fields))
