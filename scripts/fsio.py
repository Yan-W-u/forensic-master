#!/usr/bin/env python3
"""fsio.py —— 安全的证据读取层

分层原则：
  底层 fsio.read_*()  → 返回 ReadResult（只表示「成功读到」，含事实）
  命令层 winkit.read() → 截断即抛异常（半截数据绝不静默返回）

两类失败严格分开：
  ReadFailed  根本没读到：不存在 / 权限 / IO 错误
  Truncated   读到了但不满：超上限 / 短读（继承 ReadFailed，带 data）

设计判据：
  「想忽略」和「想处理」在语法上必须不同。
  read(fs,p)            → 想忽略要写 try/except，写的时候看见 Truncated
  read_partial(fs,p)    → 明确接受半截，调用方负责标注
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

# 读取成功的结果
ReadResult = namedtuple('ReadResult', 'data truncated size_expected size_actual')


# ============================================================
# 失败语义：两类严格分开
# ============================================================
class ReadFailed(Exception):
    """根本没读到：文件不存在 / 权限拒绝 / IO 错误 / 无元数据"""

    def __init__(self, path, reason):
        self.path = path
        self.reason = reason
        super().__init__('%s: %s' % (path, reason))


class Truncated(ReadFailed):
    """读到了，但不满（超上限或短读）。data 是拿到的那部分。"""

    def __init__(self, path, expected, actual, data, kind='text'):
        self.data = data
        self.expected = expected
        self.actual = actual
        self.kind = kind
        env = _ENV.get(kind, 'FSIO_MAX_TEXT')
        hint = '缺失 %d 字节；放宽: set %s=%d' % (expected - actual, env, expected)
        if kind in ('log', 'evtx'):
            hint += '（从头截断 → 丢的是最新内容）'
        Exception.__init__(self, '%s 期望 %d 实际 %d。%s'
                           % (path, expected, actual, hint))


def warn(msg):
    print('%s %s' % (WARN, msg), file=sys.stderr)


# ============================================================
# 文件状态
# ============================================================
def stat(fs, path):
    """返回 Entry。失败抛 ReadFailed。"""
    try:
        n = fs.open(path)
    except FileNotFoundError:
        raise ReadFailed(path, '文件不存在')
    except PermissionError:
        raise ReadFailed(path, '权限拒绝')
    except Exception as e:
        raise ReadFailed(path, '打不开: %s' % e)

    m = n.info.meta
    if not m:
        raise ReadFailed(path, '无元数据')
    nm = path.rstrip('/').rsplit('/', 1)[-1] or '/'
    return Entry(nm, m.size or 0,
                 m.type == pytsk3.TSK_FS_META_TYPE_DIR,
                 is_deleted(m), m)


def stat_or_none(fs, path):
    """stat 的安全版：失败返回 None 并打印原因。用于「文件可能不存在」的探测。"""
    try:
        return stat(fs, path)
    except ReadFailed as e:
        warn(str(e))
        return None


def is_deleted(meta):
    """flags & TSK_FS_META_FLAG_UNALLOC (0x2) = 已删除"""
    if not meta:
        return False
    flags = getattr(meta, 'flags', 0) or 0
    return bool(flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)


# ============================================================
# 底层读取 —— 只返回「成功」的 ReadResult，失败抛异常
# ============================================================
def _read(fs, path, kind):
    """读整个文件。返回 ReadResult。

    只有两种情况：
      成功（可能 truncated=True）
      抛 ReadFailed（根本没读到）
    """
    limit = _LIMITS.get(kind, _LIMITS['text'])

    try:
        n = fs.open(path)
    except FileNotFoundError:
        raise ReadFailed(path, '文件不存在')
    except PermissionError:
        raise ReadFailed(path, '权限拒绝')
    except Exception as e:
        raise ReadFailed(path, '打不开: %s' % e)

    m = n.info.meta
    if not m:
        raise ReadFailed(path, '无元数据')

    size = m.size or 0
    want = min(size, limit)
    truncated = size > limit

    try:
        data = n.read_random(0, want)
    except Exception as e:
        raise ReadFailed(path, '读取中断 @%d: %s' % (want, e))

    if len(data) < want:
        truncated = True

    return ReadResult(data, truncated, size, len(data))


def _read_tail(fs, path, nbytes, kind='log'):
    """读尾部 nbytes。返回 ReadResult。"""
    st = stat(fs, path)
    if st.size <= nbytes:
        return _read(fs, path, kind)
    try:
        node = fs.open(path)
        data = node.read_random(st.size - nbytes, nbytes)
    except Exception as e:
        raise ReadFailed(path, '读尾失败: %s' % e)
    return ReadResult(data, st.size > nbytes, st.size, len(data))


# ============================================================
# 对外读取接口 —— 返回 ReadResult（底层，含事实）
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
    截断后 EvtxECmd 会**缺事件而不报错**。
    """
    return _read(fs, path, 'evtx')


def read_log(fs, path, tail=None):
    """日志。返回 ReadResult。

    tail=N      只读最后 N 字节 → 找「最后一次」「最近」
    tail=None   全量读（到 MAX_LOG）→ 统计「总共多少次」
    """
    if tail:
        r = _read_tail(fs, path, tail, 'log')
        i = r.data.find(b'\n')
        data = r.data[i + 1:] if i > 0 else r.data
        return ReadResult(data, r.truncated, r.size_expected, len(data))
    return _read(fs, path, 'log')


def read_head(fs, path, n=16):
    """只读文件头（判魔数用）。返回 bytes。"""
    try:
        node = fs.open(path)
        return node.read_random(0, n)
    except Exception as e:
        raise ReadFailed(path, '读头失败: %s' % e)


# ============================================================
# 目录列举
# ============================================================
def ls(fs, path, show_deleted=False, root=None):
    """列目录，**默认排除已删除项**。

    返回 Entry 列表。Entry.name 永远是干净文件名：
        fs.open(path + '/' + e.name)   ← 契约
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
    if entry.name.startswith('/'):
        return entry.name
    return (parent.rstrip('/') + '/' + entry.name) if parent else entry.name


def count(entries, files_only=False, dirs_only=False):
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
    if not v:
        return None
    try:
        return datetime.datetime.fromtimestamp(v, UTC)
    except Exception:
        return None


def ts_filetime(ft, label=''):
    if not ft:
        return None
    try:
        return (datetime.datetime(1601, 1, 1, tzinfo=UTC)
                + datetime.timedelta(microseconds=ft // 10))
    except Exception:
        return None


def fmt_time(dt, local=False):
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
    print('=' * 56)
    print('读取上限（类型即函数，不接受 limit）：')
    for k, v in _LIMITS.items():
        print('  read_%-9s %6.0f MB   放宽: %s' % (k, v / 1e6, _ENV[k]))
    print()
    print('失败语义（两类严格分开）：')
    print('  ReadFailed   根本没读到：不存在 / 权限 / IO / 无元数据')
    print('  Truncated    读到了但不满，带 data/expected/actual（继承 ReadFailed）')
    print()
    print('底层返回 ReadResult(data, truncated, size_expected, size_actual)')
    print('命令层（winkit.read）截断即抛 Truncated')
    print()
    print('目录枚举：')
    print('  ls()       默认排除已删除')
    print('  ls_all()   显式包含已删除')
    print('  Entry.name 永远是干净文件名，可直接拼路径')
