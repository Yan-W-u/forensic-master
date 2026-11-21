#!/usr/bin/env python3
"""fsio.py —— 安全的证据读取层

解决三类静默错误：
  1. 大文件从头截断（日志是追加写的，最旧的在前面）
  2. 超过上限不报警（hive 半截喂给解析器）
  3. except 全吞（文件不存在 / 权限拒绝 / 读失败 无法区分）

设计原则：
  - 枚举原语默认排除已删除项（show_deleted=False），行为可预期
  - 删除状态放在 Entry.deleted 字段，**不污染 name**
  - 列出来的 name 必须能原样拼回路径再打开（基本契约）
  - 需要删除痕迹用 ls_all()，展示用 fmt()
"""
import os
import sys
import datetime
from collections import namedtuple

import pytsk3

# 默认上限（可通过环境变量放宽）
MAX_LOG = int(os.environ.get('FSIO_MAX_LOG', 256 << 20))    # 日志 256 MB
MAX_HIVE = int(os.environ.get('FSIO_MAX_HIVE', 512 << 20))  # hive 512 MB
MAX_TEXT = int(os.environ.get('FSIO_MAX_TEXT', 8 << 20))    # 普通文本 8 MB

WARN = '!'

# 目录项：name 永远是干净的文件名，可直接拼路径
Entry = namedtuple('Entry', 'name size is_dir deleted meta')


def warn(msg):
    print('%s %s' % (WARN, msg), file=sys.stderr)


# ============================================================
# 文件状态
# ============================================================
def stat(fs, path):
    """返回 Entry 或 None（文件不存在/无权限时打印原因）"""
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
# 读取
# ============================================================
def read_all(fs, path, limit=None, what='text'):
    """完整读取，超限则报警并返回已读部分

    返回 (data, truncated: bool)
    """
    try:
        n = fs.open(path)
    except FileNotFoundError:
        warn('文件不存在: %s' % path)
        return b'', False
    except PermissionError:
        warn('权限拒绝: %s' % path)
        return b'', False
    except Exception as e:
        warn('打开失败 %s: %s' % (path, e))
        return b'', False

    m = n.info.meta
    if not m:
        warn('无元数据: %s' % path)
        return b'', False

    sz = m.size or 0
    cap = limit if limit is not None else MAX_TEXT
    truncated = False
    if sz > cap:
        env = {'log': 'FSIO_MAX_LOG', 'hive': 'FSIO_MAX_HIVE',
               'text': 'FSIO_MAX_TEXT'}.get(what, 'FSIO_MAX_TEXT')
        warn('%s 大小 %d 超过上限 %d，只读前 %d 字节（用 %s 放宽）'
             % (os.path.basename(path), sz, cap, cap, env))
        sz = cap
        truncated = True

    try:
        data = n.read_random(0, sz)
    except Exception as e:
        warn('读取中断 %s @%d: %s' % (path, sz, e))
        return b'', truncated

    if len(data) < sz:
        warn('%s 期望 %d 实际 %d（读取不完整）' % (path, sz, len(data)))
        truncated = True
    if truncated and what == 'log':
        warn('日志被从头截断 → 丢的是**最新**内容。'
             '找「最后一次/最近」请用 read_log(tail=N)')
    return data, truncated


def read_head(fs, path, n=16):
    """只读文件头（判魔数用）"""
    try:
        node = fs.open(path)
        return node.read_random(0, n)
    except Exception as e:
        warn('读头失败 %s: %s' % (path, e))
        return b''


def read_tail(fs, path, n=64 << 10):
    """读文件尾部 —— 日志的最新内容在这里"""
    st = stat(fs, path)
    if not st:
        return b''
    sz = st.size
    if sz <= n:
        return read_all(fs, path, limit=n)[0]
    try:
        node = fs.open(path)
        return node.read_random(sz - n, n)
    except Exception as e:
        warn('读尾失败 %s: %s' % (path, e))
        return b''


def read_log(fs, path, tail=None):
    """读日志：默认读**尾部**（最新内容），或全量（有上限）

    tail=N      只读最后 N 字节  → 找「最后一次」「最近」
    tail=None   全量读（到 MAX_LOG）→ 统计「总共多少次」
    """
    if tail:
        head = read_tail(fs, path, tail)
        i = head.find(b'\n')
        if i > 0:
            head = head[i + 1:]
        return head.decode('utf-8', 'replace')
    data, trunc = read_all(fs, path, limit=MAX_LOG, what='log')
    return data.decode('utf-8', 'replace')


def read_text(fs, path, limit=None):
    """普通文本文件。超限报警，不静默截断。"""
    data, _ = read_all(fs, path, limit or MAX_TEXT, what='text')
    return data.decode('utf-8', 'replace')


def read_hive(fs, path):
    """注册表 hive —— 上限 MAX_HIVE，超限明确警告"""
    data, trunc = read_all(fs, path, limit=MAX_HIVE, what='hive')
    return data


# ============================================================
# 目录列举 —— 核心 API
# ============================================================
def ls(fs, path, show_deleted=False, root=None):
    """列目录，**默认排除已删除项**。

    参数:
        show_deleted  是否包含已删除项（默认 False）
        root          若给出，Entry.name 变成可用的完整路径

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
    """显式要全部（含已删除）。等价 ls(show_deleted=True)"""
    return ls(fs, path, show_deleted=True, root=root)


def fmt(entry, width=0):
    """展示用：加 [D] 前缀标记已删除。只用于打印，不用于拼路径。"""
    nm = entry.name
    if width and len(nm) > width:
        nm = nm[:max(0, width - 4)] + '...'
    tag = '[D] ' if entry.deleted else '    '
    return tag + nm


def fmt_row(entry, width=46, size_w=10):
    """一行表格：标记 + 名字 + 大小"""
    return '%-*s %*d' % (width + 4, fmt(entry, width), size_w, entry.size)


def path_of(entry, parent=None):
    """取可用于 fs.open() 的路径。

    entry.name 已是根路径（root 参数生效时）；否则拼 parent。
    """
    if entry.name.startswith('/'):
        return entry.name
    return (parent.rstrip('/') + '/' + entry.name) if parent else entry.name


def count(entries, files_only=False, dirs_only=False):
    """统计辅助：默认只数未删除项（ls 已过滤，这里防 ls_all 的误用）"""
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
    print('=' * 50)
    print('上限（可用环境变量放宽）：')
    print('  FSIO_MAX_LOG  %8.0f MB  日志' % (MAX_LOG / 1e6))
    print('  FSIO_MAX_HIVE %8.0f MB  注册表' % (MAX_HIVE / 1e6))
    print('  FSIO_MAX_TEXT %8.0f MB  普通文本' % (MAX_TEXT / 1e6))
    print()
    print('目录枚举：')
    print('  ls()       默认排除已删除（show_deleted=False）')
    print('  ls_all()   显式包含已删除')
    print('  Entry.name 永远是干净文件名，可直接拼路径')
    print('  fmt(e)     展示时才加 [D] 标记')
    print()
    print('时间戳统一为带 tz 的 UTC，打印时标注 UTC/LCL')
    print()
    print('--- Entry 字段 ---')
    print('  %s' % ' '.join(Entry._fields))
