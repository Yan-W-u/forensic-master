#!/usr/bin/env python3
"""fsio.py —— 安全的证据读取层

解决三类静默错误：
  1. 大文件从头截断（日志是追加写的，最旧的在前面）
  2. 超过上限不报警（hive 半截喂给解析器）
  3. except 全吞（文件不存在 / 权限拒绝 / 读失败 无法区分）

所有 kit 工具应通过本模块读文件，而不是直接 read_random(0, size)。
"""
import os
import sys
import datetime

import pytsk3

# 默认上限（可通过环境变量放宽）
MAX_LOG = int(os.environ.get('FSIO_MAX_LOG', 256 << 20))    # 日志 256 MB
MAX_HIVE = int(os.environ.get('FSIO_MAX_HIVE', 512 << 20))  # hive 512 MB
MAX_TEXT = int(os.environ.get('FSIO_MAX_TEXT', 8 << 20))    # 普通文本 8 MB

WARN = '!'


def warn(msg):
    print('%s %s' % (WARN, msg), file=sys.stderr)


# ============================================================
# 文件状态
# ============================================================
def stat(fs, path):
    """返回 (size, is_dir, is_deleted, meta) 或 None

    已删除文件通过 flags & TSK_FS_META_FLAG_UNALLOC 判断。
    """
    try:
        n = fs.open(path)
    except Exception as e:
        warn('打不开 %s: %s' % (path, e))
        return None
    m = n.info.meta
    if not m:
        return None
    flags = getattr(m, 'flags', 0) or 0
    deleted = bool(flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
    isdir = m.type == pytsk3.TSK_FS_META_TYPE_DIR
    return (m.size or 0, isdir, deleted, m)


def is_deleted(meta):
    if not meta:
        return False
    flags = getattr(meta, 'flags', 0) or 0
    return bool(flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)


# ============================================================
# 读取
# ============================================================
def read_all(fs, path, limit=None, what='file'):
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
    if sz > cap:
        env_name = {'log': 'FSIO_MAX_LOG', 'hive': 'FSIO_MAX_HIVE',
                    'text': 'FSIO_MAX_TEXT', 'file': 'FSIO_MAX_TEXT'}.get(what, 'FSIO_MAX_TEXT')
        warn('%s 大小 %d 超过上限 %d，只读前 %d 字节（用 %s 放宽）'
             % (os.path.basename(path), sz, cap, cap, env_name))
        sz = cap
        truncated = True
    else:
        truncated = False

    try:
        data = n.read_random(0, sz)
    except Exception as e:
        warn('读取中断 %s @%d: %s' % (path, sz, e))
        return b'', truncated

    if len(data) < sz:
        warn('%s 期望 %d 实际 %d（读取不完整）' % (path, sz, len(data)))
        truncated = True

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
    """读文件尾部 —— 日志的最新内容在这里

    日志是追加写的：offset 0 是最旧的。
    要看「最后发生了什么」，必须读尾部。
    """
    st = stat(fs, path)
    if not st:
        return b''
    sz, _, _, _ = st
    if sz <= n:
        data, _ = read_all(fs, path, limit=n)
        return data
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
        # 丢掉第一行（可能被截断）
        i = head.find(b'\n')
        if i > 0:
            head = head[i + 1:]
        return head.decode('utf-8', 'replace')
    data, trunc = read_all(fs, path, limit=MAX_LOG, what='log')
    text = data.decode('utf-8', 'replace')
    if trunc:
        # 从头截断 = 丢最新，明确告知
        warn('%s 被截断，末尾内容缺失。找「最近」用 read_log(tail=N)'
             % os.path.basename(path))
    return text


# 兼容旧签名（srvkit 里叫 read_text）
def read_text(fs, path, limit=None):
    """普通文本文件。超限报警，不像旧版静默截断。"""
    data, _ = read_all(fs, path, limit=limit or MAX_TEXT, what='text')
    return data.decode('utf-8', 'replace')


def read_hive(fs, path):
    """注册表 hive —— 上限 MAX_HIVE，超限明确警告"""
    data, trunc = read_all(fs, path, limit=MAX_HIVE, what='hive')
    if trunc and len(data) == MAX_HIVE:
        warn('%s 被截断到 %d MB，喂给 regipy 会解析失败。'
             '用 FSIO_MAX_HIVE 放宽后重试' % (path, MAX_HIVE >> 20))
    return data


# ============================================================
# 目录列举（带删除标记）
# ============================================================
def ls(fs, path, show_deleted=True):
    """列目录。返回 [(name, size, is_dir, is_deleted, meta)]

    第 4 项是新增的删除标记 —— 旧版没有，导致删的和没删的混在一起。
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
        out.append((nm, m.size if m else 0, isdir, deleted, m))
    return out


def ls_mark(fs, path):
    """列目录，名字后缀标记删除状态（便于直接打印）"""
    rows = []
    for nm, sz, isdir, deleted, m in ls(fs, path):
        tag = ' [DELETED]' if deleted else ''
        rows.append(('%s%s' % ('[d] ' if isdir else '    ', nm) + tag, sz, m))
    return rows


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


def fmt(dt, local=False):
    """统一格式化。默认 UTC 并标注，local=True 转本地并标注。"""
    if not dt:
        return '-'
    if local:
        return dt.astimezone().strftime('%Y-%m-%d %H:%M:%S') + ' LCL'
    return dt.astimezone(UTC).strftime('%Y-%m-%d %H:%M:%S') + ' UTC'


def fmt_epoch(v, local=False):
    return fmt(ts_epoch(v), local)


def fmt_filetime(ft, local=False):
    return fmt(ts_filetime(ft), local)


# ============================================================
# 自检
# ============================================================
if __name__ == '__main__':
    print('fsio 读取层')
    print('=' * 46)
    print('上限（可用环境变量放宽）：')
    print('  FSIO_MAX_LOG  %8.0f MB  日志' % (MAX_LOG / 1e6))
    print('  FSIO_MAX_HIVE %8.0f MB  注册表' % (MAX_HIVE / 1e6))
    print('  FSIO_MAX_TEXT %8.0f MB  普通文本' % (MAX_TEXT / 1e6))
    print()
    print('时间戳统一为带 tz 的 UTC，打印时标注 UTC/LCL')
    print('目录列举带 [DELETED] 标记')
