#!/usr/bin/env python3
"""ev.py —— 通用证据访问层（所有 kit 工具的底座）

支持格式：
  .E01/.Ex01  → pyewf + pytsk3
  .raw/.dd/.img/.001  → 直接当块设备
  .vhd/.vhdx  → 提示用 DiskMount/vmware-mount

三种打开方式，任选：

  1) 命令行传路径（最常用）
       from ev import open_fs
       fs = open_fs('D:/case/disk.E01', lba=104448)

  2) 环境变量（批量操作时）
       set CASE_IMAGE=D:/case/disk.E01
       set CASE_LBA=104448
       fs = open_fs()

  3) 映射文件（多检材案件）
       ev.py 读 $CASE_DIR/images.json：
       {
         "pc":    {"path": "D:/case/PC.E01",   "lba": 104448},
         "srv":   {"path": "D:/case/SRV.E01",  "lba": 4200448}
       }
       fs = open_fs('pc')

行业术语：
  lba   分区起始逻辑块地址（512 字节/块）
        MBR/GPT 直接给分区起始；LVM 要给 PV_start + pe_start

常见 LBA 速查：
  MBR 第一分区      2048
  GPT 第一分区      2048（但要看分区表）
  LVM PV 内 LV      4198400 + 2048 = 4200448（本机实测值，仅举例）
  NTFS 在 MBR 分区  bios 报的值 / 512
"""
import os
import sys
import json
import functools

SECTOR = 512

try:
    import pytsk3
except ImportError:
    pytsk3 = None

try:
    import pyewf
except ImportError:
    pyewf = None


# ============================================================
# 底层
# ============================================================
class _EwfImg(pytsk3.Img_Info if pytsk3 else object):
    """把 pyewf 句柄包装成 pytsk3.Img_Info"""

    def __init__(self, ewf):
        if not pytsk3:
            raise RuntimeError('需要 pytsk3')
        self._e = ewf
        pytsk3.Img_Info.__init__(self, '')

    def read(self, offset, size):
        self._e.seek_offset(offset, 0)
        return self._e.read_buffer(size)

    def get_size(self):
        return self._e.get_media_size()


class _RawImg(pytsk3.Img_Info if pytsk3 else object):
    """裸镜像（raw/dd/img）"""

    def __init__(self, path):
        if not pytsk3:
            raise RuntimeError('需要 pytsk3')
        self._f = open(path, 'rb')
        self._size = os.path.getsize(path)
        pytsk3.Img_Info.__init__(self, '')

    def read(self, offset, size):
        self._f.seek(offset)
        return self._f.read(size)

    def get_size(self):
        return self._size


# ============================================================
# 配置来源
# ============================================================
def _case_dir():
    return os.environ.get('CASE_DIR') or os.getcwd()


def _load_map():
    """读 $CASE_DIR/images.json"""
    p = os.path.join(_case_dir(), 'images.json')
    if not os.path.exists(p):
        return {}
    try:
        return json.load(open(p, encoding='utf-8'))
    except Exception as e:
        print('! images.json 解析失败: %s' % e, file=sys.stderr)
        return {}


def _resolve(name_or_path):
    """返回 (镜像路径, lba)

    支持：
      绝对/相对路径          → (path, env LBA 或 0)
      映射文件里的 key        → (path, lba)
      环境变量 CASE_IMAGE    → (CASE_IMAGE, CASE_LBA)
    """
    m = _load_map()

    # 1) 映射文件里的 key
    if name_or_path in m:
        ent = m[name_or_path]
        if isinstance(ent, dict):
            return ent['path'], int(ent.get('lba', 0))
        return ent, int(os.environ.get('CASE_LBA', 0))

    # 2) 看起来是路径
    if os.path.exists(name_or_path) or '/' in name_or_path or '\\' in name_or_path:
        return name_or_path, int(os.environ.get('CASE_LBA', 0))

    # 3) 环境变量
    if os.environ.get('CASE_IMAGE'):
        return os.environ['CASE_IMAGE'], int(os.environ.get('CASE_LBA', 0))

    raise FileNotFoundError(
        '找不到检材 %r。三种给法：\n'
        '  1) open_fs("D:/case/disk.E01", lba=2048)\n'
        '  2) set CASE_IMAGE=D:/case/disk.E01 & set CASE_LBA=2048\n'
        '  3) 在 %s\\images.json 里配 {"key": {"path": "...", "lba": 2048}}'
        % (name_or_path, _case_dir()))


# ============================================================
# 打开
# ============================================================
def _open_img(path):
    """按扩展名选 reader"""
    low = path.lower()
    if low.endswith(('.e01', '.ex01', '.e0')):
        if not pyewf:
            raise RuntimeError('读 E01 需要 pyewf：pip install libewf-python')
        h = pyewf.handle()
        h.open(pyewf.glob(path))
        return _EwfImg(h)
    if low.endswith(('.vhd', '.vhdx')):
        raise RuntimeError(
            'VHD 需要先转成 raw 或挂载：\n'
            '  挂载: DiskMount.exe /vmware-mount\n'
            '  转换: qemu-img convert -f vpc -O raw in.vhd out.raw')
    # 其余当裸镜像
    return _RawImg(path)


@functools.lru_cache(maxsize=None)
def _open_cached(path, lba):
    img = _open_img(path)
    if lba:
        try:
            return pytsk3.FS_Info(img, offset=lba * SECTOR)
        except OSError as e:
            raise OSError(
                'LBA %d 处不是文件系统：%s\n'
                '  用 -–parts 先列分区：python ev.py "%s" --parts'
                % (lba, e, path)) from e
    # lba=0 或未指定：先试整盘，失败则自动挑分区
    try:
        return pytsk3.FS_Info(img)
    except OSError:
        parts = list_partitions(path)
        mounts = [p for p in parts if p[2] > 1000 and 'Unallocated' not in p[3]]
        if not mounts:
            raise OSError('整盘不是文件系统，且没找到可挂载分区。'
                          '用 --parts 看看：python ev.py "%s" --parts' % path)
        # 按大小降序试，逐个打开直到成功
        tried = []
        for idx, plba, psize, desc in sorted(mounts, key=lambda x: -x[2]):
            for off in (0, 2048, 384, 1024):
                # off=0       普通分区
                # off=2048    LVM 默认 pe_start（PV 起始 + 2048）
                # off=384/1024  其他 LVM 布局
                try:
                    img2 = _open_img(path)
                    fs = pytsk3.FS_Info(img2, offset=(plba + off) * SECTOR)
                    if off:
                        print('  分区 %d (LBA %d) 是 LVM，实际 FS 在 +%d = %d'
                              % (idx, plba, off, plba + off), file=sys.stderr)
                    else:
                        print('  自动用分区 %d (LBA %d, %s)'
                              % (idx, plba, desc), file=sys.stderr)
                    return fs
                except OSError:
                    tried.append(plba + off)
                    continue
        raise OSError(
            '所有分区都打不开。已试 LBA: %s\n'
            '  用 --parts 看结构，或手动指定：python ev.py "%s" 4200448'
            % (', '.join(str(t) for t in tried[:12]), path))


def open_fs(name_or_path=None, lba=None):
    """打开文件系统。name_or_path 可以是路径，也可以是 images.json 里的 key。"""
    if not pytsk3:
        raise RuntimeError('需要 pytsk3：pip install pytsk3')
    if name_or_path is None:
        name_or_path = os.environ.get('CASE_IMAGE', '')
        if not name_or_path:
            raise FileNotFoundError('没给检材。用 open_fs("path.E01", lba=2048) '
                                    '或 set CASE_IMAGE=...')
    path, auto_lba = _resolve(name_or_path)
    use_lba = lba if lba is not None else auto_lba
    if not os.path.exists(path):
        raise FileNotFoundError('镜像不存在: %s' % path)
    return _open_cached(os.path.abspath(path), int(use_lba))


# 兼容旧名（案件脚本里叫 fs）
def fs(name_or_path=None, lba=None):
    return open_fs(name_or_path, lba)


# ============================================================
# 分区表探测（不知道 LBA 时用这个）
# ============================================================
def list_partitions(path):
    """列出分区表里的可挂载分区，返回 [(idx, lba, size, 描述)]

    用法：
        for idx, lba, size, desc in list_partitions('disk.E01'):
            print(idx, lba, desc)
    """
    if not pytsk3:
        raise RuntimeError('需要 pytsk3')
    img = _open_img(path)
    out = []
    try:
        vol = pytsk3.Volume_Info(img)
        for p in vol:
            if p.len < 1:
                continue
            desc = p.desc.decode('utf-8', 'replace') if p.desc else ''
            out.append((p.addr, p.start, p.len, desc.strip()))
    except Exception as e:
        print('分区表解析失败: %s' % e, file=sys.stderr)
        print('  可能整盘就是一个文件系统，试试 lba=0', file=sys.stderr)
    return out


def auto_fs(path, prefer=None):
    """猜分区并打开。prefer 是描述关键词（如 'Linux' / 'NTFS'）"""
    parts = list_partitions(path)
    if not parts:
        return open_fs(path, lba=0)
    if prefer:
        for idx, lba, size, desc in parts:
            if prefer.lower() in desc.lower():
                print('用分区 %d (LBA %d, %s)' % (idx, lba, desc))
                return open_fs(path, lba=lba)
    # 默认挑最大的
    idx, lba, size, desc = max(parts, key=lambda x: x[2])
    print('用最大分区 %d (LBA %d, %s)' % (idx, lba, desc))
    return open_fs(path, lba=lba)


# ============================================================
# 便利函数
# ============================================================
def read_file(f, path):
    """读整个文件。委托给 fsio，上限由文件类型决定。

    返回 ReadResult(data, truncated, size_expected, size_actual)。
    """
    import fsio as _fsio
    return _fsio.read_text(f, path)


def read_text(f, path):
    """读文本，返回 str。截断时抛 fsio.Truncated（不静默返回半截）。"""
    import fsio as _fsio
    r = _fsio.read_text(f, path)
    if r.truncated:
        raise _fsio.Truncated(path, r.size_expected, r.size_actual, r.data, 'text')
    return r.data.decode('utf-8', 'replace')



def ls(f, path, show_deleted=False):
    """列目录。委托给 fsio，返回 Entry 列表。

    Entry.name 是干净文件名，可直接拼路径：
        fs.open(path + '/' + e.name)
    """
    import fsio as _fsio
    return _fsio.ls(f, path, show_deleted=show_deleted)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        print('\n用法: python ev.py <镜像路径> [lba]')
        print('      python ev.py <镜像路径> --parts   # 只列分区')
        sys.exit(0)

    path = sys.argv[1]
    if '--parts' in sys.argv:
        for idx, lba, size, desc in list_partitions(path):
            print('分区 %-3d LBA %-12d %-14s %s' % (idx, lba, size, desc))
        sys.exit(0)

    lba = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else None
    f = open_fs(path, lba) if lba is not None else auto_fs(path)
    print('文件系统: block_size=%d block_count=%d'
          % (f.info.block_size, f.info.block_count))
    print()
    for e in ls(f, '/')[:20]:
        print('  %s %-46s %10d' % ('d' if e.is_dir else '-', e.name, e.size))
