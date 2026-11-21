"""forensic-master 核心库：证据统一访问 + 时间戳规范处理。

设计原则（来自 2026 美亚杯 128 题实战教训）：
1. E01 虚拟挂载，零提取 —— G 盘 92MB/s，全量提取 173GB 要 30 分钟
2. 时间戳一律显式标注时区基准 —— 本次 13 个错题里 5 个栽在时间基准
3. FILETIME 默认按 UTC，但提供已被篡改检测
4. 目录遍历失败要回补，不能静默跳过

用法：
    from forensic import Evidence, Walk, ts, ts_utc, filetime
"""
from __future__ import annotations

import datetime
import os
import struct

import pyewf
import pytsk3

# ═══════════════════════════════════════════════════════════
#  底层读流
# ═══════════════════════════════════════════════════════════


class EwfReader:
    """pyewf 随机读封装。E01/Ex01 直接读，不落地。"""

    def __init__(self, path: str):
        self.path = path
        self.h = pyewf.handle()
        self.h.open(pyewf.glob(path))
        self.size = self.h.media_size
        self.h.seek(0)

    def read(self, offset: int, length: int) -> bytes:
        self.h.seek(offset)
        out = b""
        while len(out) < length:
            d = self.h.read(length - len(out))
            if not d:
                break
            out += d
        return out

    def close(self):
        try:
            self.h.close()
        except Exception:
            pass


class RawReader:
    """普通镜像文件（dd / bin / img / raw）。"""

    def __init__(self, path: str):
        self.path = path
        self.f = open(path, "rb")
        self.f.seek(0, 2)
        self.size = self.f.tell()
        self.f.seek(0)

    def read(self, offset: int, length: int) -> bytes:
        self.f.seek(offset)
        return self.f.read(length)

    def close(self):
        self.f.close()


def open_reader(path: str):
    """按扩展名选读流。"""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".e01", ".e0", ".ex01"):
        return EwfReader(path)
    return RawReader(path)


# ═══════════════════════════════════════════════════════════
#  pytsk3 虚拟镜像
# ═══════════════════════════════════════════════════════════


class VirtualImg(pytsk3.Img_Info):
    """把 Reader 暴露为 pytsk3 镜像。

    注意：必须**继承** pytsk3.Img_Info 并调 super().__init__，
    否则 pytsk3 无法识别（不能只持有一个 Img_Info 实例）。
    """

    def __init__(self, reader):
        self._r = reader
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        pass

    def read(self, offset, size):
        return self._r.read(offset, size)

    def get_size(self):
        return self._r.size


class OffsetImg(pytsk3.Img_Info):
    """把一个分区窗口暴露为独立镜像。"""

    def __init__(self, reader, offset: int, length: int):
        self._r = reader
        self._off = offset
        self._len = length
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        pass

    def read(self, offset, size):
        if offset >= self._len:
            return b""
        end = min(offset + size, self._len)
        return self._r.read(self._off + offset, end - offset)

    def get_size(self):
        return self._len


# ═══════════════════════════════════════════════════════════
#  证据容器
# ═══════════════════════════════════════════════════════════


class Evidence:
    """一个镜像文件。可能是整盘（含分区表），也可能是裸文件系统。

    用法::

        ev = Evidence(path)          # path 用 os.path 或原始字符串
        print(ev.summary())
        fs = ev.fs()                 # 自动选最大可用卷
        fs = ev.volumes[label]       # 指定卷
    """

    def __init__(self, path: str):
        self.path = path
        self.reader = open_reader(path)
        self._img = VirtualImg(self.reader)
        self.partitions = []   # [(label, offset, length)]
        self.volumes = {}      # label -> pytsk3.FS_Info
        self._probe()

    def _probe(self):
        # 1) 试整盘分区表
        try:
            vi = pytsk3.Volume_Info(self._img)
            for v in vi:
                if v.len == 0:
                    continue
                desc = v.desc.decode("utf8", "replace")
                self.partitions.append((f"part{v.addr}:{desc}", v.start * 512, v.len * 512))
        except Exception:
            pass

        # 2) 逐个分区试文件系统
        for label, off, ln in self.partitions:
            try:
                sub = OffsetImg(self.reader, off, ln)
                self.volumes[label] = pytsk3.FS_Info(sub)
            except Exception:
                pass

        # 3) 无可用分区 -> 整镜像当文件系统
        if not self.volumes:
            try:
                self.volumes["raw"] = pytsk3.FS_Info(self._img)
                self.partitions = [("raw", 0, self.reader.size)]
            except Exception as e:
                self.error = f"{type(e).__name__}: {e}"

    def summary(self) -> str:
        g = 1024 ** 3
        lines = [f"镜像: {self.path}  大小: {self.reader.size/g:.2f} GB"]
        for label, off, ln in self.partitions:
            ok = "OK " if label in self.volumes else "--- "
            lines.append(f"  {ok}{label:34s} offset={off:>14,}  size={ln/g:8.2f} GB")
        return "\n".join(lines)

    def fs(self, label: str | None = None):
        """取文件系统。label 为空时取最大卷。"""
        if label:
            return self.volumes[label]
        best = None
        for label, off, ln in self.partitions:
            if label in self.volumes and (best is None or ln > best[1]):
                best = (label, ln)
        return self.volumes[best[0]]

    def label_of(self, fs) -> str:
        for k, v in self.volumes.items():
            if v is fs:
                return k
        return "?"


# ═══════════════════════════════════════════════════════════
#  遍历
# ═══════════════════════════════════════════════════════════


class Walk:
    """遍历助手。ls 失败不静默吞掉，记到 self.errors。"""

    def __init__(self, fs):
        self.fs = fs
        self.errors = []

    def ls(self, path="/"):
        out = []
        d = self.fs.open_dir(path if path else "/")
        for e in d:
            n = e.info.name.name
            if not n:
                continue
            name = n.decode("utf8", "replace")
            if name in (".", ".."):
                continue
            base = path.rstrip("/")
            out.append(Entry(e, f"{base}/{name}"))
        return out

    def ls_safe(self, path="/"):
        """不抛异常的 ls，失败返回空并记录。"""
        try:
            return self.ls(path)
        except Exception as e:
            self.errors.append((path, f"{type(e).__name__}: {e}"))
            return []

    def walk(self, root="/", max_files=200000, on_error=None):
        """深度遍历。失败目录会记录到 errors，事后可回补。"""
        stack = [root]
        seen = 0
        while stack and seen < max_files:
            cur = stack.pop()
            entries = self.ls_safe(cur)
            for en in entries:
                seen += 1
                yield en
                if en.is_dir:
                    stack.append(en.path)


class Entry:
    def __init__(self, tsk_entry, path: str):
        self.e = tsk_entry
        self.path = path

    @property
    def name(self):
        return self.e.info.name.name.decode("utf8", "replace")

    @property
    def meta(self):
        return self.e.info.meta

    @property
    def is_dir(self):
        m = self.meta
        return m is not None and m.type == pytsk3.TSK_FS_META_TYPE_DIR

    @property
    def is_file(self):
        m = self.meta
        return m is not None and m.type == pytsk3.TSK_FS_META_TYPE_REG

    @property
    def size(self):
        return self.meta.size if self.meta else 0

    @property
    def inode(self):
        return self.meta.addr if self.meta else None

    # ── 四个时间戳（TSK 返回 epoch 秒，已含小数部分）──
    @property
    def atime(self):
        return self.meta.atime or 0 if self.meta else 0

    @property
    def mtime(self):
        return self.meta.mtime or 0 if self.meta else 0

    @property
    def ctime(self):
        return self.meta.ctime or 0 if self.meta else 0

    @property
    def crtime(self):
        return self.meta.crtime or 0 if self.meta else 0

    def read(self) -> bytes:
        f = self.fs.open(self.path) if hasattr(self, "fs") else None
        if f is None:
            raise RuntimeError("Entry 未绑定 fs")
        return f.read_random(0, f.info.meta.size)

    def __repr__(self):
        t = "D" if self.is_dir else "F"
        return f"<{t} {self.path} {self.size}B ino={self.inode}>"


# ═══════════════════════════════════════════════════════════
#  时间戳规范（本次实战最大失分点，重点）
# ═══════════════════════════════════════════════════════════

TZ_OFFSET = 8  # 默认 UTC+8，比赛多为港台


def ts(epoch, tz=TZ_OFFSET) -> str:
    """TSK/Unix epoch 秒 -> 本地时间字符串。tz 默认 +8。"""
    if not epoch:
        return "-"
    dt = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return (dt + datetime.timedelta(hours=tz)).strftime("%Y-%m-%d %H:%M:%S")


def ts_utc(epoch) -> str:
    """TSK/Unix epoch 秒 -> UTC 字符串。"""
    if not epoch:
        return "-"
    dt = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def filetime(ft: int, as_utc=True) -> datetime.datetime | None:
    """Windows FILETIME(100ns since 1601) -> datetime。

    默认按 UTC 返回（Windows 内部存储惯例）。
    若题目要求本地时间，再 .astimezone 或手动 +8。
    """
    if not ft:
        return None
    try:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft / 10)
    except Exception:
        return None


def filetime_str(ft: int, tz=None) -> str:
    """FILETIME -> 字符串。tz 给 None 表示按 UTC 原样输出。"""
    dt = filetime(ft)
    if dt is None:
        return "-"
    if tz is not None:
        dt = dt + datetime.timedelta(hours=tz)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def systemtime(buf: bytes) -> datetime.datetime | None:
    """Windows SYSTEMTIME 结构（8×uint16 小端）-> datetime。

    注册表 NetworkList\\Profiles 的 DateLastConnected 用这个格式。
    regipy 有时返回 bytes，有时返回 hex 字符串，这里都兼容。
    """
    if isinstance(buf, str):
        try:
            buf = bytes.fromhex(buf)
        except Exception:
            return None
    if not buf or len(buf) < 16:
        return None
    y, mo, _dow, d, h, mi, s, _ms = struct.unpack("<8H", buf[:16])
    try:
        return datetime.datetime(y, mo, d, h, mi, s)
    except Exception:
        return None


def unix_days(days: int) -> datetime.date:
    """Linux shadow 第 3 字段（1970-01-01 起天数）-> date。"""
    return datetime.date(1970, 1, 1) + datetime.timedelta(days=days)


# ═══════════════════════════════════════════════════════════
#  NTFS 双时间戳（检测伪造）
# ═══════════════════════════════════════════════════════════


def ntfs_fn_times(fs, path: str) -> dict:
    """读 $FILE_NAME 属性里的四个时间戳。

    这是检测 TimeStamp Changer 类工具的关键：
    $SI 可被 GUI 工具改写，$FN 的时间戳极难伪造（含 10ns 精度）。

    返回 {'crtime','mtime','atime','ctime','fn_crtime',...} 对比。
    """
    f = fs.open(path)
    m = f.info.meta
    out = {
        "si_crtime": filetime_tsk(m.crtime),
        "si_mtime": filetime_tsk(m.mtime),
        "si_atime": filetime_tsk(m.atime),
        "si_ctime": filetime_tsk(m.ctime),
    }
    ATTR_TYPE_FILENAME = 48
    for a in f:
        if a.info.type != ATTR_TYPE_FILENAME:
            continue
        size = a.info.size
        try:
            data = f.read_random(0, size, ATTR_TYPE_FILENAME, a.info.id)
        except Exception:
            continue
        if len(data) < 66:
            continue
        c, m1, m2, at = struct.unpack("<QQQQ", data[8:40])
        out["fn_crtime"] = filetime(c)
        out["fn_mtime"] = filetime(m1)
        out["fn_atime"] = filetime(at)
        break
    return out


def filetime_tsk(epoch):
    """TSK 的 meta 时间也是 epoch 秒，转 datetime(UTC)。"""
    if not epoch:
        return None
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).replace(tzinfo=None)


def detect_tamper(fs, path: str) -> dict:
    """检测时间戳篡改。$SI 与 $FN 差异 > 1 天即报警。"""
    t = ntfs_fn_times(fs, path)
    si = t.get("si_crtime")
    fn = t.get("fn_crtime")
    result = dict(t)
    if si and fn:
        delta = abs((si - fn).total_seconds())
        result["delta_seconds"] = delta
        result["tampered"] = delta > 86400
        result["real_crtime"] = fn if result["tampered"] else si
    else:
        result["tampered"] = None
        result["real_crtime"] = si
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    ev = Evidence(sys.argv[1])
    print(ev.summary())
    if len(sys.argv) >= 4 and sys.argv[2] == "ls":
        w = Walk(ev.fs())
        for en in w.ls(sys.argv[3]):
            print(f"  {ts(en.mtime)}  {'D' if en.is_dir else 'F'}  {en.size:>14,}  {en.name}")
