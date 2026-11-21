"""forensic-master SQLite / 时间线工具。

覆盖 2026 美亚杯 FC-01 的全部数据库题：
- WAL 帧级解析，恢复已删记录（Q9/16-19 关键）
- iOS 备份 Manifest.db fileID 查询
- 浏览器 History/Web Data/Login Data
- Notepad TabState 未保存内容
- pcap 时间线

用法：
    python sqlite.py wal <wal文件> [关键词]
    python sqlite.py manifest <Manifest.db> [关键词]
    python sqlite.py browser <History> [域名]
    python sqlite.py notepad <TabState目录>
"""
from __future__ import annotations

import binascii
import csv
import datetime
import os
import re
import sqlite3
import struct
import sys

# ═══════════════════════════════════════════════════════════
#  SQLite 基础
# ═══════════════════════════════════════════════════════════


def connect_ro(path: str) -> sqlite3.Connection:
    """只读打开，绝不触发 checkpoint。

    关键：普通 connect 会 auto-checkpoint 并删掉 WAL，
    先把 WAL 复制出来再解析。
    """
    uri = f"file:{path.replace(os.sep, '/')}?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True)


def tables(con) -> list[str]:
    return [r[0] for r in con.execute("select name from sqlite_master where type='table'")]


def cols(con, table: str) -> list[str]:
    return [c[1] for c in con.execute(f"PRAGMA table_info({table})")]


ICONV = {"float_ms": None}


def apple_ts(v, tz=8):
    """Apple 时间戳（2001-01-01 起秒数）-> 字符串。"""
    if not v:
        return "-"
    try:
        dt = datetime.datetime(2001, 1, 1) + datetime.timedelta(seconds=float(v))
        return (dt + datetime.timedelta(hours=tz)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(v)


# ═══════════════════════════════════════════════════════════
#  WAL 帧解析（本次 Q9/16-19 的核心武器）
# ═══════════════════════════════════════════════════════════

def wal_pages(wal_path: str):
    """产出 (page_no, commit_size, page_bytes)。WAL 结构：32B 头 + N*(24B 帧头+页)。"""
    data = open(wal_path, "rb").read()
    if len(data) < 32:
        return
    magic, version, page_size, ckpt, salt1, salt2, c1, c2 = struct.unpack(">IIIIIIII", data[:32])
    off = 32
    while off + 24 + page_size <= len(data):
        pgno, commit = struct.unpack(">II", data[off:off + 8])
        s1, s2 = struct.unpack(">II", data[off + 8:off + 16])
        page = data[off + 24:off + 24 + page_size]
        if s1 == salt1 and s2 == salt2:
            yield pgno, commit, page
        off += 24 + page_size


def read_varint(buf, off):
    v = 0
    for i in range(9):
        if off + i >= len(buf):
            return 0, 1
        b = buf[off + i]
        if i == 8:
            return (v << 8) | b, 9
        v = (v << 7) | (b & 0x7F)
        if not (b & 0x80):
            return v, i + 1
    return v, 9


def parse_leaf_cells(page: bytes):
    """解析 b-tree table leaf 页，返回 [(rowid, payload, cell_offset)]。"""
    if len(page) < 8 or page[0] != 0x0D:
        return []
    ncell = struct.unpack(">H", page[3:5])[0]
    out = []
    for i in range(ncell):
        p = struct.unpack(">H", page[8 + i * 2:10 + i * 2])[0]
        if p == 0 or p >= len(page):
            continue
        try:
            plen, n1 = read_varint(page, p)
            rowid, n2 = read_varint(page, p + n1)
            off = p + n1 + n2
            out.append((rowid, page[off:off + plen], p))
        except Exception:
            continue
    return out


def parse_record(payload: bytes) -> list:
    """SQLite record -> 值列表。"""
    hlen, n = read_varint(payload, 0)
    types = []
    off = n
    while off < hlen:
        t, k = read_varint(payload, off)
        types.append(t)
        off += k
    vals = []
    off = hlen
    for t in types:
        if t == 0:
            vals.append(None)
        elif t == 1:
            vals.append(struct.unpack(">b", payload[off:off + 1])[0]); off += 1
        elif t == 2:
            vals.append(struct.unpack(">h", payload[off:off + 2])[0]); off += 2
        elif t == 3:
            vals.append(struct.unpack(">i", payload[off:off + 3] + b"\0")[0] >> 8); off += 3
        elif t == 4:
            vals.append(struct.unpack(">i", payload[off:off + 4])[0]); off += 4
        elif t == 5:
            vals.append(struct.unpack(">q", payload[off:off + 6] + b"\0\0")[0] >> 16); off += 6
        elif t == 6:
            vals.append(struct.unpack(">q", payload[off:off + 8])[0]); off += 8
        elif t == 7:
            vals.append(struct.unpack(">d", payload[off:off + 8])[0]); off += 8
        elif t == 8:
            vals.append(0)
        elif t == 9:
            vals.append(1)
        elif t >= 12:
            ln = (t - 12) // 2
            raw = payload[off:off + ln]
            vals.append(raw if t % 2 == 0 else raw.decode("utf8", "replace"))
            off += ln
        else:
            vals.append(None)
    return vals


def carve_wal(wal_path: str, keyword: bytes = b"", table_cols: dict | None = None):
    """从 WAL 中提取含关键词的记录。

    keyword 为空时吐出全部叶子记录。
    table_cols 可传 {page_root: [列名]} 做名值对齐。
    """
    seen = set()
    results = []
    for pgno, commit, page in wal_pages(wal_path):
        if keyword and keyword not in page:
            continue
        for rowid, payload, celloff in parse_leaf_cells(page):
            if keyword and keyword not in payload:
                continue
            vals = parse_record(payload)
            key = (pgno, rowid, len(vals))
            if key in seen:
                continue
            seen.add(key)
            results.append({"page": pgno, "rowid": rowid, "ncols": len(vals), "values": vals})
    return results


def print_carve(wal_path: str, keyword: str = "", limit=20):
    kw = keyword.encode() if keyword else b""
    rows = carve_wal(wal_path, kw)
    print(f"WAL={wal_path}  命中 {len(rows)} 条")
    for r in rows[:limit]:
        print(f"\n### page={r['page']} rowid={r['rowid']} ncols={r['ncols']}")
        for i, v in enumerate(r["values"]):
            if isinstance(v, bytes):
                try:
                    v = v.decode("utf8", "replace")
                except Exception:
                    v = v.hex()[:60]
            if v not in (None, 0, ""):
                extra = ""
                if isinstance(v, (int, float)) and 700000 < v < 900000:
                    extra = f"   [{apple_ts(v)}]"
                print(f"   [{i}] {v!r}{extra}")


# ═══════════════════════════════════════════════════════════
#  iOS 备份 Manifest
# ═══════════════════════════════════════════════════════════

def manifest_query(db: str, keyword: str):
    con = connect_ro(db)
    print(f"Files 表列: {cols(con, 'Files')}")
    print(f"总行数: {con.execute('select count(*) from Files').fetchone()[0]}\n")
    for r in con.execute(
        "select fileID, domain, relativePath from Files where relativePath like ? or fileID like ?",
        (f"%{keyword}%", f"%{keyword}%"),
    ):
        print(f"  {r[0]}  [{r[1]}]  {r[2]}")


# ═══════════════════════════════════════════════════════════
#  浏览器
# ═══════════════════════════════════════════════════════════

def browser_history(db: str, domain_kw: str = ""):
    con = connect_ro(db)
    urls = [r[0] for r in con.execute("select url from urls")]
    print(f"URL 总数: {len(urls)}")
    if domain_kw:
        hits = [u for u in urls if re.search(domain_kw, u, re.I)]
        print(f"匹配 {domain_kw!r}: {len(hits)} 条")
        for h in hits[:10]:
            print(f"  {h}")
    else:
        for u in urls[:30]:
            print(f"  {u}")


def browser_autofill(db: str, name_kw: str = "card_no"):
    con = connect_ro(db)
    try:
        rows = con.execute(
            "select name, count(*) from autofill group by name order by 2 desc").fetchall()
        print(f"[{os.path.basename(db)}] autofill 字段分布:")
        for n, c in rows:
            print(f"   {n}: {c}")
        if name_kw:
            for r in con.execute("select name, value from autofill where name like ?", (f"%{name_kw}%",)):
                print(f"   ★ {r[0]} = {r[1]}")
    except Exception as e:
        print(f"  读取失败: {e}")


def browser_logins(db: str):
    con = connect_ro(db)
    try:
        n = con.execute("select count(*) from logins").fetchone()[0]
        print(f"[{os.path.basename(db)}] logins: {n}")
        for r in con.execute("select origin_url, username_value from logins"):
            print(f"   {r[0]}  -> {r[1]}")
    except Exception as e:
        print(f"  读取失败: {e}")


# ═══════════════════════════════════════════════════════════
#  Notepad TabState（本次 Q53 的答案来源）
# ═══════════════════════════════════════════════════════════

def notepad_tabstate(dirpath: str):
    """Notepad 未保存内容。文件头 'NP' + 结构 + UTF-16LE 正文。"""
    if not os.path.isdir(dirpath):
        print(f"目录不存在: {dirpath}")
        return
    for fn in os.listdir(dirpath):
        p = os.path.join(dirpath, fn)
        if not os.path.isfile(p):
            continue
        data = open(p, "rb").read()
        print(f"\n═══ {fn} ({len(data)} B) ═══")
        if not data.startswith(b"NP"):
            print("  [非 Notepad 格式]")
            continue
        # 正文是 UTF-16LE，找最长连续可打印段
        best = ""
        cur = []
        for i in range(0, len(data) - 1, 2):
            ch = data[i:i + 2]
            try:
                c = ch.decode("utf-16le")
            except Exception:
                cur = []
                continue
            if c.isprintable() or c in "\r\n\t":
                cur.append(c)
            else:
                if len(cur) > len(best):
                    best = "".join(cur)
                cur = []
        if len(cur) > len(best):
            best = "".join(cur)
        print(best[:1500] if best.strip() else "  [无可读文本]")


# ═══════════════════════════════════════════════════════════
#  LNK 解析（Q36/Q37 的正确做法，$SI atime 不可信时用这个）
# ═══════════════════════════════════════════════════════════

def parse_lnk(data: bytes) -> dict:
    """最小 LNK 解析：取 LocalPath。"""
    r = {}
    if len(data) < 0x4C or data[:4] != b"\x4c\x00\x00\x00":
        return r
    flags = struct.unpack("<I", data[0x14:0x18])[0]
    off = 0x4C
    if flags & 1:
        sz = struct.unpack("<H", data[off:off + 2])[0]
        off += 2 + sz
    if not (flags & 2):
        return r
    lh = struct.unpack("<IIIIIIII", data[off + 4:off + 0x24])
    lboff = lh[4]
    if lboff:
        p = off + 4 + lboff
        end = data.find(b"\x00", p)
        if end > p:
            r["local_path"] = data[p:end].decode("mbcs", "replace")
    return r


def scan_lnks(dirpath: str):
    """扫描目录下全部 .lnk，列目标路径。"""
    if not os.path.isdir(dirpath):
        print(f"目录不存在: {dirpath}")
        return
    for fn in sorted(os.listdir(dirpath)):
        if not fn.lower().endswith(".lnk"):
            continue
        p = os.path.join(dirpath, fn)
        try:
            info = parse_lnk(open(p, "rb").read())
        except Exception:
            continue
        print(f"  {fn}")
        print(f"     -> {info.get('local_path')}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "wal":
        print_carve(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
    elif cmd == "manifest":
        manifest_query(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
    elif cmd == "browser":
        browser_history(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
    elif cmd == "autofill":
        browser_autofill(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "card_no")
    elif cmd == "logins":
        browser_logins(sys.argv[2])
    elif cmd == "notepad":
        notepad_tabstate(sys.argv[2])
    elif cmd == "lnk":
        scan_lnks(sys.argv[2])
    else:
        print(__doc__)
