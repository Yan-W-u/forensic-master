#!/usr/bin/env python3
"""iotkit.py —— 嵌入式/IoT 取证工具集

用法:
  python iotkit.py scan    <目录或文件>        全量魔数扫描（找出所有协议族）
  python iotkit.py gpt     <eMMC镜像>          GPT 分区表解析
  python iotkit.py recs    <文件> <魔数> [len]  按定长切分记录
  python iotkit.py align   <目录>             多介质按时间戳对齐同一事件
  python iotkit.py wrap    <文件> <魔数> <seq偏移> <seq长度>   找环形缓冲回绕点
  python iotkit.py strings <文件> [最小长度]    提字符串
  python iotkit.py tlv     <文件> [offset] [be|le]   TLV 解析
"""
import sys
import os
import re
import struct
import collections

# 已知协议族及其时间戳偏移（用于 align）
SCHEMA = {
    'GWN6': (4, '<I'),
    'MOT5': (16, '<I'),
    'MNR6': (12, '<I'),
    'LMC5': (4, '<I'),
    'TEL5': (16, '<I'),
    'RTC5': (None, None),
    'AUT5': (6, '<I'),
    'OTA5': (None, None),
    'SEV4': (None, None),
    'SSB5': (None, None),
    'FDM4': (None, None),
    'MFR6': (None, None),
    'JRN6': (None, None),
    'EL5R': (None, None),
    'MV6R': (None, None),
    'AU6R': (None, None),
    'BCT5': (None, None),
    'BOK5': (None, None),
    'BGX4': (None, None),
    'L2C5': (None, None),
    'FRG5': (None, None),
    'LKT5': (None, None),
    'HCI5': (None, None),
}


def walk_all(path):
    if os.path.isfile(path):
        return [path]
    out = []
    for root, dirs, fs in os.walk(path):
        for f in fs:
            out.append(os.path.join(root, f))
    return sorted(out)


def cmd_scan(path):
    files = walk_all(path)
    print('=' * 80)
    print('全量魔数扫描 —— %d 个文件' % len(files))
    print('=' * 80)
    agg = collections.Counter()
    for p in files:
        try:
            d = open(p, 'rb').read(32 << 20)
        except Exception:
            continue
        c = collections.Counter()
        for m in re.finditer(rb'[A-Z][A-Z0-9]{3}', d):
            c[m.group().decode()] += 1
        top = [(k, v) for k, v in c.most_common(12) if v >= 3]
        agg.update({k: v for k, v in top})
        print('\n%-48s %10d' % (os.path.relpath(p, path if os.path.isdir(path) else '.'),
                                os.path.getsize(p)))
        print('   头16B: %s' % d[:16].hex())
        if top:
            print('   魔数 : %s' % ', '.join('%s(%d)' % (k, v) for k, v in top))
        else:
            print('   魔数 : (无明显 ASCII 魔数)')
    print()
    print('=' * 80)
    print('全局汇总')
    print('=' * 80)
    for k, v in agg.most_common(30):
        mark = ' ←带时间戳' if k in SCHEMA and SCHEMA[k][0] is not None else ''
        print('  %-8s %6d%s' % (k, v, mark))


def cmd_gpt(path):
    print('=' * 80)
    print('GPT 分区表 —— %s' % path)
    print('=' * 80)
    with open(path, 'rb') as f:
        f.seek(512)
        h = f.read(92)
        if h[:8] != b'EFI PART':
            print('  不是 GPT（头 8B: %s）' % h[:8].hex())
            return
        parts_lba = struct.unpack('<Q', h[72:80])[0]
        n = struct.unpack('<I', h[80:84])[0]
        sz = struct.unpack('<I', h[84:88])[0]
        print('  分区表 LBA: %d   条目数: %d   每条: %d 字节' % (parts_lba, n, sz))
        f.seek(parts_lba * 512)
        tbl = f.read(n * sz)
        print('\n  %-4s %-14s %-14s %s' % ('#', '起始 LBA', '结束 LBA', '名称'))
        for k in range(n):
            e = tbl[k * sz:(k + 1) * sz]
            if len(e) < 128 or e[:16] == b'\x00' * 16:
                continue
            first = struct.unpack('<Q', e[32:40])[0]
            last = struct.unpack('<Q', e[40:48])[0]
            name = e[56:128].decode('utf-16-le', 'replace').rstrip('\x00')
            print('  %-4d %-14d %-14d %s' % (k, first, last, name))


def cmd_recs(path, magic, reclen=None):
    d = open(path, 'rb').read()
    print('=' * 80)
    print('记录切分 —— %s  magic=%s' % (os.path.basename(path), magic))
    print('=' * 80)
    idx = [m.start() for m in re.finditer(magic.encode(), d)]
    print('出现 %d 次' % len(idx))
    if len(idx) < 2:
        return
    # 自动推断记录长度 = 最常见的相邻间隔
    gaps = collections.Counter(idx[i + 1] - idx[i] for i in range(len(idx) - 1))
    auto = gaps.most_common(1)[0][0] if gaps else 0
    print('相邻间隔众数: %d （推断记录长度）' % auto)
    if gaps:
        print('间隔分布: %s' % gaps.most_common(6))
    L = int(reclen) if reclen else auto
    print('\n按 %d 字节解析前 10 条：' % L)
    for off in idx[:10]:
        rec = d[off:off + L]
        print('  @0x%08X  %s' % (off, rec.hex()))
        print('             %s' % ''.join(chr(c) if 32 <= c < 127 else '.' for c in rec))


def cmd_align(path):
    files = walk_all(path)
    print('=' * 80)
    print('多介质时间戳对齐 —— %d 个文件' % len(files))
    print('=' * 80)
    events = collections.defaultdict(list)
    for p in files:
        try:
            d = open(p, 'rb').read(32 << 20)
        except Exception:
            continue
        base = os.path.basename(p)
        for magic, (off, fmt) in SCHEMA.items():
            if off is None:
                continue
            for m in re.finditer(magic.encode(), d):
                o = m.start()
                if o + off + 4 > len(d):
                    continue
                ts = struct.unpack(fmt, d[o + off:o + off + 4])[0]
                # 过滤误报：ASCII 型"时间戳"（如 -HAML / :CLO）不是真 ts
                if not (0 < ts < 0xFFFFFFFF):
                    continue
                raw = d[o + off:o + off + 4]
                printable = sum(1 for c in raw if 32 <= c < 127)
                if printable >= 3:
                    continue      # 4 字节里 3 个可打印 = ASCII 文本，不是时间戳
                if ts < 1000 or ts > 0x7FFFFFFF:
                    continue      # 合理 ts 范围
                events[ts].append((base, magic, o))
    print('收集到 %d 个不同时间戳\n' % len(events))
    multi = [(ts, v) for ts, v in events.items() if len(v) >= 2]
    multi.sort(key=lambda x: -len(x[1]))
    print('多介质命中（≥2 处）TOP 20：')
    for ts, items in multi[:20]:
        srcs = sorted({i[0] for i in items})
        print('  ts=0x%08X (%d)  %d 处 / %d 介质' % (ts, ts, len(items), len(srcs)))
        for s, mg, o in items[:6]:
            print('      %-42s %-6s @0x%X' % (s, mg, o))


def cmd_wrap(path, magic, seqoff, seqlen):
    d = open(path, 'rb').read()
    seqoff, seqlen = int(seqoff, 0), int(seqlen, 0)
    print('=' * 80)
    print('环形缓冲回绕 —— %s  %s seq@%d len=%d' % (
        os.path.basename(path), magic, seqoff, seqlen))
    print('=' * 80)
    idx = [m.start() for m in re.finditer(magic.encode(), d)]
    print('记录 %d 条' % len(idx))
    fmt = '<H' if seqlen == 2 else ('<I' if seqlen == 4 else '<B')
    seqs = []
    for o in idx:
        if o + seqoff + seqlen > len(d):
            continue
        seqs.append((o, struct.unpack(fmt, d[o + seqoff:o + seqoff + seqlen])[0]))
    print('前 10 条 seq: %s' % [s for _, s in seqs[:10]])
    wraps = []
    for i in range(1, len(seqs)):
        if seqs[i][1] < seqs[i - 1][1]:
            wraps.append((i, seqs[i - 1], seqs[i]))
            print('  ★ 回绕 @record %d: seq %d -> %d (0x%X)' % (
                i, seqs[i - 1][1], seqs[i][1], seqs[i][0]))
    if not wraps:
        print('  未发现回绕（线性写入或 seq 单调）')
    else:
        print('\n  最新记录 = 回绕点前一条：@0x%X seq=%d' % (
            wraps[-1][1][0], wraps[-1][1][1]))


def cmd_strings(path, n=6):
    d = open(path, 'rb').read()
    print('=' * 80)
    print('字符串 —— %s' % os.path.basename(path))
    print('=' * 80)
    for m in re.finditer(rb'[\x20-\x7e]{%d,}' % int(n), d):
        print('  @0x%08X  %s' % (m.start(), m.group().decode()[:120]))


def cmd_tlv(path, offset=0, endian='be'):
    d = open(path, 'rb').read()
    fmt = '>H' if endian == 'be' else '<H'
    print('=' * 80)
    print('TLV —— %s offset=0x%X endian=%s' % (os.path.basename(path), offset, endian))
    print('=' * 80)
    i = offset
    cnt = 0
    while i < len(d) - 3 and cnt < 100:
        key = d[i]
        ln = struct.unpack(fmt, d[i + 1:i + 3])[0]
        if ln == 0 or i + 3 + ln > len(d):
            i += 1
            continue
        val = d[i + 3:i + 3 + ln]
        txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in val[:60])
        print('  @0x%06X  key=0x%02X len=%-5d %s' % (i, key, ln, txt))
        i += 3 + ln
        cnt += 1


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return
    c, a = sys.argv[1], sys.argv[2]
    b = sys.argv[3] if len(sys.argv) > 3 else ''
    if c == 'scan':
        cmd_scan(a)
    elif c == 'gpt':
        cmd_gpt(a)
    elif c == 'recs':
        cmd_recs(a, b)
    elif c == 'align':
        cmd_align(a)
    elif c == 'wrap':
        cmd_wrap(a, b, sys.argv[4], sys.argv[5])
    elif c == 'strings':
        cmd_strings(a, b or 6)
    elif c == 'tlv':
        cmd_tlv(a, int(b, 0) if b else 0,
                sys.argv[4] if len(sys.argv) > 4 else 'be')
    else:
        print(__doc__)


if __name__ == '__main__':
    main()
