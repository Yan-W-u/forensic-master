#!/usr/bin/env python3
"""hexins.py —— 内置十六进制检视/结构解析器（替代 010 Editor 的常用功能）

用法:
  python hexins.py view  <file> [offset] [length]     十六进制 + ASCII
  python hexins.py str   <file> <keyword> [ctx]        搜字符串并显示上下文
  python hexins.py magic <file>                        识别文件类型（魔数表）
  python hexins.py tlv   <file> <offset> [be|le]       TLV 逐层解析
  python hexins.py ent   <file>                        熵分析（判加密/压缩）
  python hexins.py carv  <file> <magic_hex> [max]      按魔数雕刻
"""
import sys
import os
import struct
import math
import binascii

MAGICS = {
    b'\x7fELF': 'ELF 可执行',
    b'MZ': 'PE 可执行',
    b'PK\x03\x04': 'ZIP/JAR/APK/DOCX',
    b'\x1f\x8b': 'gzip',
    b'BZh': 'bzip2',
    b'\xfd7zXZ': 'xz',
    b'7z\xbc\xaf\x27\x1c': '7z',
    b'Rar!': 'RAR',
    b'\x89PNG': 'PNG',
    b'\xff\xd8\xff': 'JPEG',
    b'GIF8': 'GIF',
    b'RIFF': 'RIFF(WAV/AVI)',
    b'%PDF': 'PDF',
    b'SQLite format 3\x00': 'SQLite 明文',
    b'ANDROID!': 'Android boot',
    b'UBI#': 'UBI (NAND)',
    b'hsqs': 'squashfs LE',
    b'sqsh': 'squashfs BE',
    b'\x27\x05\x19\x56': 'uImage',
    b'QCD2': 'qc 加密容器',
    b'VERA': 'VeraCrypt(解密后)',
    b'LUKS\xba\xbe': 'LUKS',
    b'VH6H': '审计视图头',
    b'JRN6': '审计记录',
    b'SSB5': '会话记录',
    b'SEV4': '安全元件记录',
    b'AUT5': '认证记录',
    b'TEL5': '遥测记录',
    b'MOT5': '电机记录',
    b'FDM4': '设备元数据',
    b'ST5R': '状态记录',
    b'DID5': '设备ID',
    b'L2C5': 'L2CAP 记录',
    b'FRG5': '分片记录',
    b'OTA5': 'OTA 记录',
    b'GWN6': '网关记录',
    b'\x0a\xf3': '—',
}


def hx(b):
    return b.hex()


def view(path, offset=0, length=512):
    if not os.path.exists(path):
        print('文件不存在:', path)
        return
    size = os.path.getsize(path)
    offset = max(0, int(offset))
    length = min(int(length), size - offset)
    with open(path, 'rb') as f:
        f.seek(offset)
        data = f.read(length)
    print('文件: %s  大小=%d  offset=0x%X  len=%d' % (path, size, offset, length))
    print('-' * 78)
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexs = ' '.join('%02x' % c for c in chunk)
        asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
        print('%08X  %-47s  |%s|' % (offset + i, hexs, asc))


def search(path, kw, ctx=64):
    size = os.path.getsize(path)
    print('文件: %s  大小=%d  搜索: %r' % (path, size, kw))
    print('-' * 78)
    with open(path, 'rb') as f:
        data = f.read()
    needle = kw.encode('utf-8', 'replace') if isinstance(kw, str) else kw
    pos, n = 0, 0
    while True:
        i = data.find(needle, pos)
        if i < 0:
            break
        n += 1
        s = max(0, i - ctx)
        e = min(len(data), i + len(needle) + ctx)
        seg = data[s:e]
        print('\n[%d] @0x%X' % (n, i))
        print('  hex:', seg[:120].hex())
        print('  txt:', ''.join(chr(c) if 32 <= c < 127 else '.' for c in seg))
        pos = i + 1
        if n >= 30:
            print('... 超过 30 处，停止')
            break
    if n == 0:
        print('未找到')


def magic(path):
    with open(path, 'rb') as f:
        head = f.read(64)
    print('文件: %s  大小=%d' % (path, os.path.getsize(path)))
    print('头 32B:', head[:32].hex())
    print()
    hit = False
    for m, name in MAGICS.items():
        if head.startswith(m):
            print('  ★ %s  (魔数 %s)' % (name, m.hex()))
            hit = True
    if not hit:
        print('  未知（对照下表逐字节看）')
    print()
    # 尾部
    with open(path, 'rb') as f:
        f.seek(max(0, os.path.getsize(path) - 32))
        print('尾 32B:', f.read(32).hex())


def tlv(path, offset=0, endian='be', maxdepth=3, limit=200):
    with open(path, 'rb') as f:
        data = f.read()
    fmt = '>H' if endian == 'be' else '<H'
    print('TLV 解析  offset=0x%X  endian=%s' % (offset, endian))
    print('-' * 78)
    i = offset
    n = 0
    while i < len(data) - 3 and n < limit:
        key = data[i]
        ln = struct.unpack(fmt, data[i + 1:i + 3])[0]
        if ln == 0 or i + 3 + ln > len(data):
            i += 1
            continue
        val = data[i + 3:i + 3 + ln]
        txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in val[:60])
        printable = sum(1 for c in val if 32 <= c < 127) / max(1, len(val))
        print('@0x%06X  key=0x%02X len=%-5d %s' % (i, key, ln, txt))
        if printable < 0.7 and ln >= 4:
            print('           hex: %s' % val[:32].hex())
        i += 3 + ln
        n += 1


def entropy(path, bs=4096):
    size = os.path.getsize(path)
    print('文件: %s  大小=%d  块=%d' % (path, size, bs))
    print('-' * 78)
    with open(path, 'rb') as f:
        off = 0
        while off < size:
            blk = f.read(bs)
            if not blk:
                break
            cnt = [0] * 256
            for c in blk:
                cnt[c] += 1
            e = 0.0
            for c in cnt:
                if c:
                    p = c / len(blk)
                    e -= p * math.log2(p)
            bar = '#' * int(e * 8)
            print('0x%08X  %.4f  %s' % (off, e, bar))
            off += bs
            if off > bs * 64 and size > bs * 200:
                print('... (大文件仅显示前 64 块)')
                break


def carve(path, mhex, maxn=10):
    needle = bytes.fromhex(mhex)
    outdir = os.path.splitext(path)[0] + '_carved'
    os.makedirs(outdir, exist_ok=True)
    with open(path, 'rb') as f:
        data = f.read()
    pos, n = 0, 0
    while n < maxn:
        i = data.find(needle, pos)
        if i < 0:
            break
        n += 1
        # 找下一个魔数作为结束，或取 1MB
        nxt = data.find(needle, i + 1)
        end = nxt if nxt > 0 else min(len(data), i + (1 << 20))
        chunk = data[i:end]
        p = os.path.join(outdir, '%s_%03d_0x%X.bin' % (os.path.basename(path)[:20], n, i))
        open(p, 'wb').write(chunk)
        print('carved -> %s  (%d bytes)' % (p, len(chunk)))
        pos = i + 1
    if n == 0:
        print('未找到魔数', mhex)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    p = sys.argv[2]
    a = sys.argv[3:]
    if cmd == 'view':
        view(p, a[0] if a else 0, a[1] if len(a) > 1 else 512)
    elif cmd == 'str':
        search(p, a[0])
    elif cmd == 'magic':
        magic(p)
    elif cmd == 'tlv':
        tlv(p, int(a[0], 0) if a else 0, a[1] if len(a) > 1 else 'be')
    elif cmd == 'ent':
        entropy(p)
    elif cmd == 'carv':
        carve(p, a[0], int(a[1]) if len(a) > 1 else 10)
    else:
        print(__doc__)
