#!/usr/bin/env python3
"""netkit.py —— 流量取证工具集（tshark 封装 + 伪装识别）

用法:
  python netkit.py health  <pcap>              体检：规模/协议层级/端点/会话
  python netkit.py fake    <pcap>              伪装识别：找 100% malformed 的分支
  python netkit.py ports   <pcap>              端口分布 TOP
  python netkit.py pairs   <pcap>              IP 会话对 TOP
  python netkit.py fields  <pcap> <f1,f2,...>  批量导出字段到 TSV
  python netkit.py check   <field1,field2>     验证字段名有效性
  python netkit.py http    <pcap>              导出 HTTP 对象
  python netkit.py find    <pcap> <关键词>      在载荷里搜字符串
"""
import sys
import os
import re
import csv
import subprocess
import collections

TSHARK = os.environ.get('TSHARK', r'C:\Program Files\Wireshark\tshark.exe')
EDITCAP = os.environ.get('EDITCAP', r'C:\Program Files\Wireshark\editcap.exe')
OUTROOT = os.environ.get('NET_OUT', os.path.join(os.getcwd(), 'net_out'))


def _run_bash(args, outfile=None):
    """跑 tshark。PowerShell 下用 shell 重定向最稳（Python stdout 会丢数据）"""
    cmd = [TSHARK] + args
    if outfile:
        with open(outfile, 'w', encoding='utf-8', errors='replace') as fh:
            r = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE)
        if r.returncode != 0:
            err = r.stderr.decode('utf-8', 'replace')
            print('  tshark stderr: %s' % err[:200])
        return open(outfile, encoding='utf-8', errors='replace').read().splitlines()
    r = subprocess.run(cmd, capture_output=True)
    return r.stdout.decode('utf-8', 'replace').splitlines()


def cmd_health(pcap):
    print('=' * 78)
    print('体检 —— %s (%.1f MB)' % (pcap, os.path.getsize(pcap) / 1e6))
    print('=' * 78)
    for label, args in [
        ('规模统计', ['-q', '-z', 'io,stat,0']),
        ('协议层级', ['-q', '-z', 'io,phs']),
        ('IP 端点 TOP', ['-q', '-z', 'endpoints,ip']),
    ]:
        print('\n### %s' % label)
        lines = _run_bash(['-r', pcap] + args)
        for ln in lines[:32]:
            if ln.strip():
                print(ln)


def cmd_fake(pcap):
    print('=' * 78)
    print('伪装识别 —— 找 100% malformed 的协议分支')
    print('=' * 78)
    lines = _run_bash(['-r', pcap, '-q', '-z', 'io,phs'])

    # 解析层级：缩进 + 协议名 + frames:N
    stack = []
    suspects = []
    for ln in lines:
        m = re.match(r'^(\s*)(\w[\w.\-]*)\s+frames:(\d+)\s+bytes:(\d+)', ln)
        if not m:
            continue
        indent = len(m.group(1))
        proto = m.group(2)
        frames = int(m.group(3))
        level = indent // 2
        stack = [x for x in stack if x[0] < level]
        stack.append((level, proto, frames))
        if proto == '_ws.malformed' and len(stack) >= 2:
            parent = stack[-2]
            if parent[2] and frames / parent[2] > 0.95:
                suspects.append((parent[1], parent[2], frames))

    if suspects:
        print('\n★ 疑似端口伪装（子协议 100%% malformed）：')
        for p, pf, mf in suspects:
            print('   %-28s 父 %d 帧，其中 malformed %d 帧 (%.0f%%)' % (
                p, pf, mf, mf / pf * 100))
            print('      → 这个端口上的流量不是 %s，是自定义协议' % p)
        print('\n   验证命令：')
        for p, _, _ in suspects[:3]:
            print('     tshark -r %s -Y \'%s\' -c 5 -T fields -e udp.payload' % (
                os.path.basename(pcap), p))
        print('\n   注意：先看 udp.payload，不要看 data.data（会被解析器吃掉）')
    else:
        print('\n未发现 100% malformed 的分支。')

    print('\n### 全部 malformed 统计')
    for ln in lines:
        if 'malformed' in ln:
            print(ln)


def cmd_ports(pcap):
    print('=' * 78)
    print('端口分布 —— %s' % pcap)
    print('=' * 78)
    lines = _run_bash(['-r', pcap, '-T', 'fields',
                       '-e', 'tcp.dstport', '-e', 'udp.dstport'])
    c = collections.Counter()
    for ln in lines:
        for p in ln.split('\t'):
            if p.strip() and p.strip() not in ('tcp.dstport', 'udp.dstport'):
                c[p.strip()] += 1
    print('%-10s %s' % ('端口', '帧数'))
    for p, n in c.most_common(25):
        print('%-10s %d' % (p, n))


def cmd_pairs(pcap, topn=20):
    print('=' * 78)
    print('IP 会话对 —— %s' % pcap)
    print('=' * 78)
    lines = _run_bash(['-r', pcap, '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst'])
    c = collections.Counter()
    for ln in lines:
        a = ln.split('\t')
        if len(a) >= 2 and a[0] and a[1]:
            c[(a[0].strip(), a[1].strip())] += 1
    print('%-18s %-18s %s' % ('源', '目的', '帧数'))
    for (s, d), n in c.most_common(topn):
        print('%-18s %-18s %d' % (s, d, n))


def cmd_fields(pcap, fields):
    fl = [x.strip() for x in fields.split(',') if x.strip()]
    os.makedirs(OUTROOT, exist_ok=True)
    out = os.path.join(OUTROOT, 'fields.tsv')
    args = ['-r', pcap, '-T', 'fields']
    for f in fl:
        args += ['-e', f]
    print('导出 %d 个字段 -> %s' % (len(fl), out))
    lines = _run_bash(args, outfile=out)
    print('行数: %d' % len(lines))
    if lines:
        print('前 3 行:')
        for ln in lines[:3]:
            print('  ' + ln[:150])
    if len(lines) == 0:
        print('⚠ 0 行 —— 大概率是字段名无效，跑 check 子命令验证')


def cmd_check(fields):
    print('=' * 78)
    print('字段名有效性检查')
    print('=' * 78)
    print('%-46s %s' % ('字段', '状态'))
    for f in [x.strip() for x in fields.split(',') if x.strip()]:
        r = subprocess.run([TSHARK, '-G', 'fields'], capture_output=True)
        txt = r.stdout.decode('utf-8', 'replace')
        ok = re.search(r'^F\t[^\t]*\t' + re.escape(f) + r'\t', txt, re.M) is not None
        print('%-46s %s' % (f, 'OK' if ok else 'INVALID ❌'))


def cmd_http(pcap):
    os.makedirs(OUTROOT, exist_ok=True)
    outdir = os.path.join(OUTROOT, 'objects')
    os.makedirs(outdir, exist_ok=True)
    print('导出 HTTP 对象 -> %s' % outdir)
    r = subprocess.run([TSHARK, '-r', pcap, '--export-objects', 'http,' + outdir],
                       capture_output=True)
    print(r.stdout.decode('utf-8', 'replace')[:500])
    n = len(os.listdir(outdir))
    print('共 %d 个对象' % n)
    for f in sorted(os.listdir(outdir))[:20]:
        p = os.path.join(outdir, f)
        print('  %10d  %s' % (os.path.getsize(p), f))


def cmd_find(pcap, kw):
    """在载荷里搜字符串（同时查 data.data 和 udp.payload）"""
    print('=' * 78)
    print('搜索 %r' % kw)
    print('=' * 78)
    os.makedirs(OUTROOT, exist_ok=True)
    out = os.path.join(OUTROOT, 'payload.tsv')
    lines = _run_bash(['-r', pcap, '-T', 'fields',
                       '-e', 'frame.number', '-e', 'ip.src', '-e', 'ip.dst',
                       '-e', 'data.data', '-e', 'udp.payload', '-e', 'tcp.payload'],
                      outfile=out)
    print('扫描 %d 帧的载荷...' % len(lines))
    n = 0
    for ln in lines:
        if kw.lower() not in ln.lower():
            continue
        p = ln.split('\t')
        print('\n  f%s  %s -> %s' % (p[0], p[1], p[2]))
        for i, label in [(3, 'data'), (4, 'udp'), (5, 'tcp')]:
            if i < len(p) and p[i]:
                try:
                    b = bytes.fromhex(p[i])
                    txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in b)
                    idx = txt.lower().find(kw.lower())
                    if idx >= 0:
                        print('     [%s] %s' % (label, txt[max(0, idx - 40):idx + 80]))
                except Exception:
                    pass
        n += 1
        if n >= 30:
            print('\n... 超过 30 处停止')
            break
    if n == 0:
        print('未找到。试试：')
        print('  - 关键词是否大小写敏感')
        print('  - 换 udp.payload / tcp.payload')
        print('  - 载荷是二进制，用 hex 搜')


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return
    c, a = sys.argv[1], sys.argv[2]
    b = sys.argv[3] if len(sys.argv) > 3 else ''
    m = {'health': cmd_health, 'fake': cmd_fake, 'ports': cmd_ports,
         'pairs': cmd_pairs, 'http': cmd_http,
         'fields': lambda x: cmd_fields(x, b), 'check': cmd_check,
         'find': lambda x: cmd_find(x, b)}
    if c in m:
        m[c](a)
    else:
        print(__doc__)


if __name__ == '__main__':
    main()
