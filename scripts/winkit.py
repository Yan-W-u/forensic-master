#!/usr/bin/env python3
"""winkit.py —— Windows 取证专用工具集

用法:
  python winkit.py info     <key>         镜像/FS 概览
  python winkit.py hives    <key>         导出全部注册表 hive 到 out/
  python winkit.py sysinfo  <key>         计算机名/时区/安装时间/关机时间
  python winkit.py accounts <key>         账号列表 + RID + 最后登录
  python winkit.py users    <key>         UserAssist/RunMRU/RecentDocs
  python winkit.py usb      <key>         外置存储三通道
  python winkit.py software <key>         已装软件清单
  python winkit.py autorun  <key>         启动项 + 服务
  python winkit.py evtx     <key>         导出事件日志并统计
  python winkit.py pf       <key>         Prefetch 清单
  python winkit.py browser  <key> [user]  浏览器数据摘要
  python winkit.py recent   <key> [user]  LNK/JumpList/回收站

<image> 镜像路径（.E01/.raw/.img）或 $CASE_DIR/images.json 里的 key
         可选 --lba N 指定分区起始块
"""
import sys
import os
import re
import json
import struct
import codecs
import datetime
import subprocess

# 技能目录必须优先（否则案件目录里的同名 ev.py 会抢占）
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.environ.get('CASE_DIR', '.'))
sys.path.insert(0, _HERE)

import pytsk3

EZ = os.environ.get('EZTOOLS', r'D:\ForensicTools\eztools')
OUTROOT = os.environ.get('WIN_OUT', os.path.join(os.getcwd(), 'win_out'))


def dt_utc(ts):
    if not ts:
        return '-'
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)


def ft2dt(ft):
    if not ft:
        return None
    try:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
    except Exception:
        return None


def read(fs, path, limit=64 << 20):
    n = fs.open(path)
    return n.read_random(0, min(n.info.meta.size or 0, limit))


def ls(fs, path):
    out = []
    try:
        for en in fs.open_dir(path):
            nm = en.info.name.name.decode('utf-8', 'replace')
            if nm in ('.', '..'):
                continue
            m = en.info.meta
            out.append((nm, m.size if m else 0, m.type == pytsk3.TSK_FS_META_TYPE_DIR, m))
    except Exception:
        pass
    return out


def find_controlset(fs):
    """确定 CurrentControlSet 编号"""
    try:
        from regipy.registry import RegistryHive
        sy = os.path.join(OUTROOT, 'SYSTEM')
        reg = RegistryHive(sy)
        v = reg.get_key(r'\Select').get_value('Current')
        return 'ControlSet%03d' % (v if isinstance(v, int) else 1)
    except Exception:
        return 'ControlSet001'


def cmd_info(fs):
    print('=' * 76)
    print('镜像概览')
    print('=' * 76)
    print('块大小 %d, 块数 %d, 约 %.1f GB' % (
        fs.info.block_size, fs.info.block_count,
        fs.info.block_size * fs.info.block_count / 1e9))
    print('\n用户目录:')
    for nm, sz, isdir, m in ls(fs, '/Users'):
        if isdir:
            print('  %-28s crtime=%s' % (nm, dt_utc(m.crtime)))
    print('\n关键 hive:')
    for p in ('/Windows/System32/config/SOFTWARE', '/Windows/System32/config/SYSTEM',
              '/Windows/System32/config/SAM', '/Windows/System32/config/SECURITY'):
        try:
            print('  %-46s %10d' % (p.split('/')[-1], fs.open(p).info.meta.size))
        except Exception:
            print('  %-46s MISSING' % p.split('/')[-1])


def cmd_hives(fs):
    os.makedirs(OUTROOT, exist_ok=True)
    print('=' * 76)
    print('导出注册表 hive -> %s' % OUTROOT)
    print('=' * 76)
    T = {}
    for c in ('SOFTWARE', 'SYSTEM', 'SAM', 'SECURITY', 'DEFAULT'):
        T[c] = '/Windows/System32/config/' + c
    for nm, sz, isdir, m in ls(fs, '/Users'):
        if not isdir:
            continue
        T['%s_NTUSER' % nm] = '/Users/%s/NTUSER.DAT' % nm
        T['%s_UsrClass' % nm] = '/Users/%s/AppData/Local/Microsoft/Windows/UsrClass.dat' % nm
    for name, p in T.items():
        try:
            d = read(fs, p)
            if d:
                open(os.path.join(OUTROOT, name), 'wb').write(d)
                print('  %-28s %10d' % (name, len(d)))
        except Exception:
            pass


def cmd_sysinfo(fs):
    print('=' * 76)
    print('系统信息')
    print('=' * 76)
    cmd_hives(fs)
    from regipy.registry import RegistryHive
    cs = find_controlset(fs)
    sy = RegistryHive(os.path.join(OUTROOT, 'SYSTEM'))
    so = RegistryHive(os.path.join(OUTROOT, 'SOFTWARE'))
    print('\n[SYSTEM] ControlSet = %s' % cs)

    def g(reg, path, name):
        """regipy 6.x: get_value 直接返回值，不带 .value"""
        try:
            return reg.get_key(path).get_value(name)
        except Exception:
            return None

    print('  %-22s %s' % ('计算机名', g(sy, r'\ControlSet001\Control\ComputerName\ComputerName', 'ComputerName')
                          or g(sy, '\\%s\\Control\\ComputerName\\ComputerName' % cs, 'ComputerName')))
    tz = g(sy, '\\%s\\Control\\TimeZoneInformation' % cs, 'TimeZoneKeyName')
    print('  %-22s %s' % ('时区', tz))
    st = g(sy, '\\%s\\Control\\Windows' % cs, 'ShutdownTime')
    if isinstance(st, bytes) and len(st) >= 8:
        import struct as _s
        _ft = _s.unpack('<Q', st[:8])[0]
        _dt = ft2dt(_ft)
        st = _dt.strftime('%Y-%m-%d %H:%M:%S UTC') if _dt else st.hex()
    print('  %-22s %s' % ('最后关机', st))

    print('\n[SOFTWARE]')
    # 先判 hive 是否截断
    sw_path = os.path.join(OUTROOT, 'SOFTWARE')
    try:
        _d = open(sw_path, 'rb').read(0x30)
        _hbs = int.from_bytes(_d[0x28:0x2c], 'little')
        _sz = os.path.getsize(sw_path)
        if _hbs > _sz:
            print('  ⚠ hive 截断：头部声称 %d 字节，实际 %d，缺口 %d（采集不全）'
                  % (_hbs, _sz, _hbs - _sz))
    except Exception:
        pass
    cv = r'\Microsoft\Windows NT\CurrentVersion'
    got = 0
    for k, label in [('ProductName', '系统版本'), ('CurrentBuild', 'Build'),
                     ('DisplayVersion', '发行版号'), ('ProductId', '产品ID'),
                     ('InstallDate', '安装时间'), ('RegisteredOwner', '注册用户'),
                     ('ComputerName', '计算机名')]:
        try:
            v = g(so, cv, k)
        except Exception:
            v = None
        if k == 'InstallDate' and v:
            try:
                v = '%s (%s)' % (dt_utc(v), datetime.datetime.fromtimestamp(v, datetime.timezone.utc).date())
            except Exception:
                pass
        if v:
            print('  %-22s %s' % (label, v))
            got += 1
    if got == 0:
        print('  ⚠ SOFTWARE hive 不可读（截断/损坏），替代来源：')
        print('     - 系统版本 -> C:/Windows/System32/ntoskrnl.exe 版本资源')
        print('     - 安装时间 -> C:/Windows/Panther/setupact.log')
        print('     - 计算机名 -> SYSTEM hive 的 Control/ComputerName（已有）')
        print('     - 已装软件 -> C:/Program Files + Amcache.hve')


def cmd_accounts(fs):
    """SAM 账号。用户名从 V 值解析（比 Names 子键可靠）"""
    print('=' * 76)
    print('账号（SAM）')
    print('=' * 76)
    cmd_hives(fs)
    from regipy.registry import RegistryHive
    sam = RegistryHive(os.path.join(OUTROOT, 'SAM'))
    base = r'\SAM\Domains\Account\Users'

    # --- 1) 从 V 值解析 RID -> 用户名 ---
    names = {}
    fulls = {}
    for sk in sam.get_key(base).iter_subkeys():
        if not (len(sk.name) == 8 and all(c in '0123456789ABCDEFabcdef' for c in sk.name)):
            continue
        rid = int(sk.name, 16)
        try:
            v = sk.get_value('V')
        except Exception:
            continue
        data = v if isinstance(v, bytes) else getattr(v, 'value', b'')
        if not isinstance(data, bytes) or len(data) < 0x20:
            continue
        try:
            noff = struct.unpack('<I', data[0x0C:0x10])[0]
            nlen = struct.unpack('<I', data[0x10:0x14])[0]
            foff = struct.unpack('<I', data[0x18:0x1C])[0]
            flen = struct.unpack('<I', data[0x1C:0x20])[0]
        except Exception:
            continue

        def rd(off, ln):
            if ln == 0 or ln > 512:
                return ''
            for base_off in (off + 0xCC, off):
                if base_off + ln <= len(data):
                    try:
                        s = data[base_off:base_off + ln].decode('utf-16-le', 'replace')
                        if s and all(32 <= ord(c) < 0x3000 for c in s):
                            return s.rstrip('\x00')
                    except Exception:
                        pass
            return ''

        names[rid] = rd(noff, nlen)
        fulls[rid] = rd(foff, flen)

    # --- 2) 从 F 值取最后登录 ---
    print('%-7s %-22s %-14s %-10s %s' % ('RID', '用户名', '全名', '类型', '最后登录'))
    for sk in sam.get_key(base).iter_subkeys():
        if not (len(sk.name) == 8 and all(c in '0123456789ABCDEFabcdef' for c in sk.name)):
            continue
        rid = int(sk.name, 16)
        try:
            f = sk.get_value('F')
        except Exception:
            f = None
        val = (f if isinstance(f, bytes) else getattr(f, 'value', b'')) or b''
        last = None
        if len(val) >= 0x10:
            last = ft2dt(struct.unpack('<Q', val[0x08:0x10])[0])
        typv = '管理员' if rid == 500 else ('系统内置' if rid < 1000 else '普通用户')
        print('%-7d %-22s %-14s %-10s %s' % (
            rid, names.get(rid) or '(未知)', fulls.get(rid) or '',
            typv, last.strftime('%Y-%m-%d %H:%M:%S') if last else '-'))

    # --- 3) 组归属 ---
    print('\n[组]')
    try:
        for sk in sam.get_key(base).iter_subkeys():
            if len(sk.name) == 8:
                continue
        gk = sam.get_key(r'\SAM\Domains\Builtin\Aliases\Names')
        print('  内置组:', [x.name for x in gk.iter_subkeys()])
    except Exception:
        pass


def cmd_users(fs):
    print('=' * 76)
    print('用户级痕迹')
    print('=' * 76)
    cmd_hives(fs)
    from regipy.registry import RegistryHive
    for h in sorted(x for x in os.listdir(OUTROOT) if x.endswith('_NTUSER')):
        user = h[:-7]
        print('\n### %s' % user)
        reg = RegistryHive(os.path.join(OUTROOT, h))
        # RunMRU
        print('  [RunMRU]')
        try:
            for v in reg.get_key(r'\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU').iter_values():
                if v.name != 'MRUList':
                    vv = v if not hasattr(v, 'value') else v.value
                    print('    %s' % str(vv).rstrip('\\1'))
        except Exception:
            print('    (无)')
        # UserAssist
        print('  [UserAssist]')
        n = 0
        try:
            for sk in reg.get_key(r'\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist').iter_subkeys():
                try:
                    cv = sk.get_value('Count')
                except Exception:
                    continue
                data = cv if isinstance(cv, bytes) else getattr(cv, 'value', b'')
                for off in range(0, max(0, len(data) - 71), 72):
                    rec = data[off:off + 72]
                    run = struct.unpack('<I', rec[4:8])[0]
                    ft = struct.unpack('<Q', rec[60:68])[0]
                    dt = ft2dt(ft)
                    if dt and run:
                        print('    run=%-3d %s' % (run, dt.strftime('%Y-%m-%d %H:%M:%S')))
                        n += 1
        except Exception:
            pass
        if n == 0:
            print('    (空 —— 只有 Version 无 Count，可能被清理)')
        # RecentDocs
        print('  [RecentDocs]')
        try:
            for v in reg.get_key(r'\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs').iter_values():
                _v = v if isinstance(v, bytes) else getattr(v, 'value', b'')
                if v.name == 'MRUListEx' or not isinstance(_v, bytes):
                    continue
                nm = _v.split(b'\x00\x00')[0].decode('utf-16-le', 'replace').strip('\x00')
                if nm:
                    print('    %s' % nm)
        except Exception:
            pass


def cmd_usb(fs):
    print('=' * 76)
    print('外置存储（三通道）')
    print('=' * 76)
    cmd_hives(fs)
    from regipy.registry import RegistryHive
    sy = RegistryHive(os.path.join(OUTROOT, 'SYSTEM'))
    cs = find_controlset(fs)
    for label, path in [
        ('USBSTOR（U盘）', '\\%s\\Enum\\USBSTOR' % cs),
        ('SCSI（外置SSD，不落USBSTOR）', '\\%s\\Enum\\SCSI' % cs),
        ('USB（USB设备）', '\\%s\\Enum\\USB' % cs),
    ]:
        print('\n[%s]' % label)
        try:
            k = sy.get_key(path)
            for sk in k.iter_subkeys():
                print('  设备: %s' % sk.name)
                for sk2 in sk.iter_subkeys():
                    print('     SN/实例: %s' % sk2.name)
        except Exception:
            print('  (无)')


def cmd_software(fs):
    """已装软件。SOFTWARE hive 截断时降级到 Program Files 目录 + Amcache"""
    print('=' * 76)
    print('已装软件')
    print('=' * 76)
    cmd_hives(fs)
    from regipy.registry import RegistryHive

    got = 0
    try:
        so = RegistryHive(os.path.join(OUTROOT, 'SOFTWARE'))
        base = r'\Microsoft\Windows\CurrentVersion\Uninstall'
        for sk in so.get_key(base).iter_subkeys():
            try:
                dn = sk.get_value('DisplayName')
            except Exception:
                continue
            if not dn:
                continue
            nm = dn if not hasattr(dn, 'value') else dn.value
            ver = inst = ''
            try:
                _t = sk.get_value('DisplayVersion')
                ver = _t if not hasattr(_t, 'value') else _t.value
            except Exception:
                pass
            try:
                _t = sk.get_value('InstallDate')
                inst = _t if not hasattr(_t, 'value') else _t.value
            except Exception:
                pass
            print('  %-52s %-14s %s' % (str(nm)[:50], str(ver)[:12], inst))
            got += 1
    except Exception as e:
        print('  ⚠ SOFTWARE\\...\\Uninstall 不可读: %s' % str(e)[:60])

    if got:
        print('\n共 %d 个（来自注册表）' % got)
        return

    print('\n  → 降级：从 Program Files 目录 + Amcache 推断')
    roots = ['/Program Files', '/Program Files (x86)']
    # 自动发现用户目录，不写死用户名
    for un, _s, isdir, _m in ls(fs, '/Users'):
        if isdir and un not in ('All Users', 'Default', 'Default User', 'Public'):
            roots.append('/Users/%s/AppData/Local/Programs' % un)
    for root in roots:
        items = [(n, s, m) for n, s, d, m in ls(fs, root) if d]
        if not items:
            continue
        print('\n[%s] %d 个' % (root, len(items)))
        for n, s, m in sorted(items)[:40]:
            print('   %-46s crtime=%s' % (n[:44], dt_utc(m.crtime)))


def cmd_autorun(fs):
    print('=' * 76)
    print('启动项与服务')
    print('=' * 76)
    cmd_hives(fs)
    from regipy.registry import RegistryHive
    so = RegistryHive(os.path.join(OUTROOT, 'SOFTWARE'))
    sy = RegistryHive(os.path.join(OUTROOT, 'SYSTEM'))
    RUNS = [r'\Microsoft\Windows\CurrentVersion\Run',
            r'\Microsoft\Windows\CurrentVersion\RunOnce',
            r'\Wow6432Node\Microsoft\Windows\CurrentVersion\Run']
    print('\n[Run / RunOnce]')
    for r in RUNS:
        try:
            for v in so.get_key(r).iter_values():
                print('  %-30s %s' % (v.name, str(v.value)[:80]))
        except Exception:
            pass
    print('\n[服务（非微软）]')
    cs = find_controlset(fs)
    try:
        for sk in sy.get_key('\\%s\\Services' % cs).iter_subkeys():
            try:
                ip = sk.get_value('ImagePath')
                st = sk.get_value('Start')
            except Exception:
                continue
            if not ip:
                continue
            v = str(ip if not hasattr(ip, 'value') else ip.value)
            if 'system32' in v.lower() or 'syswow64' in v.lower():
                continue
            _st = (st if not hasattr(st, 'value') else st.value) if st else '?'
            print('  %-34s start=%-3s %s' % (sk.name[:32], _st, v[:70]))
    except Exception as e:
        print('  ERR', str(e)[:60])


def cmd_evtx(fs):
    out = os.path.join(OUTROOT, 'evtx')
    os.makedirs(out, exist_ok=True)
    print('=' * 76)
    print('导出事件日志')
    print('=' * 76)
    WANT = ['Security.evtx', 'System.evtx', 'Application.evtx',
            'Microsoft-Windows-PowerShell%4Operational.evtx',
            'Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx',
            'Microsoft-Windows-Sysmon%4Operational.evtx']
    for n in WANT:
        try:
            d = read(fs, '/Windows/System32/winevt/Logs/' + n)
            open(os.path.join(out, n), 'wb').write(d)
            print('  %-62s %10d' % (n, len(d)))
        except Exception:
            print('  %-62s MISSING' % n)
    csv = os.path.join(OUTROOT, 'evtx_csv')
    os.makedirs(csv, exist_ok=True)
    exe = os.path.join(EZ, 'EvtxECmd', 'EvtxeCmd', 'EvtxECmd.exe')
    if os.path.exists(exe):
        print('\n跑 EvtxECmd ...')
        subprocess.run([exe, '-d', out, '--csv', csv, '--csvf', 'all.csv'],
                       capture_output=True)
        p = os.path.join(csv, 'all.csv')
        if os.path.exists(p):
            import collections
            rows = list(__import__('csv').DictReader(open(p, encoding='utf-8', errors='replace')))
            print('  共 %d 条' % len(rows))
            c = collections.Counter(r['EventId'] for r in rows)
            print('\n  EventId 分布 TOP15:')
            for eid, n in c.most_common(15):
                print('    %-8s %d' % (eid, n))
            print('\n  关机/登录关键事件:')
            for r in rows:
                if r['EventId'] in ('1074', '6006', '6005', '6013', '1102', '104',
                                    '4720', '7045', '4697'):
                    print('    %-26s %-6s %-46s %s' % (
                        r['TimeCreated'][:24], r['EventId'],
                        r['Provider'][:44], (r.get('PayloadData1') or '')[:50]))


def cmd_pf(fs):
    print('=' * 76)
    print('Prefetch')
    print('=' * 76)
    items = [(n, s, m) for n, s, d, m in ls(fs, '/Windows/Prefetch') if n.endswith('.pf')]
    print('共 %d 个 .pf' % len(items))
    for n, s, m in sorted(items)[:40]:
        print('  %-52s crtime=%s' % (n, dt_utc(m.crtime)))
    if items:
        out = os.path.join(OUTROOT, 'prefetch')
        os.makedirs(out, exist_ok=True)
        for n, s, m in items:
            try:
                open(os.path.join(out, n), 'wb').write(read(fs, '/Windows/Prefetch/' + n))
            except Exception:
                pass
        print('\n已导出到 %s，可跑 PECmd' % out)


def cmd_browser(fs, user=None):
    print('=' * 76)
    print('浏览器数据 —— %s' % user)
    print('=' * 76)
    if not user:
        users = [n for n, s, d, m in ls(fs, '/Users') if d
                 and n not in ('All Users', 'Default', 'Default User', 'Public')]
        if not users:
            print('  未找到用户目录')
            return
        user = users[0]
        print('  自动选用户: %s' % user)
    base = '/Users/%s/AppData/Local' % user
    for br, rel in [('Chrome', 'Google/Chrome/User Data/Default'),
                    ('Edge', 'Microsoft/Edge/User Data/Default')]:
        d = '%s/%s' % (base, rel)
        print('\n[%s]' % br)
        for f in ('History', 'Web Data', 'Login Data', 'Cookies', 'Bookmarks'):
            p = '%s/%s' % (d, f)
            try:
                print('  %-14s %10d' % (f, fs.open(p).info.meta.size))
            except Exception:
                print('  %-14s MISSING' % f)
        out = os.path.join(OUTROOT, 'browser_%s' % br)
        os.makedirs(out, exist_ok=True)
        for f in ('History', 'Web Data', 'Login Data', 'Bookmarks'):
            try:
                open(os.path.join(out, f.replace(' ', '_')), 'wb').write(read(fs, '%s/%s' % (d, f)))
            except Exception:
                pass


def cmd_recent(fs, user=None):
    print('=' * 76)
    print('文件痕迹 —— %s' % user)
    print('=' * 76)
    if not user:
        users = [n for n, s, d, m in ls(fs, '/Users') if d
                 and n not in ('All Users', 'Default', 'Default User', 'Public')]
        if not users:
            print('  未找到用户目录')
            return
        user = users[0]
        print('  自动选用户: %s' % user)
    D = '/Users/%s/AppData/Roaming/Microsoft/Windows' % user
    for label, p in [('Recent(LNK)', D + '/Recent'),
                     ('AutomaticDestinations', D + '/Recent/AutomaticDestinations'),
                     ('CustomDestinations', D + '/Recent/CustomDestinations'),
                     ('Startup', D + '/Start Menu/Programs/Startup')]:
        items = [(n, s, m) for n, s, d, m in ls(fs, p) if not d]
        print('\n[%s] %d 项' % (label, len(items)))
        for n, s, m in items[:8]:
            print('   %-50s %8d' % (n, s))
    print('\n[回收站]')
    for p in ('/$Recycle.Bin', '/Users/%s/$Recycle.Bin' % user):
        items = [(n, s, m) for n, s, d, m in ls(fs, p) if not d]
        if items:
            print('  %s: %d 项' % (p, len(items)))
            for n, s, m in items[:8]:
                print('     %-46s %8d' % (n, s))


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return
    cmd, key = sys.argv[1], sys.argv[2]
    arg = sys.argv[3] if len(sys.argv) > 3 else None
    from ev import open_fs
    f = open_fs(key, lba=int(os.environ.get('CASE_LBA', 0)) or None)
    m = {'info': cmd_info, 'hives': cmd_hives, 'sysinfo': cmd_sysinfo,
         'accounts': cmd_accounts, 'users': cmd_users, 'usb': cmd_usb,
         'software': cmd_software, 'autorun': cmd_autorun, 'evtx': cmd_evtx,
         'pf': cmd_pf}
    if cmd == 'browser':
        cmd_browser(f, arg)
    elif cmd == 'recent':
        cmd_recent(f, arg)
    elif cmd in m:
        m[cmd](f)
    else:
        print(__doc__)


if __name__ == '__main__':
    main()
