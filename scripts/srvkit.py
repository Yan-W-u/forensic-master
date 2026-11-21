#!/usr/bin/env python3
"""srvkit.py —— 服务器（Linux）取证专用工具集

用法:
  python srvkit.py profile  <镜像或FS>            一次性出全貌（主机名/发行版/时区/用户）
  python srvkit.py accounts <key>                 账号与密码算法
  python srvkit.py cron     <key>                 计划任务全量解析
  python srvkit.py hist     <key> [user]          shell 历史 + 可疑命令分类
  python srvkit.py ssh      <key>                 SSH 登录/失败/密钥/配置
  python srvkit.py systemd  <key> [kw]            systemd 服务清单
  python srvkit.py docker   <key>                 容器配置全量表
  python srvkit.py web      <key>                 nginx/apache 配置摘要
  python srvkit.py timeline <key>                 关键文件 mtime 排序

<image> 镜像路径（.E01/.raw/.img）或 $CASE_DIR/images.json 里的 key
"""
import sys
import os
import re
import json
import datetime
import struct

# 技能目录必须优先（否则案件目录里的同名 ev.py 会抢占）
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.environ.get('CASE_DIR', '.'))
sys.path.insert(0, _HERE)

import pytsk3
import fsio


def utc(ts):
    """epoch 秒 → 带 UTC 标记（统一口径）"""
    return fsio.fmt_epoch(ts)


def read_text(fs, path):
    """普通文本。返回 (text, truncated)。

    显式返回 truncated，调用方要自己决定是否接受。
    """
    r = fsio.read_text(fs, path)
    return r.data.decode('utf-8', 'replace'), r.truncated


def read_log(fs, path, tail=None):
    """日志专用。

    日志是追加写的：offset 0 是最旧的。
    - tail=N     只读最后 N 字节 → 找「最后一次」「最近」
    - tail=None  全量读（到上限）→ 统计「总共多少次」
    """
    return fsio.log_text(fs, path, tail)


# 目录枚举统一走 fsio.Entry。name 永远是干净文件名，可原样拼路径。
ls = fsio.ls          # 默认排除已删除
ls_all = fsio.ls_all  # 显式包含已删除
fmt = fsio.fmt        # 展示时才加 [D] 标记
count = fsio.count


def cmd_profile(fs):
    print('=' * 76)
    print('系统概览')
    print('=' * 76)
    # os-release 要先判符号链接
    for p in ('/usr/lib/os-release', '/etc/os-release'):
        t, _tr = read_text(fs, p)
        if t and '=' in t:
            d = dict(l.split('=', 1) for l in t.splitlines() if '=' in l)
            print('%-18s %-12s %s' % ('发行版', d.get('ID', '?').strip('"'),
                                      d.get('PRETTY_NAME', '').strip('"')))
            print('%-18s %s' % ('VERSION_ID', d.get('VERSION_ID', '').strip('"')))
            break
    for label, p, pat in [
        ('主机名', '/etc/hostname', None),
        ('machine-id', '/etc/machine-id', None),
        ('时区', '/etc/timezone', None),
        ('内核', '/proc/version', None),
    ]:
        t, _tr = read_text(fs, p).strip()
        if t:
            print('%-18s %s' % (label, t.splitlines()[0][:90]))
    print()
    print('%-18s %s' % ('fstab 条目', ''))
    for ln in read_text(fs, '/etc/fstab').splitlines():
        if ln.strip() and not ln.startswith('#'):
            print('   ', ln[:110])


def cmd_accounts(fs):
    print('=' * 76)
    print('账号与 shell')
    print('=' * 76)
    algo = {'$1$': 'md5', '$5$': 'sha256', '$6$': 'sha512', '$y$': 'yescrypt',
            '$2b$': 'bcrypt', '$2y$': 'bcrypt', '$argon2': 'argon2'}
    shadow = {}
    for ln in read_text(fs, '/etc/shadow').splitlines():
        p = ln.split(':')
        if len(p) > 1:
            shadow[p[0]] = p[1]
    print('%-18s %-6s %-6s %-10s %-12s %s' % ('用户', 'UID', 'GID', 'shell', '密码算法', '状态'))
    for ln in read_text(fs, '/etc/passwd').splitlines():
        p = ln.split(':')
        if len(p) < 7:
            continue
        name, _, uid, gid, _, _, shell = p[:7]
        h = shadow.get(name, '')
        a = '-'
        for k, v in algo.items():
            if h.startswith(k):
                a = v
                break
        st = '锁定' if h.startswith(('!', '*')) else ('空密码' if h == '' else '可登录')
        if h == '' and name not in shadow:
            st = '无shadow'
        print('%-18s %-6s %-6s %-10s %-12s %s' % (name, uid, gid, shell.split('/')[-1], a, st))


def cmd_cron(fs):
    print('=' * 76)
    print('计划任务')
    print('=' * 76)
    LOCS = ['/etc/crontab', '/etc/anacrontab']
    for d in ('/etc/cron.d', '/var/spool/cron/crontabs', '/var/spool/cron'):
        for e in ls(fs, d):
            nm, sz, isdir, m = e.name, e.size, e.is_dir, e.meta
            if not isdir:
                LOCS.append(d.rstrip('/') + '/' + nm)
    for d in ('/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly'):
        for e in ls(fs, d):
            nm, sz, isdir, m = e.name, e.size, e.is_dir, e.meta
            if not isdir:
                print('  [%s] %s' % (d.split('/')[-1], nm))

    BACKDOOR = ['curl', 'wget', 'base64 -d', '/dev/tcp/', 'nc -e', 'bash -i',
                'python -c', 'perl -e', 'xxd -r', 'chmod +x /tmp', 'sh -c']
    for p in LOCS:
        t, _tr = read_text(fs, p)
        if not t.strip():
            continue
        print('\n--- %s ---' % p)
        try:
            m = fs.open(p).info.meta
            print('    mtime=%s ctime=%s' % (utc(m.mtime), utc(m.ctime)))
        except Exception:
            pass
        for ln in t.splitlines():
            s = ln.strip()
            if not s or s.startswith('#'):
                continue
            flag = ''
            if any(k in s for k in BACKDOOR):
                flag = '  <<< 可疑'
            print('   ', s[:130] + flag)

    # systemd timer
    print('\n--- systemd timer ---')
    for d in ('/etc/systemd/system', '/usr/lib/systemd/system'):
        for e in ls(fs, d):
            nm, sz, isdir, m = e.name, e.size, e.is_dir, e.meta
            if not nm.endswith('.timer'):
                continue
            t, _tr = read_text(fs, d + '/' + nm)
            cal = re.search(r'OnCalendar=(.*)', t)
            unit = re.search(r'Unit=(.*)', t)
            print('  %-40s %-26s -> %s' % (nm, (cal.group(1) if cal else '?'),
                                           unit.group(1) if unit else '?'))


def cmd_hist(fs, user='root'):
    print('=' * 76)
    print('Shell 历史 —— %s' % user)
    print('=' * 76)
    base = '/root' if user == 'root' else '/home/' + user
    FILES = ['.bash_history', '.zsh_history', '.python_history',
             '.mysql_history', '.viminfo', '.lesshst']
    SUSPICIOUS = {
        '下载': ['wget', 'curl', 'scp ', 'rsync', 'git clone'],
        '提权': ['sudo', 'su -', 'chmod +s', 'find / -perm'],
        '持久化': ['crontab', 'systemctl enable', '>> ~/.bashrc', 'rc.local', 'authorized_keys'],
        '横向': ['ssh ', 'sshpass', 'proxychains', 'nmap', 'masscan'],
        '外传': ['tar czf', 'zip -r', 'base64', 'split', 'nc -'],
        '清理': ['shred', 'rm -rf', 'history -c', 'unset HISTFILE', '>/dev/null'],
    }
    for fn in FILES:
        t, _tr = read_text(fs, base + '/' + fn)
        if not t.strip():
            continue
        lines = t.splitlines()
        print('\n--- %s (%d 行) ---' % (fn, len(lines)))
        ts = None
        for ln in lines[:400]:
            if ln.startswith('#') and ln[1:].isdigit():
                ts = int(ln[1:])
                continue
            m = re.match(r'^: (\d+):(\d+);(.*)$', ln)
            if m:
                ts, ln = int(m.group(1)), m.group(3)
            if not ln.strip():
                continue
            tag = ''
            for cat, keys in SUSPICIOUS.items():
                if any(k in ln for k in keys):
                    tag = ' [%s]' % cat
                    break
            if tag:
                print('  %s  %s%s' % (utc(ts) if ts else '-', ln[:110], tag))
        # 统计
        allcmd = [l for l in lines if l.strip() and not l.startswith(('#', ':'))]
        print('  共 %d 条命令' % len(allcmd))


def cmd_ssh(fs):
    print('=' * 76)
    print('SSH 取证')
    print('=' * 76)
    cfg, _tr = read_text(fs, '/etc/ssh/sshd_config')
    if cfg:
        for k in ('Port', 'PermitRootLogin', 'PasswordAuthentication',
                  'PubkeyAuthentication', 'AllowUsers', 'MaxAuthTries'):
            for ln in cfg.splitlines():
                if ln.strip().startswith(k):
                    print('  %-28s %s' % (k, ln.strip()))
                    break
    else:
        print('  sshd_config 未找到')

    print('\n--- 认证日志（登录/失败/sudo）---')
    for p in ('/var/log/auth.log', '/var/log/secure'):
        # 先读尾部看「最近」，再全量统计
        tail, _tr = read_log(fs, p, tail=2 << 20)
        t, _tr = read_log(fs, p)
        if not t.strip() and not tail.strip():
            continue
        # 尾部里找最后一次成功登录
        last_ok = None
        for ln in tail.splitlines():
            m2 = re.search(r'Accepted (\S+) for (\S+) from ([\d.]+)', ln)
            if m2:
                last_ok = (ln[:15], m2.group(1), m2.group(2), m2.group(3))
        if last_ok:
            print('  最近成功登录: %s  方式=%s 用户=%s 来源=%s' % last_ok)
        ok = re.findall(r'Accepted (\S+) for (\S+) from ([\d.]+)', t)
        bad = re.findall(r'Failed (\S+) for (?:invalid user )?(\S+) from ([\d.]+)', t)
        print('  %s: 成功 %d 次, 失败 %d 次' % (p, len(ok), len(bad)))
        from collections import Counter
        print('    成功来源 TOP:', Counter(x[2] for x in ok).most_common(5))
        print('    失败来源 TOP:', Counter(x[2] for x in bad).most_common(5))
        print('    登录方式:', Counter(x[0] for x in ok).most_common())
        break

    print('\n--- authorized_keys（后门排查）---')
    for u in ('/root', '/home'):
        cands = [u + '/.ssh/authorized_keys'] if u == '/root' else []
        if u == '/home':
            for e in ls(fs, '/home'):
                nm, sz, isdir, m = e.name, e.size, e.is_dir, e.meta
                if isdir:
                    cands.append('/home/%s/.ssh/authorized_keys' % nm)
        for p in cands:
            t, _tr = read_text(fs, p)
            if not t.strip():
                continue
            print('  ---', p)
            try:
                m = fs.open(p).info.meta
                print('      mtime=%s' % utc(m.mtime))
            except Exception:
                pass
            for ln in t.splitlines():
                if ln.strip() and not ln.startswith('#'):
                    parts = ln.split()
                    print('      %-14s %s' % (parts[0] if parts else '?',
                                              parts[-1][:60] if len(parts) > 2 else ''))


def cmd_systemd(fs, kw=''):
    print('=' * 76)
    print('systemd 服务')
    print('=' * 76)
    for d in ('/etc/systemd/system', '/usr/lib/systemd/system'):
        for e in ls(fs, d):
            nm, sz, isdir, m = e.name, e.size, e.is_dir, e.meta
            if not nm.endswith('.service'):
                continue
            if kw and kw.lower() not in nm.lower():
                continue
            t, _tr = read_text(fs, d + '/' + nm)
            desc = re.search(r'Description=(.*)', t)
            ex = re.search(r'ExecStart=(.*)', t)
            print('  %-42s' % nm)
            if desc:
                print('        desc: %s' % desc.group(1).strip()[:90])
            if ex:
                print('        exec: %s' % ex.group(1).strip()[:90])
            for k in ('ExecStop', 'ExecStopPost', 'Requires', 'After'):
                mm = re.search(k + r'=(.*)', t)
                if mm:
                    print('        %-12s %s' % (k + ':', mm.group(1).strip()[:80]))


def cmd_docker(fs):
    print('=' * 76)
    print('Docker 容器')
    print('=' * 76)
    base = '/var/lib/docker/containers'
    for e in ls(fs, base):
        nm, sz, isdir, m = e.name, e.size, e.is_dir, e.meta
        if not isdir:
            continue
        p = '%s/%s/config.v2.json' % (base, nm)
        t, _tr = read_text(fs, p)
        if not t:
            continue
        try:
            j = json.loads(t)
        except Exception:
            continue
        print('\n%s' % j.get('Name', '?'))
        print('  Image : %s' % (j.get('Config') or {}).get('Image'))
        print('  Path  : %s %s' % (j.get('Path'), j.get('Args')))
        for e in ((j.get('Config') or {}).get('Env') or []):
            print('  ENV    %s' % e)
        for k, v in (j.get('MountPoints') or {}).items():
            print('  MNT    %s -> %s' % (k, v.get('Source')))
        labels = (j.get('Config') or {}).get('Labels') or {}
        for k, v in labels.items():
            if 'compose' in k:
                print('  LBL    %s = %s' % (k, v))


def cmd_web(fs):
    print('=' * 76)
    print('Web 服务器配置')
    print('=' * 76)
    # 标准路径 + 应用自带配置（gate.conf / *.conf）
    CAND = ['/etc/nginx/nginx.conf', '/etc/nginx/sites-enabled/default',
            '/etc/nginx/conf.d/default.conf']
    for base in ('/opt', '/usr/local', '/srv', '/var/www', '/data'):
        for e in ls(fs, base):
            nm, sz, isdir, m = e.name, e.size, e.is_dir, e.meta
            if isdir:
                for e2 in ls(fs, base + '/' + nm):
                    nm2, sz2, isdir2, m2 = e2.name, e2.size, e2.is_dir, e2.meta
                    if not isdir2 and nm2.endswith('.conf'):
                        CAND.append('%s/%s/%s' % (base, nm, nm2))
            elif nm.endswith('.conf'):
                CAND.append(base + '/' + nm)
    for p in CAND:
        t, _tr = read_text(fs, p)
        if not t.strip():
            continue
        lines = [l.strip() for l in t.splitlines()
                 if any(k in l for k in ('listen', 'server_name', 'root ',
                                         'proxy_pass', 'upstream', 'access_log',
                                         'error_log'))]
        if not lines:
            continue
        print('\n--- %s ---' % p)
        for s in lines:
            print('   ', s[:120])
    for p in ('/etc/apache2/ports.conf', '/etc/httpd/conf/httpd.conf'):
        t, _tr = read_text(fs, p)
        if t.strip():
            print('\n--- %s ---' % p)
            for ln in t.splitlines():
                if 'Listen' in ln or 'DocumentRoot' in ln:
                    print('   ', ln.strip()[:120])


def cmd_timeline(fs):
    print('=' * 76)
    print('关键文件时间线（mtime 升序）')
    print('=' * 76)
    TARGETS = ['/etc/passwd', '/etc/shadow', '/etc/crontab', '/etc/hosts',
               '/etc/ssh/sshd_config', '/etc/systemd/system',
               '/usr/local/bin', '/opt', '/root/.bash_history',
               '/var/log/auth.log', '/var/log/syslog']
    rows = []
    for p in TARGETS:
        for e in ls(fs, os.path.dirname(p)):
            nm, sz, isdir, m = e.name, e.size, e.is_dir, e.meta
            full = os.path.dirname(p) + '/' + nm
            if os.path.basename(p) and nm != os.path.basename(p):
                continue
            rows.append((m.mtime if m else 0, full, sz))
        if not os.path.basename(p):
            for e in ls(fs, p):
                nm, sz, isdir, m = e.name, e.size, e.is_dir, e.meta
                rows.append((m.mtime if m else 0, p + '/' + nm, sz))
    for mt, p, sz in sorted(set(rows))[:60]:
        print('  %s  %10d  %s' % (utc(mt), sz, p))


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return
    cmd, key = sys.argv[1], sys.argv[2]
    from ev import open_fs
    f = open_fs(key, lba=int(os.environ.get('CASE_LBA', 0)) or None)
    fn = {'profile': cmd_profile, 'accounts': cmd_accounts, 'cron': cmd_cron,
          'ssh': cmd_ssh, 'docker': cmd_docker, 'web': cmd_web,
          'timeline': cmd_timeline}.get(cmd)
    if cmd == 'hist':
        cmd_hist(f, sys.argv[3] if len(sys.argv) > 3 else 'root')
    elif cmd == 'systemd':
        cmd_systemd(f, sys.argv[3] if len(sys.argv) > 3 else '')
    elif fn:
        fn(f)
    else:
        print(__doc__)


if __name__ == '__main__':
    main()
