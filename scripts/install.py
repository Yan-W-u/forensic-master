#!/usr/bin/env python3
"""install.py —— forensic-master 一键部署器

用法:
  python install.py                  # 交互式：检查 + 问你要装什么
  python install.py --check          # 只检查，不装
  python install.py --all            # 装全部（含可选）
  python install.py --critical       # 只装关键项
  python install.py --py-only        # 只装 Python 库
  python install.py --bin-only       # 只装二进制工具
  python install.py --from FILE      # 从 GitHub/本地目录部署技能本体

设计原则:
  - 装任何东西前先查本机（铁律 3）
  - 全部可跳过，不会卡在半路
  - 装完立刻自检，失败项列清单给手动方案
"""
import os
import sys
import json
import shutil
import argparse
import subprocess
import platform

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import manifest

IS_WIN = platform.system() == 'Windows'
FT = os.environ.get('FORENSIC_TOOLS',
                    r'D:\ForensicTools' if IS_WIN else os.path.expanduser('~/forensic-tools'))
TSINGHUA = 'https://pypi.tuna.tsinghua.edu.cn/simple'
PYPI = 'https://pypi.org/simple'

# 输出符号
OK, NO, SKIP, WARN = '✓', '✗', '·', '!'


def hr(t=''):
    print('\n' + '=' * 68)
    if t:
        print(t)
        print('=' * 68)


def run(cmd, shell=False, timeout=600, capture=True):
    try:
        r = subprocess.run(cmd, shell=shell, timeout=timeout,
                           capture_output=capture, text=True,
                           encoding='utf-8', errors='replace')
        return r.returncode, (r.stdout or '') + (r.stderr or '')
    except subprocess.TimeoutExpired:
        return -1, 'TIMEOUT'
    except Exception as e:
        return -2, str(e)


# ============================================================
# Python 库
# ============================================================
def check_py():
    import importlib
    res = []
    for x in manifest.PY_LIBS:
        try:
            m = importlib.import_module(x['import_'])
            v = getattr(m, '__version__', '')
            res.append((x, True, v))
        except Exception:
            res.append((x, False, ''))
    return res


def install_py(items, mirror=TSINGHUA):
    """items: manifest entry 列表"""
    todo = [x for x in items if x.get('pip')]
    if not todo:
        return 0, 0
    ok = fail = 0
    pkgs = [x['pip'] for x in todo]
    print('  安装 %d 个包...' % len(pkgs))
    # 分批装，单个失败不影响其他
    for pkg in pkgs:
        cmd = [sys.executable, '-m', 'pip', 'install', '--quiet',
               '--disable-pip-version-check', '--no-warn-script-location',
               '-i', mirror, pkg]
        rc, out = run(cmd, timeout=900)
        if rc == 0:
            print('    %s %s' % (OK, pkg))
            ok += 1
        else:
            # 换官方源重试一次
            cmd[-1] = pkg
            cmd[cmd.index('-i') + 1] = PYPI
            rc2, out2 = run(cmd, timeout=900)
            if rc2 == 0:
                print('    %s %s（官方源）' % (OK, pkg))
                ok += 1
            else:
                print('    %s %-22s %s' % (NO, pkg, out.strip().splitlines()[-1][:60]
                                            if out.strip() else '失败'))
                fail += 1
    return ok, fail


# ============================================================
# 二进制工具
# ============================================================
def which_tool(entry):
    """返回 (是否已装, 找到的路径)"""
    for p in entry.get('check') or []:
        full = p if os.path.isabs(p) else os.path.join(FT, p)
        if os.path.exists(full):
            return True, full
    # 再查 PATH
    base = entry['name'].split()[0].lower()
    for cand in (base, base.replace('-', ''), 'tshark', 'diec', 'hashcat', 'veracrypt'):
        w = shutil.which(cand)
        if w:
            return True, w
    return False, ''


def check_bin():
    return [(x, *which_tool(x)) for x in manifest.tools()]


def try_winget(entry):
    wid = entry.get('winget')
    if not wid or not IS_WIN:
        return False, 'no winget id'
    if not shutil.which('winget'):
        return False, 'winget 不可用'
    cmd = ['winget', 'install', '--id', wid, '-e', '--silent',
           '--accept-package-agreements', '--accept-source-agreements']
    rc, out = run(cmd, timeout=1200)
    return rc == 0, out[-300:]


def _download_one(url, dest, label=''):
    """下载+解压单个 URL 到 dest。返回 (ok, msg)"""
    if not url:
        return False, '无 URL'
    os.makedirs(dest, exist_ok=True)
    fname = url.split('/')[-1].split('?')[0]
    local = os.path.join(FT, '_dl', fname)
    os.makedirs(os.path.dirname(local), exist_ok=True)

    print('    下载 %s' % fname)
    # 优先 aria2c，其次 curl，最后 urllib
    if shutil.which('aria2c'):
        rc, out = run(['aria2c', '--no-conf', '--console-log-level=error',
                       '--summary-interval=0', '--max-tries=2', '--timeout=40',
                       '-d', os.path.dirname(local), '-o', fname, url], timeout=900)
    elif shutil.which('curl'):
        rc, out = run(['curl', '-L', '--retry', '2', '--max-time', '600',
                       '-o', local, url], timeout=900)
    else:
        try:
            import urllib.request
            urllib.request.urlretrieve(url, local)
            rc = 0
        except Exception as e:
            rc, out = -1, str(e)

    if rc != 0 or not os.path.exists(local):
        return False, '下载失败: %s' % str(out)[-120:]

    size = os.path.getsize(local)
    print('    %s %s (%.1f MB)' % (OK, fname, size / 1e6))

    # 解压
    low = fname.lower()
    if low.endswith(('.zip', '.7z')):
        z = shutil.which('7z') or (r'C:\Program Files\7-Zip\7z.exe'
                                   if os.path.exists(r'C:\Program Files\7-Zip\7z.exe') else None)
        if not z:
            return False, '需要 7-Zip 解压，请先装 7-Zip'
        rc, out = run([z, 'x', local, '-o' + dest, '-y'], timeout=600)
        if rc != 0:
            return False, '解压失败'
        print('    %s 已解压到 %s' % (OK, dest))
        return True, dest
    elif low.endswith('.exe'):
        # 安装包：静默尝试，失败则提示手动
        tgt = os.path.join(FT, fname)
        shutil.copy2(local, tgt)
        print('    %s 安装包已保存: %s' % (OK, tgt))
        print('       请手动运行安装（或试 -S / /S 静默参数）')
        return True, tgt
    return False, '不认识的格式'


def try_download(entry):
    """下载 + 解压。支持单 url 与 extra 列表（EzTools 全家桶这类）。

    extra 格式: [('子工具名', 'url'), ...]，各自解压到 dest/子工具名
    """
    dest = os.path.join(FT, entry.get('dest') or '')
    os.makedirs(dest if entry.get('dest') else FT, exist_ok=True)

    targets = []
    url = entry.get('url')
    if url:
        targets.append((None, url))
    for sub, sub_url in (entry.get('extra') or []):
        targets.append((sub, sub_url))

    if not targets:
        return False, '无下载地址'

    ok_n = fail_n = 0
    last_msg = ''
    for sub, u in targets:
        sub_dest = os.path.join(dest, sub) if sub else dest
        r, msg = _download_one(u, sub_dest, sub or entry.get('name', ''))
        if r:
            ok_n += 1
        else:
            fail_n += 1
            last_msg = msg

    total = ok_n + fail_n
    if total > 1:
        print('    %s %d/%d 个子项' % (OK if fail_n == 0 else '!', ok_n, total))
    if ok_n == 0:
        return False, last_msg or '全部失败'
    if fail_n:
        return True, '%d/%d 成功（%s）' % (ok_n, total, last_msg[:60])
    return True, dest


def install_bin(items):
    ok = fail = 0
    for x in items:
        name = x['name']
        print('  %-38s' % name, end='', flush=True)
        done = False
        # 1) winget
        if IS_WIN:
            r, msg = try_winget(x)
            if r:
                print(' %s winget' % OK)
                ok += 1
                done = True
        # 2) 直接下载
        if not done:
            print(' ', end='', flush=True)
            r, msg = try_download(x)
            if r:
                print(' %s 下载' % OK)
                ok += 1
                done = True
        if not done:
            print(' %s %s' % (NO, str(msg)[:70]))
            if x.get('alt'):
                print('       手动: %s' % x['alt'])
            fail += 1
    return ok, fail


# ============================================================
# 主流程
# ============================================================
def do_check(verbose=True, profile='core'):
    hr('依赖检查')
    py = check_py()
    bn = check_bin()

    miss_crit_py = [x for x, ok, _ in py if not ok and x['critical']]
    miss_opt_py = [x for x, ok, _ in py if not ok and not x['critical']]
    miss_crit_bn = [x for x, ok, _ in bn if not ok and x['critical']]
    miss_opt_bn = [x for x, ok, _ in bn if not ok and not x['critical']]

    print('\n[Python 库] 共 %d，缺 %d（关键 %d）' % (
        len(py), len(miss_crit_py) + len(miss_opt_py), len(miss_crit_py)))
    if verbose:
        for x, ok, v in py:
            mark = OK if ok else (NO if x['critical'] else SKIP)
            print('  %s %-26s %-12s %s' % (mark, x['import_'], v or '-', x['desc']))

    print('\n[二进制工具] 共 %d，缺 %d（关键 %d）' % (
        len(bn), len(miss_crit_bn) + len(miss_opt_bn), len(miss_crit_bn)))
    if verbose:
        for x, ok, path in bn:
            mark = OK if ok else (NO if x['critical'] else SKIP)
            print('  %s %-38s %s' % (mark, x['name'], path or '-'))

    hr('汇总')
    if miss_crit_py or miss_crit_bn:
        print('!! 缺关键项 %d 个：' % (len(miss_crit_py) + len(miss_crit_bn)))
        for x in miss_crit_py:
            print('   - %-24s pip install %s' % (x['import_'], x['pip']))
        for x in miss_crit_bn:
            print('   - %-38s %s' % (x['name'], x.get('alt') or x.get('url') or ''))
        return False
    print('关键项全部就位。')
    if miss_opt_py or miss_opt_bn:
        print('可选缺失 %d 个（不影响主线）' % (len(miss_opt_py) + len(miss_opt_bn)))
    return True


def deploy_skill(target=None):
    """把技能本体部署到 ~/.dsh/skills/"""
    hr('部署技能本体')
    dst = target or os.path.join(
        os.environ.get('USERPROFILE', os.path.expanduser('~')),
        '.dsh', 'skills', 'forensic-master')
    src = os.path.dirname(HERE)   # scripts 的上级就是技能根
    if os.path.abspath(src) == os.path.abspath(dst):
        print('  已在目标位置: %s' % dst)
        return True
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.exists(dst):
        bak = dst + '.bak-' + __import__('datetime').datetime.now().strftime('%Y%m%d%H%M')
        shutil.move(dst, bak)
        print('  旧版本备份到: %s' % bak)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns('.git', '__pycache__'))
    print('  %s 已部署到 %s' % (OK, dst))
    return True


def main():
    ap = argparse.ArgumentParser(description='forensic-master 部署器')
    ap.add_argument('--check', action='store_true', help='只检查')
    ap.add_argument('--all', action='store_true', help='装全部')
    ap.add_argument('--critical', action='store_true', help='只装关键项')
    ap.add_argument('--py-only', action='store_true')
    ap.add_argument('--bin-only', action='store_true')
    ap.add_argument('--quiet', action='store_true', help='检查时不列全部')
    ap.add_argument('--yes', '-y', action='store_true',
                    help='不再询问，直接安装（无人值守用）')
    ap.add_argument('--profile', default='core',
                    choices=['docs', 'lite', 'core', 'automotive', 'full'],
                    help='安装档次：docs=只文档 / lite=轻量(磁盘+流量) / '
                         'core=常用全量(默认) / automotive=加车联网 / full=全装')
    args = ap.parse_args()

    hr('forensic-master 部署器')
    print('Python : %s' % sys.version.split()[0])
    print('平台   : %s' % platform.platform())
    print('工具根 : %s' % FT)
    print('镜像   : 清华（失败自动切官方源）')

    s = manifest.summary()
    print('\n清单：Python 库 %d（关键 %d）| 二进制 %d（关键 %d）| CLI %d | 脚本 %d'
          % (s['py_total'], s['py_crit'], s['bin_total'], s['bin_crit'],
             s['cli'], s['scripts']))
    os.makedirs(FT, exist_ok=True)

    if args.check:
        ok = do_check(verbose=not args.quiet, profile=args.profile)
        sys.exit(0 if ok else 1)

    # ---- docs 档：只读手册，零依赖 ----
    if args.profile == 'docs':
        hr('docs 档：不装任何依赖')
        print('12 份手册在 references/ 下，纯 Markdown，直接打开就能读：')
        for f in ('quickwin.md', 'traps.md', 'windows.md', 'linux.md',
                  'mobile.md', 'network.md', 'iot.md', 'automotive.md',
                  'containers.md', 'case2.md', 'howto.md', 'parallel.md'):
            print('   references/%s' % f)
        print('\n需要跑工具时再装：')
        print('   python scripts/install.py --profile lite    # 约 300 MB')
        print('   python scripts/install.py --profile core    # 约 800 MB')
        print('   python scripts/install.py --profile full    # 约 3 GB')
        return

    # 决定装什么
    do_py = not args.bin_only
    do_bin = not args.py_only
    only_crit = args.critical and not args.all

    if args.all and args.profile == 'core':
        # -All 且没显式指定 profile → 装全部
        py_list, bin_list = manifest.profile_items('full')
    elif args.all:
        # -All + 显式 profile → 以 profile 为准，并告警
        print('! 同时给了 --all 和 --profile %s，以 profile 为准'
              % args.profile)
        py_list, bin_list = manifest.profile_items(args.profile)
    elif args.critical:
        py_list, bin_list = manifest.profile_items('core')
        py_list = [x for x in py_list if x['critical']]
        bin_list = [x for x in bin_list if x['critical']]
    else:
        py_list, bin_list = manifest.profile_items(args.profile)

    print('\n档次: %s —— %s' % (args.profile,
                               manifest.PROFILES[args.profile]['desc']))

    # 先查已装的，避免重复
    py_now = {x['import_']: ok for x, ok, _ in check_py()}
    py_todo = [x for x in py_list if not py_now.get(x['import_'])]
    bn_now = {x['name']: ok for x, ok, _ in check_bin()}
    bn_todo = [x for x in bin_list if not bn_now.get(x['name'])]

    hr('安装计划')
    print('Python 库：需装 %d 个（已有 %d）' % (len(py_todo), len(py_list) - len(py_todo)))
    print('二进制  ：需装 %d 个（已有 %d）' % (len(bn_todo), len(bin_list) - len(bn_todo)))

    # 无人值守：--yes 或 非交互式 stdin 时直接开装
    if not args.all and not args.critical and not args.yes:
        interactive = sys.stdin.isatty()
        if not interactive:
            print('\n非交互式环境，直接安装')
        else:
            try:
                ans = input('\n开始安装？[Y/n] ').strip().lower()
            except (EOFError, KeyboardInterrupt):
                print('\n已取消。')
                return
            if ans and ans not in ('y', 'yes', ''):
                print('已取消。')
                return

    total_ok = total_fail = 0
    if do_py and py_todo:
        hr('安装 Python 库')
        o, f = install_py(py_todo)
        total_ok += o
        total_fail += f

    if do_bin and bn_todo:
        hr('安装二进制工具')
        o, f = install_bin(bn_todo)
        total_ok += o
        total_fail += f

    # CLI（caringcaribou 等）
    if do_py:
        hr('安装 Python 命令行工具')
        for x in manifest.PY_CLI:
            if shutil.which(x['name']):
                print('  %s %-20s 已存在' % (OK, x['name']))
                continue
            print('  %-20s ' % x['name'], end='', flush=True)
            rc, out = run([sys.executable, '-m', 'pip', 'install', '--quiet',
                           '-i', TSINGHUA, x['pip']], timeout=600)
            print(OK if rc == 0 else NO)
            total_ok += 1 if rc == 0 else 0
            total_fail += 0 if rc == 0 else 1

    hr('安装完成')
    print('%s 成功 %d / 失败 %d' % (OK, total_ok, total_fail))
    do_check(verbose=False, profile=args.profile)

    print('\n下一步：')
    print('  1. 重启 DSH（让它重新扫描 skills 目录）')
    print('  2. 新会话里说「用 forensic-master 开工」')
    print('  3. 或者直接跑: python %s --check' % os.path.join(HERE, 'toolcheck.py'))


if __name__ == '__main__':
    main()
