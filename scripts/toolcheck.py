"""forensic-master 工具链自检 —— 开工前跑一次

依赖清单来自 manifest.py（与 install.py 共用同一份数据源）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import manifest

# 工具根路径可用环境变量覆盖
FT = os.environ.get('FORENSIC_TOOLS', r'D:\ForensicTools')


def resolve(p):
    """相对路径按 FORENSIC_TOOLS 解析"""
    if os.path.isabs(p):
        return p
    return os.path.join(FT, p)



# ============================================================
# 5. 冒烟测试：能 import 不等于能跑
# ============================================================
def smoke(scripts_dir):
    """对每个 kit 用空参数调一次。

    只 import 会漏掉函数体里的崩溃（tuple 没有 .strip() 这类），
    实际跑一遍才发现。
    """
    import subprocess
    print('\n[5] 冒烟测试（空参数调用）')
    kits = ['winkit.py', 'srvkit.py', 'phonekit.py', 'netkit.py',
            'iotkit.py', 'hexins.py', 'ev.py', 'fsio.py']
    bad = []
    for fn in kits:
        pth = os.path.join(scripts_dir, fn)
        if not os.path.exists(pth):
            continue
        try:
            r = subprocess.run([sys.executable, pth], capture_output=True,
                               text=True, encoding='utf-8', errors='replace',
                               cwd=os.environ.get('TEMP', '.'))
            err = r.stderr or ''
            if 'Traceback' in err:
                lines = [l for l in err.splitlines() if l.strip()]
                msg = lines[-1][:70] if lines else '?'
                bad.append((fn, msg))
                print('  BAD %-14s %s' % (fn, msg))
            else:
                print('  OK  %-14s' % fn)
        except Exception as e:
            bad.append((fn, str(e)[:60]))
            print('  BAD %-14s %s' % (fn, str(e)[:60]))
    return bad


def main():
    print('=' * 68)
    print('forensic-master 工具链自检')
    print('=' * 68)
    print('工具根: %s' % FT)

    miss_crit, miss_opt = [], []

    # ---------- 1. Python 库 ----------
    print('\n[1] Python 库（%d 个）' % len(manifest.PY_LIBS))
    import importlib
    for x in manifest.PY_LIBS:
        mod = x['import_']
        try:
            m = importlib.import_module(mod)
            v = getattr(m, '__version__', '')
            print('  OK   %-24s %-12s %s' % (mod, str(v)[:12], x['desc']))
        except Exception:
            tag = 'CRIT' if x['critical'] else 'opt '
            print('  %s %-24s %-12s %s' % (tag, mod, '-', x['desc']))
            (miss_crit if x['critical'] else miss_opt).append(mod)

    # ---------- 2. 二进制工具 ----------
    tools = manifest.tools()
    print('\n[2] 二进制工具（%d 个）' % len(tools))
    for x in tools:
        found = ''
        for p in (x.get('check') or []):
            full = resolve(p)
            if os.path.exists(full):
                found = full
                break
        if not found:
            name = x['name'].split()[0].lower()
            import shutil
            for cand in (name, 'tshark', 'diec', 'hashcat', 'veracrypt', '7z'):
                w = shutil.which(cand)
                if w:
                    found = w
                    break
        if found:
            print('  OK   %-38s %s' % (x['name'], found))
        else:
            tag = 'CRIT' if x['critical'] else 'opt '
            print('  %s %-38s %s' % (tag, x['name'], x['desc']))
            (miss_crit if x['critical'] else miss_opt).append(x['name'])

    # ---------- 3. Python CLI ----------
    import shutil
    print('\n[3] Python 命令入口')
    for x in manifest.PY_CLI:
        exe = os.path.join(os.path.dirname(sys.executable), 'Scripts', x['name'] + '.exe')
        w = shutil.which(x['name'])
        if os.path.exists(exe) or w:
            print('  OK   %-24s %s' % (x['name'], exe if os.path.exists(exe) else w))
        else:
            print('  opt  %-24s %s' % (x['name'], x['desc']))
            miss_opt.append(x['name'])

    # ---------- 4. 技能自带脚本 ----------
    here = os.path.dirname(os.path.abspath(__file__))
    print('\n[4] 技能自带脚本（%d 个）' % len(manifest.SKILL_SCRIPTS))
    for fn, desc in manifest.SKILL_SCRIPTS:
        p = os.path.join(here, fn)
        if os.path.exists(p):
            print('  OK   %-22s %s' % (fn, desc))
        else:
            print('  CRIT %-22s 缺失！' % fn)
            miss_crit.append(fn)

    # ---------- 5. 冒烟 ----------
    bad = smoke(here)
    for fn, why in bad:
        miss_crit.append('%s 冒烟失败: %s' % (fn, why))

    # ---------- 汇总 ----------
    print('\n' + '=' * 68)
    if miss_crit:
        print('!! 缺关键项 %d 个：' % len(miss_crit))
        for x in miss_crit:
            print('   -', x)
        print('\n修复: python %s --critical' % os.path.join(here, 'install.py'))
        print('  或: python -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple <库名>')
        print('=' * 68)
        return 1
    print('关键项全部就位。')
    if miss_opt:
        print('可选缺失 %d 个（不影响主线）：%s' % (len(miss_opt), ', '.join(miss_opt[:8])))
    print('=' * 68)
    return 0


if __name__ == '__main__':
    sys.exit(main())