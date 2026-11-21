#!/usr/bin/env python3
"""phonekit.py —— 手机取证工具集（MIUI .bak 优先，兼容 Android/iOS）

用法:
  python phonekit.py survey  <备份目录>           普查：每个 .bak 的库明文/加密统计
  python phonekit.py list    <bak文件>            列出内部文件（按关键词过滤）
  python phonekit.py extract <bak文件> <路径关键词> 提取指定文件到 out/
  python phonekit.py db      <db文件>             表结构 + 行数
  python phonekit.py sp      <bak文件>            列出全部 SharedPreferences 并提关键值
  python phonekit.py chat    <db文件>             通用聊天库解析（自动认表名）
  python phonekit.py events  <db文件>             埋点事件表解析
"""
import sys
import os
import re
import glob
import json
import sqlite3
import tarfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.environ.get('CASE_DIR', '.'))

OUTROOT = r'<WORK>\phone_out'


def find_ab_start(path):
    head = open(path, 'rb').read(1 << 16)
    i = head.find(b'ANDROID BACKUP\n')
    if i < 0:
        return None, None
    pos = i
    lines = []
    for _ in range(4):
        j = head.find(b'\n', pos)
        if j < 0:
            return None, None
        lines.append(head[pos:j])
        pos = j + 1
    meta = dict(version=lines[1].decode(), compress=lines[2].decode(),
                encrypt=lines[3].decode(), tar_start=pos)
    return pos, meta


def open_tar(path):
    st, meta = find_ab_start(path)
    if st is None:
        return None, None
    f = open(path, 'rb')
    f.seek(st)
    return tarfile.open(fileobj=f, mode='r|'), f


def cmd_survey(folder):
    print('=' * 78)
    print('明文库普查 —— %s' % folder)
    print('=' * 78)
    files = sorted(glob.glob(os.path.join(folder, '*.bak')),
                   key=lambda p: -os.path.getsize(p))
    print('共 %d 个 .bak\n' % len(files))
    print('%-46s %8s %6s %6s %6s' % ('文件', 'MB', '库', '明文', '加密'))
    hot = []
    for p in files:
        tf, fh = open_tar(p)
        if tf is None:
            continue
        plain = []
        enc = 0
        try:
            for m in tf:
                if not m.isfile() or not m.name.endswith(('.db', '.sqlite')):
                    continue
                try:
                    h = tf.extractfile(m).read(16)
                except Exception:
                    continue
                if h == b'SQLite format 3\x00':
                    plain.append((m.name, m.size))
                else:
                    enc += 1
        except Exception:
            pass
        fh.close()
        if plain:
            hot.append((os.path.basename(p), plain))
        print('%-46s %8.1f %6d %6d %6d' % (
            os.path.basename(p)[:44], os.path.getsize(p) / 1e6, len(plain) + enc,
            len(plain), enc))
    print()
    print('=' * 78)
    print('明文库最多的 5 个 app（优先从这里挖）')
    print('=' * 78)
    hot.sort(key=lambda x: -len(x[1]))
    for name, plain in hot[:5]:
        print('\n%s  (%d 个明文库)' % (name, len(plain)))
        for nm, sz in sorted(plain, key=lambda x: -x[1])[:5]:
            print('   %9d  %s' % (sz, nm))


def cmd_list(bak, kw=''):
    tf, fh = open_tar(bak)
    if tf is None:
        print('不是 MIUI 备份或格式不符')
        return
    n = 0
    print('%-12s %s' % ('大小', '路径'))
    print('-' * 78)
    for m in tf:
        if not m.isfile():
            continue
        if kw and kw.lower() not in m.name.lower():
            continue
        print('%-12d %s' % (m.size, m.name))
        n += 1
        if n >= 200:
            print('... (超过 200 条停止)')
            break
    fh.close()
    print('\n共 %d 条' % n)


def cmd_extract(bak, kw):
    os.makedirs(OUTROOT, exist_ok=True)
    tf, fh = open_tar(bak)
    if tf is None:
        return
    n = 0
    for m in tf:
        if not m.isfile() or kw.lower() not in m.name.lower():
            continue
        try:
            d = tf.extractfile(m).read()
        except Exception:
            continue
        name = m.name.rsplit('/', 1)[-1] or 'file%d' % n
        p = os.path.join(OUTROOT, name)
        base, ext = os.path.splitext(p)
        k = 1
        while os.path.exists(p):
            p = '%s_%d%s' % (base, k, ext)
            k += 1
        open(p, 'wb').write(d)
        print('  %9d  %s' % (len(d), p))
        n += 1
    fh.close()
    print('\n共提取 %d 个文件到 %s' % (n, OUTROOT))


def cmd_db(path):
    print('=' * 78)
    print('数据库 —— %s' % path)
    print('=' * 78)
    head = open(path, 'rb').read(16)
    if head != b'SQLite format 3\x00':
        print('  ⚠ 非明文 SQLite（头 16B: %s）' % head.hex())
        print('  需要密钥，见 references/case2.md')
        return
    # 先复制三件套（防 WAL 被 checkpoint）
    tmp = os.path.join(OUTROOT, 'tmpdb')
    os.makedirs(tmp, exist_ok=True)
    d = os.path.join(tmp, 'x.db')
    shutil.copy(path, d)
    for suf in ('-wal', '-shm'):
        if os.path.exists(path + suf):
            shutil.copy(path + suf, d + suf)
    con = sqlite3.connect('file:%s?mode=ro&immutable=1' % d.replace('\\', '/'), uri=True)
    tabs = [r[0] for r in con.execute(
        "select name from sqlite_master where type='table' order by name")]
    print('%-34s %8s  %s' % ('表', '行数', '列'))
    for t in tabs:
        try:
            n = con.execute('select count(*) from "%s"' % t).fetchone()[0]
        except Exception:
            n = -1
        cols = [c[1] for c in con.execute('pragma table_info("%s")' % t)]
        print('%-34s %8d  %s' % (t, n, ','.join(cols[:10])))
    con.close()


def cmd_sp(bak):
    print('=' * 78)
    print('SharedPreferences')
    print('=' * 78)
    tf, fh = open_tar(bak)
    if tf is None:
        return
    KEY = re.compile(rb'name="([^"]+)"[^>]*>([^<]{0,200})')
    for m in tf:
        if not m.isfile() or '/sp/' not in m.name or not m.name.endswith('.xml'):
            continue
        try:
            d = tf.extractfile(m).read()
        except Exception:
            continue
        print('\n--- %s (%d B) ---' % (m.name, len(d)))
        for mm in KEY.finditer(d):
            k = mm.group(1).decode('utf-8', 'replace')
            v = mm.group(2).decode('utf-8', 'replace').strip()
            if not v:
                continue
            if any(x in k.lower() for x in ('key', 'token', 'user', 'uid', 'login',
                                            'phone', 'mobile', 'nick', 'auth', 'imei',
                                            'id', 'vip', 'pay', 'alipay')):
                print('   %-40s = %s' % (k[:38], v[:80]))
    fh.close()


def cmd_chat(path):
    print('=' * 78)
    print('聊天库 —— %s' % path)
    print('=' * 78)
    tmp = os.path.join(OUTROOT, 'tmpdb')
    os.makedirs(tmp, exist_ok=True)
    d = os.path.join(tmp, 'c.db')
    shutil.copy(path, d)
    con = sqlite3.connect('file:%s?mode=ro&immutable=1' % d.replace('\\', '/'), uri=True)
    tabs = [r[0] for r in con.execute(
        "select name from sqlite_master where type='table'")]
    lower = {t.lower(): t for t in tabs}

    def T(*names):
        for n in names:
            if n.lower() in lower:
                return lower[n.lower()]
        return None

    # 本人
    tu = T('CHAT_USER', 'user_info', 'users')
    if tu:
        cols = [c[1] for c in con.execute('pragma table_info("%s")' % tu)]
        want = [c for c in cols if any(k in c.upper() for k in
                                       ('NICK', 'MOBILE', 'PHONE', 'USER_ID', 'AVATAR', 'GENDER'))]
        if want:
            print('\n[本人]')
            for row in con.execute('select %s from "%s"' % (','.join(want), tu)):
                for k, v in zip(want, row):
                    if v:
                        print('   %-16s %s' % (k, str(v)[:70]))
    # 会话
    tc = T('CONVERSATION', 'conversations')
    if tc:
        cols = [c[1] for c in con.execute('pragma table_info("%s")' % tc)]
        tcol = next((c for c in cols if 'TIME' in c.upper()), None)
        ncol = next((c for c in cols if c.upper() in ('NAME', 'SESSION_NAME', 'TITLE')), None)
        if tcol and ncol:
            print('\n[会话（按时间排序）]')
            try:
                for row in con.execute(
                        'select %s,%s from "%s" order by %s' % (tcol, ncol, tc, tcol)):
                    print('   %-18s %s' % (str(row[0])[:18], str(row[1])[:50]))
            except Exception:
                pass
    # 消息
    tm = T('CHAT_MESSAGE', 'message', 'messages', 'sms')
    if tm:
        cols = [c[1] for c in con.execute('pragma table_info("%s")' % tm)]
        ccol = next((c for c in cols if c.upper() in ('CONTENT', 'BODY', 'TEXT')), None)
        tcol = next((c for c in cols if 'TIME' in c.upper()), None)
        if ccol:
            n = con.execute('select count(*) from "%s"' % tm).fetchone()[0]
            print('\n[消息] 共 %d 条，前 15 条：' % n)
            q = 'select %s from "%s"' % (
                ','.join(filter(None, [tcol, ccol])), tm)
            for row in con.execute(q):
                vals = [str(x)[:80] for x in row if x is not None]
                print('   ' + ' | '.join(vals))
    con.close()


def cmd_events(path):
    print('=' * 78)
    print('埋点事件 —— %s' % path)
    print('=' * 78)
    tmp = os.path.join(OUTROOT, 'tmpdb')
    os.makedirs(tmp, exist_ok=True)
    d = os.path.join(tmp, 'e.db')
    shutil.copy(path, d)
    con = sqlite3.connect('file:%s?mode=ro&immutable=1' % d.replace('\\', '/'), uri=True)
    tabs = [r[0] for r in con.execute(
        "select name from sqlite_master where type='table'")]
    for t in tabs:
        cols = [c[1] for c in con.execute('pragma table_info("%s")' % t)]
        if not any('TIME' in c.upper() for c in cols):
            continue
        try:
            n = con.execute('select count(*) from "%s"' % t).fetchone()[0]
        except Exception:
            continue
        if n == 0:
            continue
        print('\n[%s] %d 行  列: %s' % (t, n, ','.join(cols)))
        tcol = next(c for c in cols if 'TIME' in c.upper())
        # 事件类型分布（比全量列表有用得多）
        ecol = next((c for c in cols if c.upper() in ('EVTID', 'EVENT', 'TYPE', 'EVTTYPE')), None)
        if ecol:
            import collections
            cc = collections.Counter()
            try:
                for row in con.execute('select "%s" from "%s"' % (ecol, t)):
                    cc[str(row[0])] += 1
            except Exception:
                pass
            print('   事件类型分布:')
            for k, v in cc.most_common(15):
                print('      %-40s %d' % (k[:38], v))
        # 只显示非噪声事件
        NOISE = ('$EnterScreen', '$ExitScreen', '$AppFirstOpen', '$LaunchApp')
        print('\n   非噪声事件（前 20 条）:')
        try:
            q = 'select * from "%s" order by "%s"' % (t, tcol)
            shown = 0
            for row in con.execute(q):
                d = dict(zip(cols, row))
                ev = str(d.get(ecol) or '')
                if any(no in ev for no in NOISE):
                    continue
                vals = [str(x)[:40] for x in row if x is not None and str(x)]
                print('   ' + ' | '.join(vals[:6]))
                shown += 1
                if shown >= 20:
                    break
            if shown == 0:
                print('   （全是屏幕进出事件，无其他类型）')
        except Exception as e:
            print('   ERR', str(e)[:50])
    con.close()


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return
    c, a = sys.argv[1], sys.argv[2]
    b = sys.argv[3] if len(sys.argv) > 3 else ''
    m = {'survey': cmd_survey, 'list': lambda x: cmd_list(x, b),
         'extract': lambda x: cmd_extract(x, b), 'db': cmd_db,
         'sp': cmd_sp, 'chat': cmd_chat, 'events': cmd_events}
    if c in m:
        m[c](a)
    else:
        print(__doc__)


if __name__ == '__main__':
    main()
