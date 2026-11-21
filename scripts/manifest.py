#!/usr/bin/env python3
"""manifest.py —— forensic-master 依赖清单（安装器与自检的唯一数据源）

被 install.py（安装）和 toolcheck.py（自检）共同引用。
新增依赖只改这里，两处同时生效。

字段说明：
  name      显示名
  import_   Python import 名（库）或 None（CLI 工具）
  pip       pip 包名（库）
  critical  True = 缺了主线跑不通
  desc      用途
  url       二进制工具下载地址
  dest      解压/落盘位置（相对 FORENSIC_TOOLS）
  check     自检用的可执行文件名
"""

import os

# ============================================================
# 一、Python 库
# ============================================================
PY_LIBS = [
    # --- 磁盘 / 文件系统 ---
    dict(import_='pyewf',      pip='libewf-python', critical=True,
         desc='E01/Ex01 镜像读取'),
    dict(import_='pytsk3',     pip='pytsk3',        critical=True,
         desc='文件系统解析（NTFS/ext4/APFS）'),
    dict(import_='dissect.target', pip='dissect.target', critical=False,
         desc='多格式镜像统一访问'),
    dict(import_='dissect.regf', pip='dissect.regf', critical=False,
         desc='注册表（容错解析，能读损坏 hive）'),
    dict(import_='dissect.eventlog', pip='dissect.eventlog', critical=False,
         desc='事件日志（跨平台）'),

    # --- 注册表 / Windows ---
    dict(import_='regipy',     pip='regipy',        critical=True,
         desc='注册表批量查询'),
    dict(import_='pefile',     pip='pefile',        critical=True,
         desc='PE 结构解析'),
    dict(import_='oletools',   pip='oletools',      critical=False,
         desc='Office 宏提取'),

    # --- 内存 ---
    dict(import_='volatility3', pip='volatility3',  critical=False,
         desc='内存取证'),

    # --- 加密 / 哈希 ---
    dict(import_='Crypto',     pip='pycryptodome',  critical=True,
         desc='加解密（含 MD4/NTLM）'),
    dict(import_='cryptography', pip='cryptography', critical=True,
         desc='现代加密（HKDF/AESGCM/Ed25519）'),
    dict(import_='nacl',       pip='pynacl',        critical=False,
         desc='X25519 / Salsa20（车联网密钥链）'),

    # --- 图像 / OCR ---
    dict(import_='PIL',        pip='Pillow',        critical=True,
         desc='图像处理'),
    dict(import_='rapidocr_onnxruntime', pip='rapidocr_onnxruntime', critical=True,
         desc='中文 OCR（面单/截图，无需语言包）'),
    dict(import_='exifread',   pip='exifread',      critical=False,
         desc='EXIF 元数据'),

    # --- 二进制 / 逆向 ---
    dict(import_='capstone',   pip='capstone',      critical=False,
         desc='反汇编'),
    dict(import_='elftools',   pip='pyelftools',    critical=False,
         desc='ELF 深解析'),
    dict(import_='lief',       pip='lief',          critical=False,
         desc='ELF/PE/Mach-O 统一解析'),
    dict(import_='unicorn',    pip='unicorn',       critical=False,
         desc='固件模拟执行'),
    dict(import_='pwn',        pip='pwntools',      critical=False,
         desc='漏洞利用/ROP'),
    dict(import_='yara',       pip='yara-python',   critical=False,
         desc='YARA 规则扫描'),

    # --- 网络 / 流量 ---
    dict(import_='scapy',      pip='scapy',         critical=True,
         desc='报文构造与解析'),
    dict(import_='dpkt',       pip='dpkt',          critical=False,
         desc='轻量 pcap 解析'),
    dict(import_='pyshark',    pip='pyshark',       critical=False,
         desc='tshark 的 Python 封装'),
    dict(import_='requests',   pip='requests',      critical=False,
         desc='HTTP 请求'),

    # --- 车联网 ---
    dict(import_='can',        pip='python-can',    critical=True,
         desc='CAN：读 asc/blf/mf4/trc/candump'),
    dict(import_='cantools',   pip='cantools',      critical=True,
         desc='DBC/ARXML/KCD/SYM 解码物理值'),
    dict(import_='canmatrix',  pip='canmatrix',     critical=True,
         desc='CAN 描述格式互转'),
    dict(import_='asammdf',    pip='asammdf',       critical=False,
         desc='MDF4 (.mf4/.mdf) 读写'),
    dict(import_='udsoncan',   pip='udsoncan',      critical=True,
         desc='UDS 服务/NRC 定义'),
    dict(import_='serial',     pip='pyserial',      critical=False,
         desc='串口'),
    dict(import_='obd',        pip='obd',           critical=False,
         desc='ELM327 OBD-II'),

    # --- 手机 ---
    dict(import_='androguard', pip='androguard',    critical=False,
         desc='APK 静态分析'),
    dict(import_='frida',      pip='frida-tools',   critical=False,
         desc='动态插桩'),

    # --- 数据 ---
    dict(import_='pandas',     pip='pandas',        critical=False,
         desc='表格处理/批量统计'),
    dict(import_='openpyxl',   pip='openpyxl',      critical=False,
         desc='Excel 读写'),

    # --- 文档 ---
    dict(import_='docx',       pip='python-docx',   critical=False,
         desc='题目 docx 解析'),
    dict(import_='binwalk',    pip='binwalk',       critical=False,
         desc='固件解包'),
]

# ============================================================
# 二、二进制工具（Windows）
# ============================================================
_BIN = [
    # --- 必装：网络 ---
    dict(name='Wireshark (tshark)', critical=True, desc='流量分析核心',
         url='https://2.na.dl.wireshark.org/win64/Wireshark-4.4.2-x64.exe',
         winget='WiresharkFoundation.Wireshark',
         check=[r'C:\Program Files\Wireshark\tshark.exe'],
         alt='choco install wireshark -y'),

    dict(name='7-Zip', critical=True, desc='解压（zip/7z/rar）',
         url='https://www.7-zip.org/a/7z2408-x64.exe',
         winget='7zip.7zip',
         check=[r'C:\Program Files\7-Zip\7z.exe'],
         alt='choco install 7zip -y'),

    # --- 必装：加密容器 ---
    dict(name='VeraCrypt', critical=True, desc='加密容器挂载（只挂载不解密）',
         url='https://launchpad.net/veracrypt/trunk/1.26.20/+download/VeraCrypt%20Setup%201.26.20.exe',
         winget='IDRIX.VeraCrypt',
         check=[r'VeraCrypt.exe',
                r'C:\Program Files\VeraCrypt\VeraCrypt.exe',
                r'C:\Program Files (x86)\VeraCrypt\VeraCrypt.exe'],
         alt='choco install veracrypt -y'),

    # --- 必装：哈希破解 ---
    dict(name='hashcat', critical=True, desc='哈希破解（NTLM/WPA/文档）',
         url='https://hashcat.net/files/hashcat-6.2.6.7z',
         winget='',
         dest='hashcat',
         check=[r'Toolset\FileDecryptTool\hashcat.exe',
                r'hashcat\hashcat.exe'],
         alt='从 hashcat.net 下载 7z，解压到 FORENSIC_TOOLS\\hashcat'),

    # --- 必装：二进制判壳 ---
    dict(name='Detect It Easy', critical=True, desc='判壳/打包器（PyInstaller/UPX/Go/Rust）',
         url='https://github.com/horsicq/DIE-engine/releases/download/4.0.0/die_win64_4.0.0.zip',
         dest='DetectItEasy',
         check=[r'DetectItEasy\diec.exe', r'DetectItEasy\die.exe'],
         alt='gh release download -R horsicq/DIE-engine -p "die_win64_*.zip"'),

    # --- 推荐：EzTools 全家桶 ---
    dict(name='EzTools (MFTECmd/PECmd/LECmd/...)', critical=True,
         desc='Windows 痕迹解析全家桶',
         url='https://download.ericzimmermanstools.com/net9/EvtxECmd.zip',
         dest='eztools',
         check=[r'eztools\MFTECmd\MFTECmd.exe',
                r'eztools\PECmd\PECmd.exe',
                r'eztools\EvtxECmd\EvtxeCmd\EvtxECmd.exe',
                r'eztools\LECmd\LECmd.exe'],
         extra=[
             ('EvtxECmd', 'https://download.ericzimmermanstools.com/net9/EvtxECmd.zip'),
             ('MFTECmd', 'https://download.ericzimmermanstools.com/net9/MFTECmd.zip'),
             ('PECmd', 'https://download.ericzimmermanstools.com/net9/PECmd.zip'),
             ('LECmd', 'https://download.ericzimmermanstools.com/net9/LECmd.zip'),
             ('JLECmd', 'https://download.ericzimmermanstools.com/net9/JLECmd.zip'),
             ('RBCmd', 'https://download.ericzimmermanstools.com/net9/RBCmd.zip'),
             ('AmcacheParser', 'https://download.ericzimmermanstools.com/net9/AmcacheParser.zip'),
             ('SrumECmd', 'https://download.ericzimmermanstools.com/net9/SrumECmd.zip'),
             ('SBECmd', 'https://download.ericzimmermanstools.com/net9/SBECmd.zip'),
             ('RECmd', 'https://download.ericzimmermanstools.com/net9/RECmd.zip'),
             ('bstrings', 'https://download.ericzimmermanstools.com/net9/bstrings.zip'),
             ('MFTECmd', 'https://download.ericzimmermanstools.com/net9/MFTECmd.zip'),
         ],
         alt='从 ericzimmermanstools.com 逐个下载'),

    # --- 推荐：APK 反编译 ---
    dict(name='jadx', critical=False, desc='APK 反编译 GUI',
         url='https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-gui-1.5.1-with-jre-win.zip',
         dest='jadx',
         check=[r'jadx\jadx-gui-1.5.6.exe',
                r'jadx\bin\jadx-gui.bat',
                r'jadx\jadx-gui-1.5.1.exe'],
         alt='gh release download -R skylot/jadx'),

    # --- 推荐：内存 ---
    dict(name='Volatility 3', critical=False, desc='内存取证',
         url='',
         pip_note='volatility3 已通过 pip 安装，命令行 `vol` 即可',
         check=[],
         alt='pip install volatility3'),

    # --- 可选：CAN GUI ---
    dict(name='SavvyCAN', critical=False, desc='CAN 总线 GUI 分析',
         url='https://github.com/collin80/SavvyCAN/releases/download/v220/SavvyCAN-Windows_x64_CIBuild.zip',
         dest='carlink/SavvyCAN',
         check=[r'carlink\SavvyCAN\SavvyCAN-Windows_x64\SavvyCAN.exe',
                r'carlink\SavvyCAN\SavvyCAN.exe'],
         alt='gh release download -R collin80/SavvyCAN'),

    # --- 可选：遗漏补充 ---
    dict(name='FTK Imager', critical=False, desc='镜像挂载/制作',
         url='https://d1kpmuwb7gvu1i.cloudfront.net/AFTKImager.exe',
         winget='',
         check=[r'C:\Program Files\AccessData\FTK Imager\FTK Imager.exe'],
         alt='从 exterro.com 下载（需注册）'),

    dict(name='Tesseract OCR', critical=False, desc='OCR 备选（RapidOCR 已够用）',
         url='https://digi.bib.uni-mannheim.de/tesseract/tesseract-ocr-w64-setup-5.4.0.20240606.exe',
         winget='UB-Mannheim.TesseractOCR',
         check=[r'C:\Program Files\Tesseract-OCR\tesseract.exe'],
         alt='choco install tesseract -y'),
]

# ============================================================
# 三、Python 命令入口（pip 装的带 exe 的包）
# ============================================================
PY_CLI = [
    dict(name='caringcaribou', pip='caringcaribou', critical=False,
         desc='UDS 安全访问/模糊测试'),
    dict(name='binwalk', pip='binwalk', critical=False,
         desc='固件熵分析/签名扫描'),
]

# ============================================================
# 四、本技能自带的工具（无需安装）
# ============================================================
SKILL_SCRIPTS = [
    ('winkit.py',    'Windows 取证（12 子命令）'),
    ('srvkit.py',    '服务器取证（9 子命令）'),
    ('phonekit.py',  '手机取证（7 子命令）'),
    ('netkit.py',    '流量取证（8 子命令）'),
    ('iotkit.py',    '嵌入式取证（7 子命令）'),
    ('hexins.py',    '十六进制检视（6 子命令）'),
    ('fsio.py',      '安全读取层（日志尾部/删除标记/时间戳）'),
    ('ev.py',        '证据访问层（E01/raw → pytsk3 FS）'),
    ('forensic.py',  '证据访问层'),
    ('registry.py',  '注册表高频查询'),
    ('sqlite_tools.py', 'SQLite/WAL/LNK'),
    ('toolcheck.py', '工具链自检'),
    ('setup.py',     '环境自检 + docx 解析'),
]


# ============================================================
# 五、安装档次（profile）
# ============================================================
# 只为读手册的人不该装 3GB 工具。
# docs 档 = 0 依赖，纯文本可读。

PROFILES = {
    'docs': {
        'desc': '只读手册，不装任何依赖（12 份 md 直接可读）',
        'py': [],
        'bin': [],
    },
    'lite': {
        'desc': '轻量：磁盘镜像 + 文件系统 + 流量（约 300 MB）',
        'py': ['pyewf', 'pytsk3', 'regipy', 'pycryptodome', 'cryptography',
               'Pillow', 'pefile', 'scapy', 'dissect.target'],
        'bin': ['Wireshark (tshark)', '7-Zip'],
    },
    'core': {
        'desc': '常用全量：再加 Windows 痕迹 + OCR + 哈希破解（约 800 MB）',
        'py': ['pyewf', 'pytsk3', 'regipy', 'pycryptodome', 'cryptography',
               'Pillow', 'pefile', 'scapy', 'dissect.target', 'dissect.regf',
               'dissect.eventlog', 'rapidocr_onnxruntime', 'oletools',
               'capstone', 'pyelftools', 'dpkt', 'pandas', 'openpyxl',
               'python-docx', 'exifread'],
        'bin': ['Wireshark (tshark)', '7-Zip', 'VeraCrypt', 'hashcat',
                'Detect It Easy', 'EzTools (MFTECmd/PECmd/LECmd/...)'],
    },
    'automotive': {
        'desc': 'core + 车联网（CAN/UDS/DBC/GPS）',
        'py': 'CORE_PLUS',
        'extra_py': ['python-can', 'cantools', 'canmatrix', 'asammdf',
                     'udsoncan', 'pyserial', 'obd', 'pynacl'],
        'bin': 'CORE_BIN_PLUS',
        'extra_bin': ['SavvyCAN'],
    },
    'full': {
        'desc': '全部（含内存/逆向/手机/APK，约 3 GB）',
        'py': 'ALL',
        'bin': 'ALL',
    },
}


def profile_items(name):
    """返回 (py_libs, bin_tools) 两个 manifest 条目的列表"""
    if name not in PROFILES:
        raise KeyError('未知档次: %s' % name)
    p = PROFILES[name]

    # --- Python ---
    if p['py'] == 'ALL':
        py = list(PY_LIBS)
    elif p['py'] == 'CORE_PLUS':
        core = PROFILES['core']['py']
        names = set(core) | set(p.get('extra_py', []))
        py = [x for x in PY_LIBS if x['pip'] in names]
    else:
        names = set(p['py']) | set(p.get('extra_py', []))
        py = [x for x in PY_LIBS if x['pip'] in names]

    # --- 二进制 ---
    if p['bin'] == 'ALL':
        bn = list(_BIN)
    elif p['bin'] == 'CORE_BIN_PLUS':
        core = PROFILES['core']['bin']
        names = set(core) | set(p.get('extra_bin', []))
        bn = [x for x in _BIN if x['name'] in names]
    else:
        names = set(p['bin']) | set(p.get('extra_bin', []))
        bn = [x for x in _BIN if x['name'] in names]

    return py, bn


def tools():
    return _BIN


def summary():
    crit_py = [x for x in PY_LIBS if x['critical']]
    opt_py = [x for x in PY_LIBS if not x['critical']]
    crit_bin = [x for x in _BIN if x['critical']]
    opt_bin = [x for x in _BIN if not x['critical']]
    return dict(py_total=len(PY_LIBS), py_crit=len(crit_py), py_opt=len(opt_py),
                bin_total=len(_BIN), bin_crit=len(crit_bin), bin_opt=len(opt_bin),
                cli=len(PY_CLI), scripts=len(SKILL_SCRIPTS))


if __name__ == '__main__':
    s = summary()
    print('forensic-master 依赖清单')
    print('=' * 50)
    print('Python 库 : %d 个（关键 %d / 可选 %d）' % (s['py_total'], s['py_crit'], s['py_opt']))
    print('二进制工具: %d 个（关键 %d / 可选 %d）' % (s['bin_total'], s['bin_crit'], s['bin_opt']))
    print('Python CLI: %d 个' % s['cli'])
    print('技能脚本  : %d 个' % s['scripts'])
    print()
    print('关键 Python 库:')
    for x in PY_LIBS:
        if x['critical']:
            print('  %-24s %s' % (x['import_'], x['desc']))
    print()
    print('关键二进制工具:')
    for x in _BIN:
        if x['critical']:
            print('  %-34s %s' % (x['name'], x['desc']))
