import os
"""车联网取证工具链一键自检 —— 放进技能 scripts/，开工前跑一次"""
import os
import shutil
import subprocess
import sys

PY_LIBS = [
    # (import 名, 用途, 是否关键)
    ('can', 'python-can：读 asc/blf/mf4/trc/log', True),
    ('cantools', 'DBC/ARXML/KCD/SYM 解码物理值', True),
    ('canmatrix', 'CAN 描述格式互转', True),
    ('asammdf', 'MDF4 (.mf4/.mdf) 读写', False),
    ('udsoncan', 'UDS 服务/NRC 定义', True),
    ('serial', 'pyserial 串口', False),
    ('obd', 'ELM327 OBD-II', False),
    ('scapy', 'scapy.layers.can / CANSocket', True),
    ('dpkt', '轻量 pcap', False),
    ('pyshark', 'tshark 封装', False),
    ('lief', 'ELF/PE/Mach-O 解析', False),
    ('elftools', 'ELF 深解析', False),
    ('unicorn', '固件模拟执行', False),
    ('pwn', 'pwntools', False),
    ('capstone', '反汇编', False),
    # 通用取证
    ('pyewf', 'E01', True),
    ('pytsk3', '文件系统', True),
    ('dissect.target', '多格式镜像', False),
    ('regipy', '注册表', True),
    ('volatility3', '内存', False),
    ('rapidocr_onnxruntime', '中文 OCR', True),
    ('Crypto', 'pycryptodome', True),
    ('cryptography', '加密', True),
    ('PIL', 'Pillow', True),
    ('yara', 'YARA', False),
    ('pefile', 'PE 解析', True),
    ('androguard', 'APK', False),
    ('frida', '动态插桩', False),
    ('pandas', '表格处理', False),
]

# 工具路径可用环境变量覆盖：FORENSIC_TOOLS / WIRESHARK_DIR / BINUTILS_DIR
FT = os.environ.get('FORENSIC_TOOLS', r'D:\ForensicTools')
WS = os.environ.get('WIRESHARK_DIR', r'C:\Program Files\Wireshark')
BU = os.environ.get('BINUTILS_DIR', r'E:\bianyiqi\mingw64\bin')
GO = os.environ.get('GO_DIR', r'C:\Program Files\Go')

TOOLS = [
    # (路径, 用途, 关键)
    (r'D:\ForensicTools\carlink\SavvyCAN\SavvyCAN-Windows_x64\SavvyCAN.exe', 'SavvyCAN CAN GUI', True),
    (r'D:\ForensicTools\VeraCrypt.exe', 'VeraCrypt 挂载', True),
    (r'D:\ForensicTools\Toolset\FileDecryptTool\hashcat.exe', 'hashcat', True),
    (r'D:\ForensicTools\DetectItEasy\diec.exe', 'DIE 命令行判壳', True),
    (r'D:\ForensicTools\DetectItEasy\die.exe', 'DIE GUI', False),
    (r'D:\ForensicTools\jadx\jadx-gui-1.5.6.exe', 'jadx APK 反编译', False),
    (os.path.join(os.environ.get('USERPROFILE', ''), '.dsh', 'skills',
                  'forensic-master', 'scripts', 'srvkit.py'), '服务器取证工具集', True),
    (os.path.join(os.environ.get('USERPROFILE', ''), '.dsh', 'skills',
                  'forensic-master', 'scripts', 'winkit.py'), 'Windows 取证工具集', True),
    (os.path.join(os.environ.get('USERPROFILE', ''), '.dsh', 'skills',
                  'forensic-master', 'scripts', 'phonekit.py'), '手机取证工具集', True),
    (os.path.join(os.environ.get('USERPROFILE', ''), '.dsh', 'skills',
                  'forensic-master', 'scripts', 'netkit.py'), '流量取证工具集', True),
    (os.path.join(os.environ.get('USERPROFILE', ''), '.dsh', 'skills',
                  'forensic-master', 'scripts', 'iotkit.py'), '嵌入式取证工具集', True),
    (os.path.join(os.environ.get('USERPROFILE', ''), '.dsh', 'skills',
                  'forensic-master', 'scripts', 'hexins.py'), '十六进制检视器', True),
    (r'D:\ForensicTools\ForensicDesktop\bin\tools\john\john.exe', 'John', False),
    (r'C:\Program Files\Wireshark\tshark.exe', 'tshark', True),
    (r'C:\Program Files\Wireshark\capinfos.exe', 'capinfos', False),
    (r'C:\Program Files\7-Zip\7z.exe', '7-Zip', True),
    (r'C:\Program Files\Tesseract-OCR\tesseract.exe', 'Tesseract', False),
    (r'C:\Program Files\AccessData\FTK Imager\FTK Imager.exe', 'FTK Imager', False),
    (r'D:\ForensicTools\Toolset\MemoryAnalysis\tools\vol.exe', 'Volatility3', True),
    (r'D:\ForensicTools\Toolset\DiskMountTool\Bin64\DiskMount.exe', 'DiskMount', False),
    (r'D:\ForensicTools\eztools\MFTECmd\MFTECmd.exe', 'MFTECmd', True),
    (r'D:\ForensicTools\eztools\PECmd\PECmd.exe', 'PECmd', True),
    (r'D:\ForensicTools\eztools\LECmd\LECmd.exe', 'LECmd', True),
    (r'D:\ForensicTools\eztools\JLECmd\JLECmd.exe', 'JLECmd', False),
    (r'D:\ForensicTools\eztools\RBCmd\RBCmd.exe', 'RBCmd', False),
    (r'D:\ForensicTools\eztools\EvtxECmd\EvtxeCmd\EvtxECmd.exe', 'EvtxECmd', True),
    (r'D:\ForensicTools\eztools\AmcacheParser\AmcacheParser.exe', 'AmcacheParser', False),
    (r'D:\ForensicTools\eztools\SrumECmd\SrumECmd.exe', 'SrumECmd', False),
    (r'D:\ForensicTools\eztools\SBECmd\SBECmd.exe', 'SBECmd', False),
    (r'D:\ForensicTools\eztools\RECmd\RECmd\RECmd.exe', 'RECmd', False),
    (r'D:\ForensicTools\eztools\bstrings\bstrings.exe', 'bstrings', False),
    (r'E:\bianyiqi\mingw64\bin\strings.exe', 'strings', True),
    (r'E:\bianyiqi\mingw64\bin\readelf.exe', 'readelf', True),
    (r'E:\bianyiqi\mingw64\bin\objdump.exe', 'objdump', True),
    (r'E:\bianyiqi\mingw64\bin\nm.exe', 'nm', False),
    (r'C:\Program Files\Go\bin\go.exe', 'Go 工具链', False),
    (r'D:\ForensicTools\aria2\aria2-1.37.0-win-64bit-build1\aria2c.exe', 'aria2 下载', False),
    (r'D:\ForensicTools\filerecon\everything.exe', 'Everything 搜索', False),
    (r'D:\ForensicTools\networkminer\NetworkMiner_3-2\NetworkMiner.exe', 'NetworkMiner', False),
]

PY_PKGS = [('caringcaribou', 'caringcaribou UDS 工具')]


def main():
    print('=' * 66)
    print('车联网 + 取证工具链自检')
    print('=' * 66)

    miss_crit, miss_opt = [], []

    print('\n[1] Python 库')
    import importlib
    for mod, desc, crit in PY_LIBS:
        try:
            m = importlib.import_module(mod)
            v = getattr(m, '__version__', '')
            print('  OK   %-24s %-10s %s' % (mod, v, desc))
        except Exception:
            tag = 'CRIT' if crit else 'opt '
            print('  %s %-24s %-10s %s' % (tag, mod, '-', desc))
            (miss_crit if crit else miss_opt).append(mod)

    print('\n[2] 命令行工具')
    for p, desc, crit in TOOLS:
        if os.path.exists(p):
            print('  OK   %-58s %s' % (os.path.basename(p), desc))
        else:
            tag = 'CRIT' if crit else 'opt '
            print('  %s %-58s %s' % (tag, p, desc))
            (miss_crit if crit else miss_opt).append(p)

    print('\n[3] Python 命令入口')
    for pkg, desc in PY_PKGS:
        exe = os.path.join(os.path.dirname(sys.executable), 'Scripts', pkg + '.exe')
        if os.path.exists(exe):
            print('  OK   %-58s %s' % (pkg + '.exe', desc))
        else:
            r = shutil.which(pkg)
            if r:
                print('  OK   %-58s %s' % (r, desc))
            else:
                print('  opt  %-58s %s' % (pkg, desc))
                miss_opt.append(pkg)

    print('\n' + '=' * 66)
    if miss_crit:
        print('!! 缺失关键项 %d 个：' % len(miss_crit))
        for x in miss_crit:
            print('   -', x)
        print('\n修复：python -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple <库名>')
    else:
        print('关键项全部就位。')
    if miss_opt:
        print('可选缺失 %d 个（不影响主线）：%s' % (len(miss_opt), ', '.join(miss_opt)))
    print('=' * 66)


if __name__ == '__main__':
    main()
