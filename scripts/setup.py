"""forensic-master 环境自检 + 题目清单解析。

用法：
    python setup.py            # 检查依赖与工具
    python setup.py docx <题目.docx>   # 提取题目清单到 txt
"""
from __future__ import annotations

import importlib
import os
import shutil
import subprocess
import sys

DEPS = [
    ("pyewf", "E01 读取"),
    ("pytsk3", "文件系统解析"),
    ("regipy", "注册表"),
    ("dissect.regf", "注册表（备选）"),
    ("dissect.eventlog", "事件日志"),
    ("dissect.ntfs", "NTFS"),
    ("Cryptodome.Hash.MD4", "NTLM 哈希"),
    ("volatility3", "内存取证"),
    ("oletools", "Office 文档"),
    ("exifread", "EXIF"),
    ("hachoir", "多媒体元数据"),
    ("pefile", "PE 分析"),
    ("yara", "规则扫描"),
    ("docx", "题目 docx 读取"),
]

EXTERNALS = [
    ("tshark", r"C:\Program Files\Wireshark\tshark.exe", "流量分析"),
    ("tesseract", r"C:\Program Files\Tesseract-OCR\tesseract.exe", "OCR"),
    ("ffmpeg", "ffmpeg", "视频帧提取"),
    ("7z", r"C:\Program Files\7-Zip\7z.exe", "解压"),
]

EZTOOLS = [
    "MFTECmd", "PECmd", "LECmd", "JLECmd", "RBCmd",
    "EvtxeCmd", "RECmd", "SrumECmd", "AmcacheParser", "SQLECmd",
]


def check_python():
    print("═══ Python 依赖 ═══")
    ok = fail = 0
    for mod, desc in DEPS:
        try:
            importlib.import_module(mod)
            print(f"  [OK]   {mod:22s} {desc}")
            ok += 1
        except Exception as e:
            print(f"  [MISS] {mod:22s} {desc}  ({type(e).__name__})")
            fail += 1
    return ok, fail


def check_externals():
    print("\n═══ 外部工具 ═══")
    for name, path, desc in EXTERNALS:
        found = None
        if os.path.exists(path):
            found = path
        else:
            found = shutil.which(path)
        if found:
            print(f"  [OK]   {name:12s} {desc:12s} {found}")
        else:
            print(f"  [MISS] {name:12s} {desc:12s} 未找到")


def check_eztools():
    print("\n═══ EzTools ═══")
    roots = [r"D:\ForensicTools\eztools", r"D:\food", r"C:\ForensicTools"]
    base = None
    for r in roots:
        if os.path.isdir(r):
            base = r
            break
    if not base:
        print("  [MISS] EzTools 目录未找到，检查 D:\\ForensicTools\\eztools")
        return
    print(f"  根目录: {base}")
    for t in EZTOOLS:
        hit = None
        for dirpath, _, files in os.walk(base):
            for f in files:
                if f.lower() == f"{t.lower()}.exe":
                    hit = os.path.join(dirpath, f)
                    break
            if hit:
                break
        if hit:
            print(f"  [OK]   {t:16s} {hit}")
        else:
            print(f"  [MISS] {t:16s}")


def check_volatility():
    print("\n═══ Volatility ═══")
    try:
        r = subprocess.run(["vol", "--help"], capture_output=True, text=True, timeout=30)
        first = (r.stdout or r.stderr).splitlines()[0] if (r.stdout or r.stderr) else ""
        print(f"  [OK]   vol  {first[:80]}")
    except Exception as e:
        try:
            r = subprocess.run([sys.executable, "-m", "volatility3", "--help"],
                               capture_output=True, text=True, timeout=30)
            print(f"  [OK]   python -m volatility3")
        except Exception:
            print(f"  [MISS] volatility  ({type(e).__name__})")


def extract_docx(path: str):
    """从 docx 提取题目正文。"""
    try:
        import docx
    except ImportError:
        print("需要 python-docx: pip install python-docx")
        return
    d = docx.Document(path)
    lines = []
    for p in d.paragraphs:
        t = p.text.strip()
        if t:
            lines.append(t)
    for tb in d.tables:
        for row in tb.rows:
            cells = [c.text.strip() for c in row.cells]
            if any(cells):
                lines.append(" | ".join(cells))
    out = os.path.splitext(path)[0] + ".txt"
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"提取 {len(lines)} 行 -> {out}")

    # 统计题号
    import re
    qs = re.findall(r"^\s*(\d+)[.、]\s", "\n".join(lines), re.M)
    if qs:
        nums = sorted({int(x) for x in qs})
        print(f"识别到题号 {len(nums)} 个，范围 {nums[0]}–{nums[-1]}")
        missing = [i for i in range(nums[0], nums[-1] + 1) if i not in nums]
        if missing:
            print(f"缺号: {missing}")


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "docx":
        extract_docx(sys.argv[2])
        sys.exit(0)

    print("=" * 60)
    print("forensic-master 环境自检")
    print("=" * 60)
    ok, fail = check_python()
    check_externals()
    check_eztools()
    check_volatility()
    print("\n" + "=" * 60)
    print(f"Python 依赖: {ok} 个可用, {fail} 个缺失")
    if fail:
        print("缺失的用 pip install 补齐，或跳过相关题型")
