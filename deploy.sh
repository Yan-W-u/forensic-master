#!/usr/bin/env bash
# deploy.sh —— forensic-master 一键部署（Linux / macOS）
#
# 用法:
#   ./deploy.sh             交互式安装
#   ./deploy.sh --check     只检查
#   ./deploy.sh --all       装全部
#   ./deploy.sh --critical  只装关键项
#   ./deploy.sh --skill-only  只部署技能本体

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_PY="$SCRIPT_DIR/scripts/install.py"
SKILL_ONLY=0
PY_ARGS=()

for a in "$@"; do
  case "$a" in
    --check)      PY_ARGS+=("--check") ;;
    --all)        PY_ARGS+=("--all") ;;
    --critical)   PY_ARGS+=("--critical") ;;
    --skill-only) SKILL_ONLY=1 ;;
    *)            PY_ARGS+=("$a") ;;
  esac
done

head() {
  echo
  echo "===================================================================="
  echo "$1"
  echo "===================================================================="
}

head "forensic-master 部署脚本 (Linux/macOS)"

# ---------- 1. Python ----------
PY=""
for c in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python; do
  if command -v "$c" >/dev/null 2>&1; then
    ver=$("$c" -c 'import sys;print(sys.version_info[1])' 2>/dev/null || echo 0)
    if [ "$ver" -ge 9 ] 2>/dev/null; then PY="$c"; break; fi
  fi
done

if [ -z "$PY" ]; then
  echo "✗ 未找到 Python 3.9+"
  echo "  Debian/Ubuntu: sudo apt install python3 python3-pip python3-venv"
  echo "  macOS:         brew install python@3.12"
  exit 1
fi
echo "✓ Python: $($PY --version 2>&1)"

# ---------- 2. pip ----------
if ! "$PY" -m pip --version >/dev/null 2>&1; then
  echo "! pip 不可用，尝试 ensurepip..."
  "$PY" -m ensurepip --upgrade 2>/dev/null || {
    echo "✗ pip 装不上，请手动装 python3-pip"; exit 1; }
fi
echo "✓ pip 就绪"

# ---------- 3. 系统包（Debian 系）----------
head "检查系统依赖"
if command -v apt-get >/dev/null 2>&1; then
  MISSING=""
  for pkg in libewf-dev libtsk-dev tshark 7zip; do
    dpkg -s "$pkg" >/dev/null 2>&1 || MISSING="$MISSING $pkg"
  done
  if [ -n "$MISSING" ]; then
    echo "缺少系统包:$MISSING"
    echo "  建议: sudo apt install$MISSING"
    echo "  （pyewf/pytsk3 若 pip 装失败，需先装上面两个 -dev 包）"
  else
    echo "✓ 系统包齐全"
  fi
elif command -v brew >/dev/null 2>&1; then
  echo "✓ Homebrew 可用"
  for pkg in libewf sleuthkit wireshark; do
    brew list "$pkg" >/dev/null 2>&1 || echo "  建议: brew install $pkg"
  done
else
  echo "· 未检测到 apt/brew，跳过系统包检查"
fi

# ---------- 4. 部署技能本体 ----------
if [ "$SKILL_ONLY" -eq 0 ]; then
  head "步骤 1/2 部署技能本体"
  DST="${DSH_SKILLS_DIR:-$HOME/.dsh/skills}/forensic-master"
  SRC_ABS="$(cd "$SCRIPT_DIR" && pwd)"
  if [ "$SRC_ABS" = "$DST" ]; then
    echo "✓ 已在目标位置: $DST"
  else
    if [ -d "$DST" ]; then
      BAK="$DST.bak-$(date +%Y%m%d%H%M)"
      mv "$DST" "$BAK"
      echo "  旧版本备份: $BAK"
    fi
    mkdir -p "$(dirname "$DST")"
    rsync -a --exclude=".git" --exclude="__pycache__" --exclude="_dl" --exclude="out" "$SRC_ABS/" "$DST/" 2>/dev/null || cp -r "$SRC_ABS" "$DST"
    echo "✓ 已部署到: $DST"
  fi
  INSTALL_PY="$DST/scripts/install.py"
fi

# ---------- 5. 安装依赖 ----------
if [ "$SKILL_ONLY" -eq 0 ]; then
  head "步骤 2/2 安装依赖"
  "$PY" "$INSTALL_PY" "${PY_ARGS[@]:-}"
fi

# ---------- 6. 提示 ----------
head "完成"
echo "下一步:"
echo "  1. 重启 DSH（重新扫描 skills 目录）"
echo "  2. 新会话里说「用 forensic-master 开工」"
echo "  3. 随时自检: python3 \"$INSTALL_PY\" --check"
echo
echo "可选：环境变量覆盖默认路径"
echo "  export FORENSIC_TOOLS=\"\$HOME/forensic-tools\""
echo "  export CASE_DIR=\"\$HOME/case\""
echo "  export TSHARK=/usr/bin/tshark"
