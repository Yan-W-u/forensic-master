#!/usr/bin/env pwsh
# deploy.ps1 —— forensic-master 一键部署（Windows）
#
# 用法:
#   .\deploy.ps1                    交互式安装
#   .\deploy.ps1 -Check             只检查
#   .\deploy.ps1 -All               装全部
#   .\deploy.ps1 -Critical          只装关键项
#   .\deploy.ps1 -SkillOnly         只部署技能本体，不装依赖
#
# 无执行权限时先跑:
#   powershell -ExecutionPolicy Bypass -File deploy.ps1

param(
    [switch]$Check,
    [switch]$All,
    [switch]$Critical,
    [switch]$SkillOnly,
    [string]$Target = "",
    [string]$Profile = "core"
)

$ErrorActionPreference = 'Continue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallPy = Join-Path $ScriptDir 'scripts\install.py'

function Write-Head($t) {
    Write-Host ""
    Write-Host ("=" * 68) -ForegroundColor Cyan
    Write-Host $t -ForegroundColor Cyan
    Write-Host ("=" * 68) -ForegroundColor Cyan
}

Write-Head "forensic-master 部署脚本 (Windows)"

# ---------- 1. 检查 Python ----------
$py = $null
foreach ($c in @('python', 'python3', 'py')) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if ($cmd) {
        $v = & $c --version 2>&1
        if ($v -match 'Python 3\.(\d+)') {
            $minor = [int]$Matches[1]
            if ($minor -ge 9) { $py = $c; break }
        }
    }
}
if (-not $py) {
    Write-Host "✗ 未找到 Python 3.9+" -ForegroundColor Red
    Write-Host "  安装: winget install Python.Python.3.12"
    Write-Host "  或:   https://www.python.org/downloads/"
    exit 1
}
Write-Host "✓ Python: $(& $py --version 2>&1)" -ForegroundColor Green

# ---------- 2. 检查 pip ----------
& $py -m pip --version *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ pip 不可用，尝试 ensurepip..." -ForegroundColor Yellow
    & $py -m ensurepip --upgrade
}
Write-Host "✓ pip 就绪" -ForegroundColor Green

# ---------- 3. 部署技能本体 ----------
if (-not $Check) {
    Write-Head "步骤 1/2 部署技能本体"
    $dst = if ($Target) { $Target } else {
        Join-Path $env:USERPROFILE '.dsh\skills\forensic-master'
    }
    $srcAbs = (Resolve-Path $ScriptDir).Path
    $dstAbs = [System.IO.Path]::GetFullPath($dst)

    if ($srcAbs -eq $dstAbs) {
        Write-Host "✓ 已在目标位置: $dstAbs" -ForegroundColor Green
    } else {
        if (Test-Path $dstAbs) {
            $bak = "$dstAbs.bak-" + (Get-Date -Format 'yyyyMMddHHmm')
            Move-Item $dstAbs $bak
            Write-Host "  旧版本备份: $bak" -ForegroundColor Yellow
        }
        New-Item -ItemType Directory -Force -Path (Split-Path $dstAbs) | Out-Null
        # 排除 .git / __pycache__ / 输出目录
        $exclude = @('.git', '__pycache__', '_dl', 'out', '*.pyc')
        $robocopy = Get-Command 'robocopy' -ErrorAction SilentlyContinue
        if ($robocopy) {
            $args = @($srcAbs, $dstAbs, '/E', '/NFL', '/NDL', '/NJH', '/NJS', '/NP',
                      '/XD', '.git', '__pycache__', '_dl', 'out',
                      '/XF', '*.pyc')
            & robocopy @args *> $null
        } else {
            Copy-Item -Path (Join-Path $srcAbs '*') -Destination $dstAbs -Recurse -Force `
                -Exclude $exclude
        }
        Write-Host "✓ 已部署到: $dstAbs" -ForegroundColor Green
    }
    $InstallPy = Join-Path $dstAbs 'scripts\install.py'
}

# ---------- 4. 安装依赖 ----------
if (-not $SkillOnly) {
    Write-Head "步骤 2/2 安装依赖"
    $args = @()
    if ($Check)    { $args += '--check' }
    if ($All)      { $args += '--all' }
    if ($Critical) { $args += '--critical' }
    $args += @('--profile', $Profile)
    & $py $InstallPy @args
}

# ---------- 5. 后续提示 ----------
Write-Head "完成"
Write-Host "下一步:" -ForegroundColor Cyan
Write-Host "  1. 重启 DSH（重新扫描 skills 目录）"
Write-Host "  2. 新会话里说「用 forensic-master 开工」"
Write-Host "  3. 随时自检: python `"$InstallPy`" --check"
Write-Host ""
Write-Host "可选：设置环境变量覆盖默认路径" -ForegroundColor Cyan
Write-Host "  setx FORENSIC_TOOLS `"D:\ForensicTools`""
Write-Host "  setx CASE_DIR `"D:\case`""
Write-Host "  setx WIRESHARK_DIR `"C:\Program Files\Wireshark`""
