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
    [string]$PkgProfile = "core"
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
        # ---- 先复制到临时目录，成功后再替换（失败可回滚） ----
        $stage = "$dstAbs.staging-" + (Get-Date -Format 'yyyyMMddHHmmss')
        New-Item -ItemType Directory -Force -Path $stage | Out-Null

        Write-Host "  复制到暂存区: $stage" -ForegroundColor DarkGray
        $copyOk = $true
        $robocopy = Get-Command 'robocopy' -ErrorAction SilentlyContinue
        if ($robocopy) {
            & robocopy $srcAbs $stage /E /NFL /NDL /NJH /NJS /NP `
                /XD '.git' '__pycache__' '_dl' 'out' /XF '*.pyc' | Out-Null
            # robocopy: 0-7 成功，>=8 失败
            if ($LASTEXITCODE -ge 8) {
                Write-Host "✗ robocopy 失败 (exit $LASTEXITCODE)" -ForegroundColor Red
                $copyOk = $false
            }
        } else {
            try {
                Copy-Item -Path (Join-Path $srcAbs '*') -Destination $stage -Recurse -Force
            } catch {
                Write-Host "✗ 复制失败: $_" -ForegroundColor Red
                $copyOk = $false
            }
        }

        if (-not $copyOk) {
            Write-Host "  清理暂存区，原目录未动" -ForegroundColor Yellow
            Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "✗ 部署失败，旧版本保持原样" -ForegroundColor Red
            exit 1
        }

        # ---- 校验暂存区完整性 ----
        if (-not (Test-Path (Join-Path $stage 'SKILL.md'))) {
            Write-Host "✗ 暂存区缺 SKILL.md，放弃替换" -ForegroundColor Red
            Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
            exit 1
        }

        # ---- 原子替换（失败自动回滚） ----
        $bak = $null
        if (Test-Path $dstAbs) {
            $bak = "$dstAbs.bak-" + (Get-Date -Format 'yyyyMMddHHmm')
            try {
                Move-Item $dstAbs $bak -ErrorAction Stop
                Write-Host "  旧版本移入: $bak" -ForegroundColor DarkGray
            } catch {
                Write-Host "✗ 备份旧版本失败: $_" -ForegroundColor Red
                Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
                exit 1
            }
        }

        try {
            Move-Item $stage $dstAbs -ErrorAction Stop
            Write-Host "✓ 已部署到: $dstAbs" -ForegroundColor Green
        } catch {
            Write-Host "✗ 替换失败: $_" -ForegroundColor Red
            # 回滚
            if ($bak -and (Test-Path $bak) -and -not (Test-Path $dstAbs)) {
                Move-Item $bak $dstAbs -ErrorAction SilentlyContinue
                Write-Host "  已回滚到旧版本" -ForegroundColor Yellow
            }
            Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
            exit 1
        }
    }
    $InstallPy = Join-Path $dstAbs 'scripts\install.py'
}

# ---------- 4. 安装依赖 ----------
if (-not $SkillOnly) {
    Write-Head "步骤 2/2 安装依赖"
    $pyArgs = @()
    if ($Check)    { $pyArgs += '--check' }
    if ($All)      { $pyArgs += '--all' }   # install.py 内部会检查是否与 -Profile 冲突
    if ($Critical) { $pyArgs += '--critical' }
    $pyArgs += @('--profile', $PkgProfile, '--yes')
    & $py $InstallPy @pyArgs
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
