---
name: forensic-master
description: |
  数字取证比赛/实战的全流程作战手册：从检材识别、证据提取到逐题作答，带脚本库和判断准则。
  适用于：取证比赛、CTF 取证题、美亚杯/盘古石/长安杯/龙信杯等赛事、电子数据取证分析、
  E01/raw/vhd 镜像分析、VeraCrypt/LUKS 加密容器、LVM、内存取证、MIUI/iOS 手机备份解析、
  pcap 流量分析、自定义二进制协议、SCTP、IoT/嵌入式固件与 eMMC、
  车联网（CAN/CAN-FD/UDS/DBC/GPS/车机镜像/T-Box）、注册表/事件日志分析、
  已删除文件恢复、时间线重建、WhatsApp/iOS 备份/浏览器数据提取。
  核心是三档分类法（A 不用密钥 / B 解一薄层 / C 密钥链），执行顺序 A→B→C。
  带 40 条失分陷阱 + 26 项开工检查表 + 6 个专用工具集。
license: MIT
metadata:
  version: "2.0.0"
  family: forensic-toolkit
  requires: python3.9+
---

# 取证大师

数字取证比赛/实战的作战手册。目标不是"跑通工具"，而是**答对题**。

本 skill 来自两场真实取证赛的完整实战复盘：
- **2026 美亚杯个人赛（128 题）**：拿下了全部高难度技术题（WAL 恢复、内存哈希、NTFS 双时间戳、Deauth 循环统计、pcap 全链路），失分集中在**时间戳归属**和**读题精度**。
- **2026 龙信杯（75 题）**：容器镜像 + 手机备份 + 两台 Linux 服务器 + 自定义协议流量 + 智能门锁固件。首轮 15 题确认 / 12 题推断 / 48 题未解，复盘出的问题**几乎全是流程问题而非技术问题**——见下面「零、五条铁律」。

## 开工第 0 步：环境自检

**任何分析开始前，先跑这两条。**

```powershell
# 1. 依赖是否齐全（38 个 Python 库 + 11 个二进制工具）
python <skill>/scripts/install.py --check

# 2. 技能自带工具是否可用
python <skill>/scripts/toolcheck.py
```

任一条报缺失，先修环境再开工。**别边分析边缺库** —— 查 PyInstaller 时发现没装 `pyinstxtractor`，
现场 pip 装 5 分钟，比开工前自检 10 秒贵 30 倍。

依赖清单与下载地址见 `scripts/manifest.py`（安装器与自检的唯一数据源）。
首次部署、换机器、或缺关键项时读 `README.md` 的「部署」章。

## 零、五条铁律（2026 龙信杯复盘，按浪费的时间排序）

这几条是拿 48 道未解题换来的。**违反任意一条，损失以小时计。**

### 铁律 1：密码先原样试，再理解它

用户给的是 `<BASE64_PASSWORD>`，肉眼一看是 Base64，解码后得到一个"看起来合理"的字符串，然后用解码值试了 15 种 KDF 组合、25 分钟全败。真实密码**就是那串 Base64 字面量本身**。

```
密码候选顺序（每个只花 1 秒，永远全试）：
1. 原样字符串（含引号内所有字符，注意全角/半角）
2. Base64 解码后的值
3. 原样 + 换行 / 去掉尾部空字节
4. 用户明确说"密码是 X" 时，X 的字节一律按 UTF-8 原样
```

**判据**：只要 `PBKDF2(...)` 解出来的前 4 字节是 `VERA`/`TRUE`（VeraCrypt）或 `LUKS`（LUKS），就是对了。错一次和错一万次成本一样，别做"合理性推断"。

### 铁律 2：加密容器只挂载，不解密

VeraCrypt / LUKS / BitLocker 拿到密码后，**立刻用一个盘符/挂载点直读**，永远不要先把整卷解密成 raw。

| 错误做法 | 代价 | 正确做法 |
|---|---|---|
| 105 GiB 卷全量 AES-XTS 解密 | 40 分钟 + 写 105 GiB | `VeraCrypt.exe /volume <img> /letter Z /password <pw> /quit /silent`，秒级 |

全量解密只在两种情况下做：容器不支持随机读（罕见），或需要给别的工具喂 raw 格式且该工具不支持 FUSE。

### 铁律 3：装任何工具前，先查本机

`D:\ForensicTools\` 里已经有 VeraCrypt 1.26.31、hashcat 7.1.2、tshark、7z、EzTools 全套（EvtxECmd/MFTECmd/PECmd/LECmd/JLECmd/RBCmd/AmcacheParser/SQLECmd/SrumECmd）、Wireshark、FTK、Autopsy。Python 侧已有 pyewf / pytsk3 / dissect / regipy / volatility3 / rapidocr / pycryptodome / oletools / pypykatz / exifread。

我先花 581 秒从 GitHub 下 VeraCrypt 安装包，装完发现本机早就有。开工前一条命令：

```powershell
foreach($p in 'D:\ForensicTools\VeraCrypt.exe','D:\ForensicTools\Toolset\FileDecryptTool\hashcat.exe',
              'C:\Program Files\Tesseract-OCR\tesseract.exe','C:\Program Files\Wireshark\tshark.exe',
              'D:\ForensicTools\eztools\PECmd\PECmd.exe'){ "{0,-70} {1}" -f $p,(Test-Path $p) }
```

### 铁律 4：一个文件可能答 6 题——先做映射，再动手

龙信杯手机部分 15 题，我先去啃微信（SQLCipher 加密）、抖音（`encrypted_*` 加密）、高德（1600 个文件），浪费 30 分钟零产出。真正的答案全在一个明文库 `sy_chat_imPROD_SY.db`（思语 app）里，一个文件答了 6 题。

**正确顺序**：

```
1. 读题，提取每题的「实体关键词」：名字、文件名、列数、编号、时间
2. 列出检材里所有候选数据源（所有 IM app 的库、所有 .db、所有配置文件）
3. 做一张 源 × 题 的矩阵，先打覆盖题数最多的源
4. 只对矩阵填不满的格子，才去深挖
```

详见 `references/quickwin.md`。

### 铁律 5：自定义协议先按题面关键词定位，再做全量统计

流量题面出现「控制会话」「nonce」「规范输入」「cumulative TSN」「I-DATA」，说明存在**特定前缀**的协议帧。我先把 11835 条 `TLM4` 记录全解一遍（导出 111594 行），结果 `TLM4` 是干扰协议；而按题面词一搜 `IN7`/`UI7`/`PMU7` 十分钟就全出来了。

```
先做：tshark 导出所有 data.data，正则提取前缀，按题面词过滤
后做：全量解析、统计、建模
```

同理，二进制格式（TLV、eMMC 元数据）**不要猜字节序**——先找同族样本对比，两个文件一对比，`大端/小端` 立刻分明。

## 一、开工前的四件事

拿到检材和题目后，**先做这四件事，再碰任何工具**。

### 0. 先给每道题分档（2026 龙信杯最大教训）

**这一步不能跳过。** 龙信杯服务器 20 题里，我全押在密钥链上，结果 14 题空白；
而那 20 题里**有 7 题根本不需要密钥**，读个配置文件就能答。

逐题看完，立刻打三档：

| 档 | 判据 | 例子 |
|---|---|---|
| **A 档：不用密钥** | 答案在明文配置/日志/二进制字符串/文件名/时间戳里 | 服务名、镜像标签、容器名、端口、版本、执行顺序、文件哈希 |
| **B 档：需解一薄层** | 要解压缩/解一层 XOR/解 TLV，但不需要密钥 | MIUI .bak、protobuf、eMMC 分区、pcap 载荷 |
| **C 档：需密钥链** | 要过 HKDF/AES/密码派生，且密钥可能不在检材里 | 加密库、密钥链派生、FDE |

**执行顺序永远是 A → B → C。**

理由：A 档单题成本 1–5 分钟、成功率 >80%；C 档单题成本 30 分钟起、还可能撞死锁。
先把 A 档清完（通常占总分 40% 以上），再决定要不要碰 C 档。

**什么时候放弃 C 档**（任一条命中就标 ⬜ 转降级目标）：

1. 密钥是 32 字节 raw 且生成它的标识（androidId 之类）不在任何检材里
2. 密钥依赖的文件在另一份被 FDE 加密的镜像里，且无恢复密钥
3. 算法源码被 `shred` 擦除，且 journal 里只剩目录项无数据块
4. 已经穷举 400+ 组合且全灭

详见 `references/case2.md`、`references/containers.md` 第八章。

### 1. 把题目按"证据源"分组，不是按题号

逐题读，给每题打一个标签：`磁盘` / `内存` / `注册表` / `事件日志` / `手机数据库` / `流量` / `文件痕迹` / `容器` / `固件` / `概念题`。

分组的好处：
- 同一证据源的题一次提取、批量回答，避免反复挂载镜像
- 能一眼看出哪些题依赖同一份数据（例：Q120 的笔数错会导致 Q121 金额也错）

**分组之后立刻做第二步：源 × 题 矩阵**（见铁律 4 与 `references/quickwin.md`），把「一个文件答多题」的格子先清掉。这一步 10 分钟，能省 2 小时。

### 2. 清点检材，判断格式与规模

| 格式 | 特征 | 处理方式 |
|---|---|---|
| `.e01/.ex01` | 头 8 字节 `45 56 46 09 0d 0a ff 00` | pyewf 直读，**不要全量提取** |
| `.raw/.dd/.img` | 无头，或 `55 aa` 在 510 | RawReader |
| `.vhd/.vhdx` | `conectix` 尾标 | 需转换，或 pyvhd 挂载 |
| `.bin` | 可能是裸文件系统（NTFS 头 `eb 52 90`） | 直接当 FS 开 |
| 内存 `*.raw/*.dmp/*.vmem` | 前 4MB 内找 `KDBG`/`PAGE` | Volatility 3 |

**注意**：E01 的 `media_size` 可能远大于文件实际大小（压缩比 7x 以上）。先读采集日志（`.e01.txt`）里的 `Capacity` 核对，别急着判断"镜像损坏"。

### 3. 建立工作目录约定

```
case/
├── out/          # 提取出的文件，永远不碰原始检材
│   ├── <检材代号>/
└── ans/
    ├── progress.md   # 逐题答案 + 证据路径（边做边写）
    └── FINAL.md      # 最终答案表
```

**规矩**：原始检材只读。所有操作输出到 `out/`。`progress.md` 每题都要带**证据路径 + 具体字段/偏移**，因为最后核对答案时，没有证据的答案等于没做。

### 4. 本机工具清单（2026-11 全量扫描，798 个 exe 择要）

**铁律**：动手前先看这张表。本机已装的东西远超想象，**绝大多数题目用现成工具就能解**。

#### 4.1 磁盘 / 镜像 / 加密

| 工具 | 完整路径 | 能力 |
|---|---|---|
| **VeraCrypt 1.26.31** | `D:\ForensicTools\VeraCrypt.exe` | 命令行挂载（驱动在运行） |
| VeraCrypt Format / Expander | 同目录 | 建卷 / 扩容 |
| **FTK Imager** | `C:\Program Files\AccessData\FTK Imager\FTK Imager.exe` | E01/raw/AFF 挂载、镜像、内存 |
| FTK Imager 安装包 | `D:\ForensicTools\ftk-imager\` | 重装用 |
| **DiskMount** | `D:\ForensicTools\Toolset\DiskMountTool\Bin64\DiskMount.exe` | 镜像挂载为盘符 |
| vmware-mount / vmware-vdiskmanager | `C:\Program Files (x86)\VMware\VMware Virtual Disk Development Kit\bin\` | VMDK 挂载 |
| vixDiskCheck / EVixMnt | `D:\ForensicTools\Emulation Support\bin\VmCtl\` | VMDK 校验 / 挂载 |
| Ghost64 / MYFS_Mounter / vold | `D:\ForensicTools\Service\bin\` | 美亚私有 FS 挂载 |
| **CrystalDiskInfo** | `C:\Program Files\CrystalDiskInfo\DiskInfo64.exe` | 磁盘/SMART 信息 |

#### 4.2 Windows 痕迹（EzTools 全家桶）

`D:\ForensicTools\eztools\`

| 工具 | 解什么 |
|---|---|
| `EvtxECmd\EvtxeCmd\EvtxECmd.exe` | 事件日志 evtx |
| `MFTECmd\MFTECmd.exe` | `$MFT` / `$J` / `$Boot` / `$SDS` |
| `PECmd\PECmd.exe` | Prefetch |
| `LECmd\LECmd.exe` | LNK 快捷方式 |
| `JLECmd\JLECmd.exe` | JumpList |
| `RBCmd\RBCmd.exe` | 回收站 `$I/$R` |
| `AmcacheParser\AmcacheParser.exe` | Amcache.hve |
| `AppCompatCacheParser\AppCompatCacheParser.exe` | ShimCache |
| `SrumECmd\SrumECmd.exe` | SRUM 网络/应用用量 |
| `SBECmd\SBECmd.exe` | ShellBags |
| `RECmd\RECmd\RECmd.exe` | 注册表批量（带 Batch 文件） |
| `RegistryExplorer\RegistryExplorer\RegistryExplorer.exe` | 注册表 GUI |
| `ShellBagsExplorer\ShellBagsExplorer\ShellBagsExplorer.exe` | ShellBags GUI |
| `SumECmd\SumECmd.exe` | SUM 数据库 |
| `RecentFileCacheParser` | RecentFileCache.bcf |
| `bstrings\bstrings.exe` | 正则提串（比 strings 强） |
| `hasher\Hasher\Hasher.exe` | 哈希 |
| `rla\rla.exe` | 批量 ACL 重置 |

#### 4.3 手机 / 移动

| 工具 | 路径 | 能力 |
|---|---|---|
| **美亚手机大师** | `D:\ForensicTools\MYOSMobileMaster\` | 全流程提取（需授权） |
| MYOS 底层 | `...\MYOSMobileSupport\Bin64\` | `apk_parser.exe` `bsdcpio.exe` `plutil.exe` `PTForensic.exe` |
| adb / hdc | `...\BaseTool\Android\` | Android/HarmonyOS 直连 |
| QPST | `...\BaseTool\Qpst\QPSTServerMod.exe` | 高通 |
| 小米传输四件套 | `...\BaseTool\Android\TransferMi*.exe` | 通话/联系人/短信/便签 |
| **雷电/逍遥模拟器支持** | `D:\ForensicTools\Emulation Support\` | Android 仿真 |
| **iApps** | `D:\ForensicTools\MYOSMobileMaster\MYOSiAppsSupport\` | iOS 应用解析（`realm2json.exe`） |
| **QIKO 手机大师** | `D:\ForensicTools\QIKOMobileMaster\` | 另一套（FileForensic.exe 等） |
| ForensicDesktop 工具组 | `D:\ForensicTools\ForensicDesktop\bin\tools\` | 7z / hashcat / **john** / fd / rg / uv |
| 语音转写 | `D:\ForensicTools\resources\voice-asr\bin\sherpa-onnx-offline.exe` | 录音转文字 |

#### 4.4 网络 / 流量

| 工具 | 路径 |
|---|---|
| Wireshark 全套（tshark/capinfos/mergecap/editcap/dumpcap/sharkd） | `C:\Program Files\Wireshark\` |
| **NetworkMiner 3.2** | `D:\ForensicTools\networkminer\NetworkMiner_3-2\NetworkMiner.exe` |
| 仿真网络（winbox64） | `D:\ForensicTools\Emulation Support\data\Tools\winbox64.exe` |

#### 4.5 数据库

| 工具 | 路径 | 用途 |
|---|---|---|
| **HeidiSQL** | `D:\ForensicTools\Toolset\HeidiSQL\heidisql.exe` | MySQL/MariaDB GUI |
| DBRebuild | `D:\ForensicTools\Toolset\DBRebuild\dbrebuild.exe` | 库重建 |
| MySQL Binlog Parser | `D:\ForensicTools\Toolset\MySQLBinlog\BinlogPro Parser.exe` | binlog 解析 |
| sqlite3 | `D:\ForensicTools\MYAppPlugins\Computer\Win_WeChat\sqlite3.exe` | SQLite CLI |
| redis-cli/server | `D:\ForensicTools\report-runtimes\MYReport\Bin64\` | Redis 转储 |

#### 4.5A 二进制判壳 / 十六进制（2026-11 新装）

| 工具 | 路径 | 用途 |
|---|---|---|
| **Detect It Easy 4.0（GUI）** | `D:\ForensicTools\DetectItEasy\die.exe` | 判壳/打包器（PyInstaller/Nuitka/UPX/Go/Rust） |
| **DIE 命令行** | `D:\ForensicTools\DetectItEasy\diec.exe` | **可脚本调用**：`diec.exe sample.exe` 直接出结果 |
| **hexins.py（自建）** | `<skill>\scripts\hexins.py` | 十六进制检视/魔数识别/TLV/熵分析/雕刻 |
| jadx GUI | `D:\ForensicTools\jadx\jadx-gui-1.5.6.exe` | APK 反编译 |
| FinalShell | `D:\ForensicTools\MYAppPlugins\Computer\Win_FinalShell\` | 服务器远程、看隐藏目录 |
| Xftp | `D:\ForensicTools\MYAppPlugins\Computer\Win_Xftp\` | SFTP |

**DIE 命令行实测**（判恶意样本框架，一次出结果）：

```powershell
PS> & 'D:\ForensicTools\DetectItEasy\diec.exe' 'sample.exe'
PE64
    Linker: Microsoft Linker (9.00.30729)
    Compiler: MASM (9.00.30729)
```

**hexins.py 六条命令**：

```powershell
python <skill>\scripts\hexins.py magic  fw.bin           # 魔数识别（内置 40+ 条）
python <skill>\scripts\hexins.py view   fw.bin 0 512     # hex + ASCII
python <skill>\scripts\hexins.py str    fw.bin 'dq/field' # 搜字符串带上下文
python <skill>\scripts\hexins.py tlv    fw.bin 0x100 be   # TLV 逐层解析
python <skill>\scripts\hexins.py ent    disk.img          # 熵分析（判加密/压缩）
python <skill>\scripts\hexins.py carv   disk.img 46444d34 # 按魔数雕刻
```

**替代关系**：010 Editor 官网有反爬，下载通道受限；`hexins.py` 覆盖其常用功能，
且天然支持批量/脚本，**比 GUI 更适合取证流水线**。

#### 4.6 密码 / 解密

| 工具 | 路径 | 用途 |
|---|---|---|
| **hashcat 7.1.2** | `D:\ForensicTools\Toolset\FileDecryptTool\hashcat.exe` | GPU 爆破（须在自身目录跑） |
| hashcat（另一份） | `D:\ForensicTools\ForensicDesktop\bin\tools\hashcat\hashcat.exe` | |
| **John the Ripper** | `D:\ForensicTools\ForensicDesktop\bin\tools\john\john.exe` | 多 CPU 变体（avx2/sse41/xop） |
| IMKeyTool | `D:\ForensicTools\Toolset\IMKeyTool\IMKeyTool.exe` | IM 库密钥 |
| SysKeyTool | `D:\ForensicTools\Service\bin\SysKeyTool.exe` | 系统密钥 |
| WalletRecoveryTool / WRR | `D:\ForensicTools\Toolset\` | 钱包恢复 |
| openssl | `D:\ForensicTools\Service\bin\openssl.exe` | 证书/加解密 |

#### 4.7 反编译 / 逆向

| 工具 | 路径 | 用途 |
|---|---|---|
| **strings / objdump / readelf / nm / objcopy / strip** | `E:\bianyiqi\mingw64\bin\` | 全套 binutils |
| **c++filt** | 同上 | C++ 符号 demangle |
| **Go 工具链** | `C:\Program Files\Go\bin\go.exe` | `go tool objdump/nm` 解 Go 二进制 |
| Go 内部工具 | `C:\Program Files\Go\pkg\tool\windows_amd64\` | `nm.exe` `objdump.exe` `addr2line.exe` |
| apk_parser | `D:\ForensicTools\MYAppPlugins\Computer\Any_ApkInfo\apk_parser.exe` | APK 解析 |
| DecodeAllUI | `D:\ForensicTools\Toolset\DecodeAllUI\DecodeAllUI.exe` | 编码转换 |
| muPDF / OutsideIn / Xpdf | `D:\ForensicTools\Service\bin\Plugins\` | PDF 提取 |
| **exiftool** | `D:\ForensicTools\MYAppPlugins\Computer\Any_OfficeMetaInfo\exiftool.exe` | 元数据 |
| ExifToolGUI | `D:\ForensicTools\Toolset\Exiftoolgui\ExifToolGUI_X64.exe` | 元数据 GUI |
| NTFSLog | `D:\ForensicTools\MYAppPlugins\Computer\Win_NTFSLog\NTFSLog.exe` | `$LogFile` |

#### 4.8 OCR / 图像 / 视频

| 工具 | 路径 | 说明 |
|---|---|---|
| **Tesseract 5.4.0** | `C:\Program Files\Tesseract-OCR\tesseract.exe` | 只有 eng+osd，中文需外挂 tessdata |
| **RapidOCR（Python）** | `rapidocr_onnxruntime` | **中文首选，0.56 s/张** |
| ScreenshotOCR | `D:\ForensicTools\Toolset\ScreenshotOCR\ocr.exe` | 美亚 OCR |
| QR 扫描 | `D:\ForensicTools\Toolset\SmartQRScan\qr_scanner.exe` | 二维码 |
| ffmpeg | `D:\ForensicTools\Client\bin\ffmpeg.exe` | 视频抽帧 |
| 多份 ffmpeg | `...\MYFrsAnalyze\bin\ffmpeg.exe`、`...\bin\tools\` | |

#### 4.9 内存 / 仿真 / AI

| 工具 | 路径 | 用途 |
|---|---|---|
| **Volatility 3** | `D:\ForensicTools\Toolset\MemoryAnalysis\tools\vol.exe` | 内存分析 |
| MemoryAnalysis MCP | `...\MemoryAnalysis\MemoryAnalysisMCP.exe` | 内存 GUI |
| **AI 引擎** | `D:\ForensicTools\myai-engine\Qiko3.0 AI引擎.exe` | 本地大模型辅助 |
| ollama | `D:\ForensicTools\myai-engine\resources\ollama\ollama.exe` | 本地模型 |
| 美亚主客户端 | `D:\ForensicTools\Client\bin\ForensicDesktop.exe` | 综合 |
| 软件管家 | `D:\ForensicTools\美亚软件管家\bin\MYAppStore.exe` | 装插件 |

#### 4.10 车联网（2026-11 新装）

| 工具 | 路径 | 用途 |
|---|---|---|
| **SavvyCAN** | `D:\ForensicTools\carlink\SavvyCAN\SavvyCAN.exe` | CAN 抓包浏览 + DBC 解码 GUI |
| **caringcaribou** | `D:\ForensicTools\carlink\caringcaribou\` | UDS/DCM 扫描、fuzz |
| can-utils 源码 | `D:\ForensicTools\carlink\can-utils\` | candump 等参考实现 |

**开工前先自检**：`python "$env:USERPROFILE\.dsh\skills\forensic-master\scripts\toolcheck.py"` —— 缺关键项会标 CRIT。

#### 4.11 通用

| 工具 | 路径 |
|---|---|
| 7-Zip 26.04 | `C:\Program Files\7-Zip\7z.exe` |
| aria2 1.37（多线程下载） | `D:\ForensicTools\aria2\aria2-1.37.0-win-64bit-build1\aria2c.exe` |
| Everything（文件名秒搜） | `D:\ForensicTools\filerecon\everything.exe` |
| filerecon | `D:\ForensicTools\filerecon\filerecon.exe` |
| Docker Desktop / CLI | `C:\Program Files\Docker\Docker\resources\bin\docker.exe` |
| WSL | `C:\Program Files\WSL\wsl.exe` |
| gh（GitHub CLI） | `C:\Program Files\GitHub CLI\gh.exe` |
| ripgrep | `D:\ForensicTools\ForensicDesktop\bin\tools\rg.exe` |

#### 4.12 Python 库（已安装，2026-11 核实）

```
取证核心 : pyewf pytsk3 dissect.target regipy volatility3 pypykatz oletools
          yara capstone pefile pyelftools lief unicorn pwntools
数据库   : sqlite3(内置) pandas openpyxl
网络     : scapy dpkt pyshark requests
加密     : pycryptodome cryptography pynacl paramiko
图像/OCR : Pillow rapidocr_onnxruntime exifread
安卓     : androguard frida
车联网   : python-can cantools canmatrix udsoncan pyserial obd
其他     : binwalk numpy tqdm
```

**一条命令核对全部**：

```powershell
python -c @"
import importlib
for m in ['pyewf','pytsk3','dissect.target','regipy','volatility3','pypykatz','oletools','yara',
          'capstone','pefile','elftools','lief','unicorn','pwn','pandas','scapy','dpkt','pyshark',
          'Crypto','cryptography','PIL','rapidocr_onnxruntime','exifread','androguard','frida',
          'can','cantools','canmatrix','udsoncan','serial','obd','binwalk']:
    try: importlib.import_module(m)
    except Exception as e: print('MISSING:', m)
print('check done')
"@
```

### 5. 常用工具调用模板

**别每次都现场想命令，照抄。**

```powershell
# —— 镜像挂载 ——
& 'D:\ForensicTools\VeraCrypt.exe' /volume $img /letter Z /password $pw /quit /silent /history n /cache n
& 'D:\ForensicTools\Toolset\DiskMountTool\Bin64\DiskMount.exe'   # GUI

# —— EzTools 批量 ——
$ez='D:\ForensicTools\eztools'
& "$ez\MFTECmd\MFTECmd.exe"     -f '$MFT' --csv out --csvf mft.csv
& "$ez\PECmd\PECmd.exe"        -d C:\Windows\Prefetch --csv out --csvf pe.csv
& "$ez\LECmd\LECmd.exe"        -d .\Recent --csv out --csvf le.csv
& "$ez\JLECmd\JLECmd.exe"      -d .\AutomaticDestinations --csv out
& "$ez\RBCmd\RBCmd.exe"        -d '$Recycle.Bin' --csv out
& "$ez\EvtxECmd\EvtxeCmd\EvtxECmd.exe" -d .\winevt\Logs --csv out
& "$ez\AmcacheParser\AmcacheParser.exe" -f Amcache.hve --csv out
& "$ez\SrumECmd\SrumECmd.exe"  -f SRUDB.dat -r SOFTWARE --csv out
& "$ez\SBECmd\SBECmd.exe"      -d NTUSER.DAT --csv out
& "$ez\RECmd\RECmd\RECmd.exe"  -d . --bn BatchFiles\Kroll_Batch.reb --csv out

# —— tshark ——
& 'C:\Program Files\Wireshark\tshark.exe' -r x.pcapng -q -z io,phs
& 'C:\Program Files\Wireshark\tshark.exe' -r x.pcapng -Y 'http.request' -T fields -e frame.number -e ip.src -e http.host -e http.request.uri
& 'C:\Program Files\Wireshark\tshark.exe' -G fields 2>&1 | Select-String 'sctp\.'   # 查字段名！

# —— Volatility ——
& 'D:\ForensicTools\Toolset\MemoryAnalysis\tools\vol.exe' -f mem.raw windows.info
& 'D:\ForensicTools\Toolset\MemoryAnalysis\tools\vol.exe' -f mem.raw windows.registry.hashdump

# —— hashcat（必须 cd 到自身目录）——
Push-Location 'D:\ForensicTools\Toolset\FileDecryptTool'
& .\hashcat.exe -m 0 -a 3 $hash -1 '?l?d' '?1?1?1?1?1?1?1?1' --increment -O --potfile-path pot.txt
Pop-Location

# —— 反编译 ——
& 'E:\bianyiqi\mingw64\bin\readelf.exe' -a fw.elf
& 'E:\bianyiqi\mingw64\bin\objdump.exe' -d --no-show-raw-insn fw.elf
& 'C:\Program Files\Go\bin\go.exe' tool objdump -s 'main\.main' app.bin
& 'E:\bianyiqi\mingw64\bin\strings.exe' -n 6 -t x app.bin

# —— 车联网 ——
python -c "import can; [print(m) for i,m in zip(range(5), can.ASCReader('x.asc'))]"
python -m canmatrix.cli.convert -i x.arxml -o out.dbc
```

## 二、核心判断准则（这部分最值钱）

### 准则 1：时间戳必须标基准，FILETIME 默认 UTC

这是**第一大失分点**。同一场比赛里，5 道题栽在时间基准上。

| 时间类型 | 基准 | 处理 |
|---|---|---|
| Windows FILETIME（注册表、事件日志、MFT） | **UTC** | 需要本地时间就 `+8h` |
| Unix epoch（Linux 文件、TSK meta） | UTC | 同上 |
| Apple 时间戳（2001-01-01 起秒） | UTC | 同上 |
| Linux shadow 第 3 字段 | 1970-01-01 起**天数** | `date(1970,1,1)+timedelta(days=n)` |
| 应用日志内的文本时间 | **通常是本地时间** | 不再转换 |

**验证方法**：拿注册表键自身的 `last_modified` 做交叉校验。如果算出的事件时间比键的写入时间还晚，说明转换方向错了。

> 实战案例：蓝牙 `LastConnected` 直接解出 `11:34:56`，同键写入时间 `03:35:04 UTC`（本地 11:35:04）。两者相差 8 秒，自洽 → 该值已是本地时间，**不能再 +8**。官方答案把它当 UTC 加了 8 得 `19:34:56`，逻辑上比键写入晚 8 小时，不成立。

### 准则 2：$SI 时间戳不可信，先查 $FN

**镜像可能被 TimeStamp Changer 类工具批量篡改过**。识别方法：

- 一批文件的 atime 落在**同一秒**（如都是 `11:11:43`）→ 批量改写
- `$SI` 与 `$FILE_NAME` 的 crtime 差好几年 → 篡改

正确做法：`$FN` 的时间戳极难伪造（含 10ns 精度，GUI 工具做不出来）。用 `forensic.detect_tamper()` 比对。

> 实战案例：`videoplayback (1).mp4` 的 `$SI` crtime = `2019-07-01`（假），`$FN` crtime = `2026-08-04 01:51:53.904564`（真）。选项里给了 `09:51:53`（本地）和 `01:51:53`（UTC）两个陷阱。

**但反过来也要注意**：$SI 不可信时，**别去找 atime 排序**，改用 LNK/JumpList 的 `TargetAccessed`，那才是真实的访问记录。

### 准则 3：账号"创建时间"看 EventId 4720，不看目录 crtime

用户目录的 `crtime` 是**首次登录**时间，不是账号创建时间。

正确依据：Security.evtx 的 **EventId 4720**（创建账号）。

> 实战案例：目录 crtime 显示 Wah `09:32:50` < WONGKH `09:33:46`，但 4720 事件显示 WONGKH `01:26:56` 先建、Wah `01:31:53` 后建。**结论相反**。

### 准则 4：程序"启动时间"看 Prefetch，不看应用日志

应用日志（如 Telegram `log.txt`）的首行是**日志初始化**时刻，晚于进程真实启动。

优先级：`Prefetch LastRun` > `SRUM` > `BAM` > 应用日志。

> 实战案例：Telegram log.txt 首行 `10:06:18`，Prefetch LastRun `10:06:12`。官方取后者。

### 准则 5：题目问的是哪一层？服务层 ≠ 应用层

> 实战案例：Q103 问"Web 服务器 LISTEN 端口"，`.env` 里 `PORT=3000` 是 node 应用端口，nginx `listen 80` 才是 Web 服务端口。答案是 **80**。

读题时先问：**这个信息在哪一层？（应用 / 服务 / 系统 / 硬件）** 每一层都可能有一个"看起来对"的值。

### 准则 6：外置存储要查三条通道

- **USBSTOR**：U 盘、读卡器
- **SCSI**：外置 SSD、移动硬盘（**不落 USBSTOR！**）
- **Portable Devices**：卷标 + 最后连接时间

> 实战案例：Q66 问最后连接的外接存储品牌。只查 USBSTOR 会得到 Kingston，但 SCSI 通道里有 `SanDisk Extreme 55DD`，最后写入时间晚两天。答案是 **SanDisk**。

### 准则 7：日志清除看 104，不是 1102

- `104`（System.evtx）：某一日志文件被清除，带日志名
- `1102`（Security.evtx）：安全日志被清除

问"Application 日志被清除几次"→ 查 System 里的 104，筛 `PayloadData1` 含 `Application`。

### 准则 8：重启 ≠ 关机

判别三件套：`6006`（事件日志服务停止）+ `109`（内核发起关机）+ `13`（系统时间已同步到硬件）。三者齐全才是真关机。

只有 `1074` 且 Kernel-Power `42` 写 `Sleep initiated` → 是**睡眠换休眠**，不是关机。

> 实战案例：8-04 有两条 1074。`17:56:33` 那条无三件套、42 写 Sleep；`09:03:45` 那条三件套齐全。真关机是后者。

### 准则 9：弱口令用 MD4，不是 MD5

NTLM = `MD4(UTF-16LE(password))`。Python 标准库 `hashlib` 在部分平台不支持 MD4，用 `Cryptodome.Hash.MD4`。

### 准则 10：SQLite 删记录要先复制 WAL

直接 `sqlite3.connect()` 会触发 auto-checkpoint，**把 WAL 合并并删掉**，删除记录就永久丢失了。

正确流程：
1. 把 `.sqlite`、`.sqlite-wal`、`.sqlite-shm` 三个文件**一起**复制到独立目录
2. 解析 WAL 时用**复制件**
3. 主库用 `mode=ro&immutable=1` 只读打开

## 三、脚本库

`scripts/` 下三个文件，都是可直接 import 的库。

### forensic.py —— 证据访问层

```python
import sys; sys.path.insert(0, r"<skill>/scripts")
from forensic import Evidence, Walk, ts, ts_utc, filetime, detect_tamper

ev = Evidence(r"G:\case\disk.e01")
print(ev.summary())                    # 分区表 + 可用卷
fs = ev.fs()                           # 自动选最大卷
fs = ev.volumes["part3:Linux (0x83)"]  # 或指定

w = Walk(fs)
for en in w.ls("/home/kali"):          # 列目录
    print(en.name, en.size, ts(en.mtime))
for en in w.walk("/Users"):            # 递归（失败目录记入 w.errors）
    pass

data = fs.open("/etc/hostname").read_random(0, 100)   # 读文件

detect_tamper(fs, "/Users/x/a.mp4")    # 检测时间戳篡改
```

### registry.py —— 注册表高频查询

命令行：
```bash
python registry.py sam  <SYSTEM> <SAM>        # 用户/RID/密码提示/登录时间
python registry.py net  <SYSTEM> <SOFTWARE>   # WLAN配置/蓝牙/网卡真实MAC
python registry.py devices <SYSTEM> <SOFTWARE> # USB/SCSI/便携设备（按时间排序）
python registry.py ua   <NTUSER.DAT>          # UserAssist + RunMRU
```

库调用：
```python
from registry import sam_users, enum_scsi, enum_bluetooth, userassist, crack_ntlm, COMMON_PASSWORDSeh
users = sam_users("SAM")
for u in users:
    print(u["rid"], u["name"], u["hint"])
crack_ntlm("259745cb...", COMMON_PASSWORDS)
```

### setup.py —— 环境自检 + 题目 docx 解析

```powershell
python <skill>/scripts/setup.py                    # 检查依赖与工具
python <skill>/scripts/setup.py docx <题目.docx>    # 提取题目清单到 txt
```

**用途**：拿到 docx 格式的题目时，先转成 txt 再按证据源分组。
比手工复制粘贴可靠（不会漏题、不会串行）。

### toolcheck.py —— 工具链自检

```powershell
python <skill>/scripts/toolcheck.py```

开一个新赛题前先跑，确认 Python 库与 CLI 工具都在，避免开工后才发现缺东西。

### iotkit.py —— 嵌入式/IoT 取证工具集

```powershell
python <skill>\scripts\iotkit.py scan    <目录或文件>      # 全量魔数扫描（找所有协议族）
python <skill>\scripts\iotkit.py gpt     <eMMC镜像>       # GPT 分区表
python <skill>\scripts\iotkit.py recs    <文件> <魔数>     # 按定长切分（自动推断长度）
python <skill>\scripts\iotkit.py align   <目录>          # ★ 多介质时间戳对齐
python <skill>\scripts\iotkit.py wrap    <文件> <魔数> <seq偏移> <seq长度>  # 环形缓冲回绕
python <skill>\scripts\iotkit.py strings <文件> [n]      # 提字符串
python <skill>\scripts\iotkit.py tlv     <文件> [off] [be|le]   # TLV 解析
```

**实测产出**（龙信杯 17 个检材）：

```
scan:  一次扫出 26 个协议族
       LMLL(40) TEL5(18) AUTH(16) MOT5(16) BOOT(12) SEV4(11) GWN6(10)
       EL5R(9) MV6R(9) AU6R(9) JRN6(8) AUT5(8) BCT5(7) MFR6(6) L2C5(6)
       FRG5(6) BOK5(4) OTA5(4) NCE4(3) LMC5(3) RTC5(3) FDM4(3) BGX4(3)
       SSB5(3) MNR6(3) N6FC(3)
       ← 标"带时间戳"的协议可用于对齐

align: 自动找出目标事件的铁证
       ts=0x000A17C2 (661442)  32 处 / 5 介质  ← 目标事件
       ts=0x000A1782 (661378)  17 处 / 3 介质
       ts=0x000A17C1 (661441)   3 处 / 2 介质
       （已过滤 ASCII 型误报）
```

### phonekit.py —— 手机取证工具集

```powershell
python <skill>\scripts\phonekit.py survey  <备份目录>          # 普查：每个 .bak 的明文/加密库统计
python <skill>\scripts\phonekit.py list    <bak> [关键词]      # 列出内部文件
python <skill>\scripts\phonekit.py extract <bak> <路径关键词>   # 提取到 out/
python <skill>\scripts\phonekit.py db      <db>               # 表结构 + 行数
python <skill>\scripts\phonekit.py sp      <bak>              # 全部 SharedPreferences + 关键值
python <skill>\scripts\phonekit.py chat    <db>               # 聊天库（自动认表名）
python <skill>\scripts\phonekit.py events  <db>               # 埋点事件（按类型分布）
```

**实测产出**（龙信杯 54 个 .bak）：

```
survey: 微信 35 库 → 24 明文 / 11 加密   ← 不止 EnMicroMsg
        抖音 37 库 → 32 明文 / 5 加密
        思语 13 库 → 13 明文 / 0 加密
        百度 32 库 → 32 明文 / 0 加密

chat:   本人 快递男神 / 13800138000 / USER_ID 15407437
        会话 13 个，按时间排序，「合规核验组」排最前
        消息 52 条，CONTENT 全是明文中文

events: 117 行全是 $EnterScreen/$ExitScreen → 埋点库无效
        → 转去 CHAT_MESSAGE（判据写在 mobile.md 9.3）
```

### netkit.py —— 流量取证工具集

```powershell
python <skill>\scripts\netkit.py health <pcap>               # 体检：规模/协议层级/端点
python <skill>\scripts\netkit.py fake   <pcap>               # ★ 伪装识别（100% malformed）
python <skill>\scripts\netkit.py ports  <pcap>               # 端口分布
python <skill>\scripts\netkit.py pairs  <pcap>               # IP 会话对
python <skill>\scripts\netkit.py fields <pcap> f1,f2,f3      # 批量导出字段
python <skill>\scripts\netkit.py check  f1,f2,f3             # ★ 字段名有效性验证
python <skill>\scripts\netkit.py http   <pcap>               # 导出 HTTP 对象
python <skill>\scripts\netkit.py find   <pcap> <关键词>        # 载荷搜字符串
```

**实测产出**（龙信杯 360 MB pcapng）：

```
fake:  ★ 识别出 9 个伪装协议
       dns 27101 帧 (100% malformed)  ← 端口 53 上不是 DNS
       mdns 6021 帧 (100% malformed)
       hcrt/enip/elasticsearch/tzsp/trdp/tc_nv/a21 全部 100% malformed

check: dns.qry.name          OK
       sctp.data_mid         OK
       sctp.i_forward_tsn_mid INVALID ❌   ← 就是卡了我三轮的字段

ports: 443(32992) 9000(29020) 9444(27659) 123(27395) 53(27101)
```

### ev.py + fsio.py —— 证据访问层与安全读取层

**所有 kit 工具的底座。分析前先看这两个。**

```powershell
# 通用访问层：E01/raw → pytsk3 FS
python <skill>\scripts\ev.py "D:\case\disk.E01" --parts     # 只列分区
python <skill>\scripts\ev.py "D:\case\disk.E01"             # 自动挑最大分区

# 安全读取层自检
python <skill>\scripts\fsio.py
```

**fsio 解决的四个静默错误**（见 traps 36–40）：

| 问题 | 旧做法 | fsio |
|---|---|---|
| 日志方向 | `read_random(0, 2MB)` 拿最旧 | `read_log(tail=N)` 拿最新 |
| hive 截断 | 静默限 64 MB | `read_hive()` 限 512 MB 且报警 |
| 删除文件 | 混在正常项里 | `Entry.deleted` 字段，默认排除 |
| 时间口径 | 两种格式混打 | `fmt_epoch`/`fmt_filetime` 统一带 UTC/LCL |

```python
import fsio
from ev import open_fs
fs = open_fs('D:/case/disk.E01')                     # 自动选分区
tail = fsio.read_log(fs, '/var/log/auth.log', tail=2<<20)   # 最近
rows = fsio.ls(fs, '/Users')                          # Entry 列表，默认排除删除项
print(fsio.fmt_epoch(rows[0].meta.mtime))            # 2026-09-01 06:13:20 UTC
for e in fsio.ls_all(fs, '/Users'):                    # 显式含删除项
    print(fsio.fmt(e))                                # 展示时才有 [D] 标记
```

### winkit.py —— Windows 取证工具集

```powershell
python <skill>\scripts\winkit.py info     yizhan         # 镜像概览 + 用户目录
python <skill>\scripts\winkit.py hives    yizhan         # 导出全部 hive 到 out/
python <skill>\scripts\winkit.py sysinfo  yizhan         # 计算机名/时区/关机时间/系统版本
python <skill>\scripts\winkit.py accounts yizhan         # RID + 用户名 + 最后登录 + 组
python <skill>\scripts\winkit.py users    yizhan         # UserAssist/RunMRU/RecentDocs
python <skill>\scripts\winkit.py usb      yizhan         # 外置存储三通道
python <skill>\scripts\winkit.py software yizhan         # 已装软件（截断时自动降级）
python <skill>\scripts\winkit.py autorun  yizhan         # 启动项 + 非微软服务
python <skill>\scripts\winkit.py evtx     yizhan         # 导出日志 + EvtxECmd 统计
python <skill>\scripts\winkit.py pf       yizhan         # Prefetch 清单
python <skill>\scripts\winkit.py browser  yizhan [user]  # 浏览器数据
python <skill>\scripts\winkit.py recent   yizhan [user]  # LNK/JumpList/回收站
```

**实测产出**（龙信杯驿站 PC）：

```
sysinfo:  DESKTOP-L8LJ3U8 / China Standard Time / 关机 2026-09-01 06:13:20 UTC
          ⚠ SOFTWARE hive 截断（声称 71 MB，实际 67 MB）→ 自动降级
accounts: RID 1001 parcel_station，最后登录 2026-09-03 10:53:32
          内置组 19 个全部列出
usb:      USBSTOR 空，但 SCSI 抓到 SANDISK ELE + WD Game Drive
          → 印证"外置 SSD 不落 USBSTOR"
evtx:     3752 条，4720 显示 parcel_station 创建于 2026-09-01 06:08:39
pf:       REVERSE_SHELL_BACKUP.EXE pf 存在 → 恶意程序确实运行过
software: SOFTWARE 不可读 → 降级到 Program Files，看到火绒 09-03 08:15 安装
```

### srvkit.py —— 服务器（Linux）取证工具集

```powershell
python <skill>\scripts\srvkit.py profile  srv1        # 发行版/主机名/machine-id/fstab
python <skill>\scripts\srvkit.py accounts srv1        # 账号 + 密码算法 + 锁定状态
python <skill>\scripts\srvkit.py cron     srv1        # crontab/cron.d/spool + systemd timer
python <skill>\scripts\srvkit.py hist     srv1 goyasha # 历史 + 可疑命令分类
python <skill>\scripts\srvkit.py ssh      srv1        # 登录/失败/authorized_keys/sshd_config
python <skill>\scripts\srvkit.py systemd  srv1 [kw]   # 服务清单（Description+ExecStart）
python <skill>\scripts\srvkit.py docker   srv1        # 容器全量表
python <skill>\scripts\srvkit.py web      srv1        # nginx/apache + 应用自带 *.conf
python <skill>\scripts\srvkit.py timeline srv1        # 关键文件 mtime 排序
```

**实测产出示例**（龙信杯 srv1）：

```
ssh:      成功 15 次, 失败 2 次；登录方式全为 password
          → 说明没配密钥登录，是弱口令风险点
hist:     抓到 rm -f /home/*/.bash_history + unset HISTFILE
          → 证据被主动销毁，不是"没有记录"
web:      抓到 /opt/delivery-query/gate.conf（不在 /etc/nginx）
          listen 8080 / proxy_pass app:8000 / access_log off
```

### sqlite_tools.py —— 数据库与文件痕迹

```bash
python sqlite_tools.py wal      <wal文件> [关键词]    # WAL 帧级恢复
python sqlite_tools.py manifest <Manifest.db> [关键词]
python sqlite_tools.py browser  <History> [域名正则]
python sqlite_tools.py autofill <Web Data> [字段名]
python sqlite_tools.py logins   <Login Data>
python sqlite_tools.py notepad  <TabState目录>
python sqlite_tools.py lnk      <Recent目录>
```

## 四、按题型查手册

各题型的完整操作步骤见 `references/`：

| 文件 | 覆盖题型 |
|---|---|
| **`references/quickwin.md`** | **源 × 题 矩阵、一源多题的位置、什么时候换源（先读这个）** |
| `references/traps.md` | **失分陷阱清单 34 条 + 开工检查表（必读）** |
| `references/windows.md` | **Windows 全量**：注册表/事件日志/$J/时间戳三道/DPAPI/Amcache/ShellBags/浏览器/**hive损坏诊断**/**shellcode** |
| `references/linux.md` | **服务器取证全量**：配置/账号/日志/**cron**/**bash_history**/**SSH**/Docker/Web/**反取证识别** + Go/Rust 判别 |
| `references/mobile.md` | **手机全量**：iOS/WhatsApp/**MIUI .bak**/protobuf/**明文库普查**/Android 特有数据/反取证/OCR |
| `references/network.md` | **流量全量**：pcap 全流程/自定义协议/蜜罐/SCTP/时钟阶跃/**协议伪装识别**/通用套路 |
| `references/containers.md` | **VeraCrypt/LUKS/BitLocker/LVM2/打不开的判别树** |
| `references/iot.md` | **嵌入式全量**：eMMC/固件/TLV/**26 个协议族全表**/审计链/定目标事件/NOR-FRAM 区别 |
| **`references/case2.md`** | **加密库密钥不在检材：微信/抖音/SQLCipher 系统排查** |
| **`references/automotive.md`** | **车联网：CAN/CAN-FD/UDS/DBC/GPS/车机镜像/T-Box** |
| **`references/howto.md`** | **高手怎么解题：解析作者的实操路径与工具偏好** |
| **`references/parallel.md`** | **子智能体调度：什么时候分包有收益、怎么分包** |

## 五、交付规矩

1. **边做边写 `progress.md`**：每题 `| 题号 | 答案 | 证据路径 + 字段 |`。没有证据的答案不写。
2. **答案格式严格照题目要求**：大小写、`MMM-DD_hhmm` 这类自定义格式、要不要带括号/冒号，逐字对。
3. **不确定的题标注清楚**：`✅ 已确认` / `🟡 推断（写清推断依据）` / `⬜ 不可解（写清缺什么）`。
4. **多选题口径要交代**：如"只算实际使用"还是"含通讯录登记"，两种都写在备注里。

### 5.1 时间预算（75 题规模，实测校准）

| 阶段 | 预算 | 产出 |
|---|---|---|
| 工具自检 | 2 min | `toolcheck.py` 全绿 |
| 读题 + 三档分类 + 矩阵 | 15 min | 三档清单 + 源×题矩阵 |
| 清点检材 | 10 min | 分区表/备份结构/接口列表 |
| **A 档全清** | **60 min** | 通常拿到 30–40% 的题 |
| B 档 | 90 min | 再拿 25–30% |
| C 档（能做多少做多少） | 90 min | 剩下的 |
| 一致性核对 + 出表 | 30 min | `FINAL.md` |

**硬规则**：
- A 档没清完 **不许碰 C 档**
- 单个 C 档题目超过 **30 分钟无产出** → 标 🟡 换下一题
- 单次全盘扫描超过 **10 分钟** → 切片段/挂后台，别阻塞

### 5.2 放弃的四个硬判据

命中任意一条，立刻标 ⬜ 并写清原因，不要恋战：

1. 密钥是 32 字节 raw 且生成它的标识（androidId 等）不在任何检材里
2. 密钥依赖的文件在另一份被 FDE 加密的镜像里，且无恢复密钥
3. 算法源码被 `shred` 擦除，且 journal 里只剩目录项无数据块
4. 已穷举 400+ 组合且全灭

**交付物要写清三件事**（不许只写"解密失败"）：

```
1. 断了哪一层：root → seed 的 HKDF info 未知
2. 已穷举什么：20 info × 20 salt = 400 组合，全灭
3. 为什么不可恢复：源码被 shred 两遍（auth.log 07:42:20 有记录）、
   journal 只剩目录项、docker 层已清
```

## 六、能力边界（提前告知用户）

这套流程能稳定拿下 **85–90%**。剩下 10% 不是技术问题：

| 类型 | 表现 | 应对 |
|---|---|---|
| **口径歧义** | "排除后续更新"到底排不排某个注册表值 | 无法判断出题人意图，只能二选一并说明依据 |
| **多源冲突** | WiFi 信道在 3 个文件里记了 3 个值 | 同上 |
| **跨检材依赖** | 题目要的数据在另一份检材里 | 不可解，需明确告知 |
| **官方答案错误** | 答案值在检材里根本不存在 | 核对时能发现并指出 |

遇到这四类，**如实说明**比硬猜更有价值。

### 6.1 已知的技术死锁（遇到直接跳过）

| 场景 | 为什么解不开 |
|---|---|
| WeChat 4.x 库 + MIUI 备份 | 4.x 需 androidId，MIUI 备份不备份它 |
| 被 FDE 全盘加密的 PC 里存着手机库的密钥 | 两层加密，外层无密钥 |
| 算法源码被 shred + journal 无数据块 | ext4 journal 只保元数据 |
| docker 镜像层被清（overlay2 空） | 容器内文件不可恢复，只能读宿主机侧挂载 |

## 七、工具与文件总览

```
<skill>/
├── SKILL.md              本文
├── references/
│   ├── quickwin.md       ★ 三档分类 + 源×题矩阵（开工先读）
│   ├── traps.md          ★ 34 条失分陷阱 + 25 条检查表
│   ├── containers.md     容器/加密 + 密钥链断了怎么办
│   ├── case2.md          加密库密钥不在检材
│   ├── windows.md        Windows 全量（含 hive 损坏诊断）
│   ├── linux.md          Linux 服务/Docker + Go/Rust 判别
│   ├── mobile.md         手机全量（含明文库普查）
│   ├── network.md        流量全量（含伪装识别）
│   ├── iot.md            eMMC/固件/TLV/定目标事件
│   ├── automotive.md     车联网 CAN/UDS/DBC/GPS
│   ├── howto.md          高手方法论（GUI 优先）
│   └── parallel.md       子智能体调度判据
└── scripts/
    ├── toolcheck.py      工具链自检（开新题先跑）
    ├── setup.py           环境自检 + 题目 docx 解析
    ├── winkit.py         Windows 取证工具集（12 个子命令）
    ├── srvkit.py         服务器(Linux)取证工具集（9 个子命令）
    ├── phonekit.py       手机取证工具集（7 个子命令）
    ├── netkit.py         流量取证工具集（8 个子命令）
    ├── iotkit.py         嵌入式取证工具集（7 个子命令）
    ├── hexins.py         十六进制检视/魔数/TLV/熵/雕刻
    ├── forensic.py       证据访问层
    ├── registry.py       注册表高频查询
    └── sqlite_tools.py   WAL/浏览器/Notepad/LNK
```
