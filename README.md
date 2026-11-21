# forensic-master

数字取证比赛与实战的**全流程作战手册**，作为一个 DSH 技能（skill）发布。

不是「帮你跑命令」，是「帮你答对题」。

来自两场真实取证赛的完整复盘：**2026 美亚杯个人赛（128 题）** + **2026 龙信杯（75 题）**。
包含 35 条用真实失误换来的陷阱、6 个专用工具集、一套「先做哪一半」的开工流程，
以及**一键部署脚本**（自动装 Python 库 + 二进制工具）。

---

## 一、部署

### 只要读手册？零依赖

12 份 Markdown 直接打开就能读，**不需要装任何东西**：

```bash
git clone https://github.com/Yan-W-u/forensic-master.git
cd forensic-master/references
```

先读 `quickwin.md`（三档分类法）和 `traps.md`（40 条陷阱）。

### 要跑工具？按需选档

| 档次 | 内容 | 体积 | 命令 |
|---|---|---|---|
| `docs` | 只读手册 | **0** | `python scripts/install.py --profile docs` |
| `lite` | 磁盘镜像 + 文件系统 + 流量 | ~300 MB | `--profile lite` |
| `core` | 加 Windows 痕迹 + OCR + 破解 | ~800 MB | `--profile core`（默认） |
| `automotive` | core + 车联网 | ~1 GB | `--profile automotive` |
| `full` | 全部（内存/逆向/手机/APK） | ~3 GB | `--profile full` |

```bash
# 例：只做磁盘和流量分析
python scripts/install.py --profile lite

# 例：全都要
python scripts/install.py --profile full
```

### 一键部署（含技能本体）

**Windows**

```powershell
git clone https://github.com/Yan-W-u/forensic-master.git
cd forensic-master
powershell -ExecutionPolicy Bypass -File deploy.ps1              # core 档
powershell -ExecutionPolicy Bypass -File deploy.ps1 -Profile lite
```

**Linux / macOS**

```bash
git clone https://github.com/Yan-W-u/forensic-master.git
cd forensic-master
chmod +x deploy.sh
./deploy.sh                    # core 档
./deploy.sh --profile lite     # 轻量
```

### 部署选项

```powershell
.\deploy.ps1 -Check              # 只检查
.\deploy.ps1 -Profile docs       # 只部署技能本体，零依赖
.\deploy.ps1 -Profile full       # 全装
.\deploy.ps1 -SkillOnly          # 只部署本体，不碰依赖
```

### 工具集需要一个证据访问层

`winkit/srvkit/phonekit` 依赖 `scripts/ev.py`（已随仓库提供）。给检材有三种方式：

**1. 直接传路径（最简单）**

```powershell
# 自动列分区、挑最大的
python scripts/winkit.py sysinfo "D:\case\disk.E01"

# 指定分区 LBA
python scripts/winkit.py sysinfo "D:\case\disk.E01" --lba 104448

# 先看有哪些分区
python scripts/ev.py "D:\case\disk.E01" --parts
```

**2. 环境变量**

```powershell
set CASE_IMAGE=D:\case\disk.E01
set CASE_LBA=104448
python scripts/winkit.py sysinfo
```

**3. 多检材映射文件**（案件目录下建 `images.json`）

```json
{
  "pc":  {"path": "D:/case/PC.E01",  "lba": 104448},
  "srv": {"path": "D:/case/SRV.E01", "lba": 4200448}
}
```

```powershell
set CASE_DIR=D:\case
python scripts/winkit.py sysinfo pc
python scripts/srvkit.py ssh srv
```

`ev.py` 支持 `.E01/.Ex01`（pyewf）、`.raw/.dd/.img`（直读）。

### 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `CASE_DIR` | 当前目录 | 找 `images.json` 的地方 |
| `CASE_IMAGE` | — | 默认镜像路径 |
| `CASE_LBA` | 0 | 默认分区起始 |
| `FORENSIC_TOOLS` | `D:\ForensicTools` | 二进制工具根目录 |
| `EZTOOLS` | `%FORENSIC_TOOLS%\eztools` | EzTools 位置 |
| `WIRESHARK_DIR` | `C:\Program Files\Wireshark` | tshark 位置 |
| `WIN_OUT` / `PHONE_OUT` / `NET_OUT` | `./win_out` 等 | 输出目录 |

---

## 二、装了什么

### Python 库（38 个）

| 分类 | 库 |
|---|---|
| **磁盘/文件系统** | pyewf, pytsk3, dissect.target, dissect.regf, dissect.eventlog |
| **注册表/Windows** | regipy, pefile, oletools |
| **内存** | volatility3 |
| **加密** | pycryptodome, cryptography, pynacl |
| **图像/OCR** | Pillow, rapidocr_onnxruntime, exifread |
| **二进制/逆向** | capstone, pyelftools, lief, unicorn, pwntools, yara-python |
| **网络** | scapy, dpkt, pyshark, requests |
| **车联网** | python-can, cantools, canmatrix, asammdf, udsoncan, pyserial, obd |
| **手机** | androguard, frida-tools |
| **数据/文档** | pandas, openpyxl, python-docx, binwalk |

关键项 13 个（缺了主线跑不通），其余为可选。

### 二进制工具（11 个）

| 工具 | 关键 | 用途 |
|---|---|---|
| **Wireshark / tshark** | ✅ | 流量分析核心 |
| **7-Zip** | ✅ | 解压 |
| **VeraCrypt** | ✅ | 加密容器挂载 |
| **hashcat** | ✅ | 哈希破解 |
| **Detect It Easy** | ✅ | 判壳/打包器 |
| **EzTools 全家桶** | ✅ | MFTECmd/PECmd/LECmd/EvtxECmd/... 共 10 个 |
| jadx | · | APK 反编译 |
| Volatility 3 | · | 内存（pip 已装） |
| SavvyCAN | · | CAN GUI |
| FTK Imager | · | 镜像挂载 |
| Tesseract | · | OCR 备选 |

完整清单（含下载地址）见 `scripts/manifest.py`。

### 技能自带工具（随仓库提供，需 ev.py 读检材）

| 工具 | 子命令 | 用途 |
|---|---|---|
| `winkit.py` | 12 | Windows：hive/账号/痕迹/USB/事件日志 |
| `srvkit.py` | 9 | 服务器：账号/cron/history/SSH/Docker/Web |
| `phonekit.py` | 7 | 手机：明文库普查/聊天库/埋点 |
| `netkit.py` | 8 | 流量：体检/伪装识别/字段验证 |
| `iotkit.py` | 7 | 嵌入式：魔数扫描/GPT/多介质对齐 |
| `hexins.py` | 6 | 十六进制：魔数/TLV/熵/雕刻 |

---

## 三、核心：三档分类法

拉开分数差距的不是会不会解，而是**先解哪一半**。

| 档 | 判据 | 单题成本 | 成功率 | 典型占比 |
|---|---|---|---|---|
| **A 不用密钥** | 明文配置/日志/字符串/文件名/时间戳/哈希 | 1–5 min | >80% | 约 40% |
| **B 解一薄层** | 解压缩/XOR/TLV/protobuf/pcap | 5–15 min | ~70% | 约 30% |
| **C 密钥链** | HKDF/AES/密码派生，密钥可能不在检材 | 30 min+ | <50% | 约 30% |

**执行顺序固定 A → B → C。A 档没清完不许碰 C 档。**

实测依据：某次比赛服务器 20 题里，把时间全押在密钥链上，结果 14 题空白；
而那 20 题里**有 10 题根本不需要密钥**，读个配置文件就能答。

### 时间预算（75 题规模）

| 阶段 | 预算 | 产出 |
|---|---|---|
| 工具自检 | 2 min | `install.py --check` 全绿 |
| 读题 + 三档分类 + 矩阵 | 15 min | 三档清单 + 源×题矩阵 |
| 清点检材 | 10 min | 分区表/备份结构/接口列表 |
| **A 档全清** | **60 min** | **30–40% 的题** |
| B 档 | 90 min | 再 25–30% |
| C 档 | 90 min | 剩下的 |
| 一致性核对 + 出表 | 30 min | `FINAL.md` |

---

## 四、五条铁律

1. **密码先原样试，再理解它** —— 一眼看着是 Base64 的那串，往往就是密码本身。解码后的值反而不对。两种各试 1 秒。
2. **加密容器只挂载，不解密** —— 拿到密码立刻挂成盘符，3 秒可读。写全量解密脚本是 40 分钟 + 写满磁盘。
3. **装任何工具前，先查本机** —— 一条命令核对，别先花 10 分钟下载。
4. **一个文件可能答 6 题** —— 先做「源 × 题」矩阵，从覆盖题数最多的源打起。
5. **自定义协议先按题面关键词定位** —— 不要先全量解析。

---

## 五、内容

### references/ —— 12 份手册

| 文件 | 体量 | 覆盖 |
|---|---|---|
| `quickwin.md` | 11.6 KB | **三档分类法**、源 × 题矩阵、A 档验证 |
| `traps.md` | 20.9 KB | **40 条失分陷阱** + 26 项开工检查表 |
| `windows.md` | 37.9 KB | 注册表/事件日志/$J/时间戳/DPAPI/ShellBags/**hive 损坏诊断**/shellcode |
| `linux.md` | 31.5 KB | 配置/账号/**cron**/**bash_history**/**SSH**/Docker/Web/**反取证**/Go-Rust |
| `mobile.md` | 30.0 KB | iOS/WhatsApp/**MIUI .bak**/protobuf/**明文库普查**/Android/OCR |
| `automotive.md` | 24.4 KB | CAN/UDS/DBC/GPS/**DoIP-SOMEIP**/传感器融合/**充电桩**/T-Box |
| `iot.md` | 21.5 KB | eMMC/固件/TLV/**26 个协议族全表**/审计链/定目标事件 |
| `network.md` | 21.1 KB | pcap/自定义协议/SCTP/时钟阶跃/**协议伪装识别** |
| `containers.md` | 17.9 KB | VeraCrypt/LUKS/BitLocker/LVM2/**密钥链断了怎么办** |
| `case2.md` | 6.6 KB | **加密库密钥不在检材**：微信/抖音/SQLCipher 排查 |
| `howto.md` | 6.2 KB | 高手方法论 |
| `parallel.md` | 4.9 KB | 子智能体调度 |

12 份相互交叉引用，形成全连通图（无孤立手册）。

---

## 六、开工流程

```
第 0 步  三档分类（A/B/C），执行顺序 A→B→C
第 0.5步 A 档也要验证（同名多服务、多二进制看 mtime）
第 1 步  源 × 题矩阵（一个文件答多题）
第 2 步  清点检材（分区表/备份结构/接口）
第 3 步  A 档全清
第 4 步  B 档
第 5 步  C 档（能做多少做多少）
第 6 步  一致性核对 + 出 FINAL.md
```

详见 `SKILL.md` 与 `references/quickwin.md`。

---

## 七、40 条陷阱（节选）

- **陷阱 20**：密码「看起来是编码」就去解码 —— 花了 25 分钟试 15 种 KDF 组合全败，真密码就是那串 Base64 字面量
- **陷阱 21**：加密容器整卷解密 —— 写了 105 GiB 全量解密脚本跑 40 分钟，而挂载只要 3 秒
- **陷阱 28**：不判二进制语言就按 Go 的思路啃 —— Go 找 `gopclntab`，Rust 找 `core::`，白费半天
- **陷阱 30**：把题面 `[标准格式：xxx]` 当答案 —— 示例和真答案完全不同
- **陷阱 31**：`mov reg,imm64` 只取到 IP 就收工 —— 端口在 `imm[2:4]` 按大端取
- **陷阱 32**：拿通用指令字节当框架指纹 —— `AQAPRQVH1` 是 `push` 指令，任何 shellcode 都有
- **陷阱 33**：`tshark -T fields` 一个字段名无效 → **整条命令静默返回 0 行**
- **陷阱 34**：按 `len` 字段推二进制偏移 —— 用 `find(已知值)` 定位实测偏移
- **陷阱 35**：同名多服务取第一个就错 —— `-guard` 是故障保护，不是主服务

完整清单见 `references/traps.md`。

---

## 八、能力边界

能稳定拿下 **85–90%**。剩下 10% 不是技术问题：

| 类型 | 表现 |
|---|---|
| 口径歧义 | 「排除后续更新」到底排不排某个注册表值 |
| 多源冲突 | WiFi 信道在 3 个文件里记了 3 个值 |
| 跨检材依赖 | 题目要的数据在另一份检材里 |
| 官方答案错误 | 答案值在检材里根本不存在 |

### 已知技术死锁（遇到直接跳过）

| 场景 | 原因 |
|---|---|
| WeChat 4.x + MIUI 备份 | 4.x 需 androidId，MIUI 不备份 |
| FDE 加密的 PC 存着手机库密钥 | 两层加密，外层无密钥 |
| 源码被 shred + journal 无数据块 | ext4 journal 只保元数据 |
| docker 镜像层被清 | 只能读宿主机侧挂载 |

---

## 九、目录结构

```
forensic-master/
├── SKILL.md               技能主索引（DSH 靠 frontmatter 识别）
├── README.md              本文件
├── deploy.ps1             Windows 一键部署
├── deploy.sh              Linux/macOS 一键部署
├── LICENSE                MIT
├── references/            12 份手册
└── scripts/
    ├── manifest.py        依赖清单（安装器与自检的唯一数据源）
    ├── install.py         部署器
    ├── toolcheck.py       工具链自检
    ├── winkit.py          Windows 取证
    ├── srvkit.py          服务器取证
    ├── phonekit.py        手机取证
    ├── netkit.py          流量取证
    ├── iotkit.py          嵌入式取证
    ├── hexins.py          十六进制检视
    ├── forensic.py        证据访问层
    ├── registry.py        注册表查询
    ├── sqlite_tools.py    SQLite/WAL/LNK
    └── setup.py           环境自检 + docx 解析
```

---

## 十、常见问题

**Q: 装完 DSH 不认这个技能？**
A: 重启 DSH。技能靠 `~/.dsh/skills/forensic-master/SKILL.md` 的 frontmatter 识别。

**Q: pyewf / pytsk3 装不上？**
A: Linux 先装 `libewf-dev libtsk-dev`；macOS `brew install libewf sleuthkit`；
Windows 用 `pip install libewf-python pytsk3`，失败就装预编译 wheel。

**Q: 二进制工具下载慢？**
A: 用 `setx FORENSIC_TOOLS` 指向已有工具目录，装脚本会自动跳过已存在的。
或手动装 Wireshark/7-Zip/VeraCrypt，`install.py --check` 能识别。

**Q: 没有 GitHub 也能用吗？**
A: 能。技能本体是纯文本 + Python 脚本，拷目录即可；二进制工具按 `manifest.py` 里的 URL 手动下。

---

## 免责声明

本手册用于**授权的电子数据取证**：取证竞赛、CTF、以及取得合法授权的取证分析。

案例数据已脱敏：密码、手机号、内网 IP、个人路径替换为占位符。

## License

MIT
