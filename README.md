# forensic-master

数字取证比赛与实战的**全流程作战手册**。

不是「帮你跑命令」，是「帮你答对题」。

来自两场真实取证赛的完整复盘：**2026 美亚杯个人赛（128 题）** + **2026 龙信杯（75 题）**。
包含 35 条用真实失误换来的陷阱、6 个专用工具集、以及一套「先做哪一半」的开工流程。

---

## 核心：三档分类法

拉开分数差距的不是会不会解，而是**先解哪一半**。

| 档 | 判据 | 单题成本 | 成功率 | 典型占比 |
|---|---|---|---|---|
| **A 不用密钥** | 明文配置/日志/字符串/文件名/时间戳/哈希 | 1–5 min | >80% | 约 40% |
| **B 解一薄层** | 解压缩/XOR/TLV/protobuf/pcap，不需密钥 | 5–15 min | ~70% | 约 30% |
| **C 密钥链** | HKDF/AES/密码派生，密钥可能不在检材 | 30 min+ | <50% | 约 30% |

**执行顺序固定 A → B → C。A 档没清完不许碰 C 档。**

实测依据：某次比赛服务器 20 题里，把时间全押在密钥链上，结果 14 题空白；
而那 20 题里**有 10 题根本不需要密钥**，读个配置文件就能答。

---

## 五条铁律

1. **密码先原样试，再理解它** —— 一眼看着是 Base64 的那串，往往就是密码本身。解码后的值反而不对。两种各试 1 秒，不要做"合理性推断"。
2. **加密容器只挂载，不解密** —— VeraCrypt/LUKS 拿到密码立刻挂成盘符，3 秒可读。写全量解密脚本是 40 分钟 + 写满磁盘。
3. **装任何工具前，先查本机** —— 本机可能已有 798 个 exe。一条命令核对，别先花 10 分钟下载。
4. **一个文件可能答 6 题** —— 先做「源 × 题」矩阵，从覆盖题数最多的源打起。
5. **自定义协议先按题面关键词定位** —— 不要先全量解析。360 MB pcap 里前缀最多的那批往往是干扰协议。

---

## 内容

### references/ —— 12 份手册

| 文件 | 体量 | 覆盖 |
|---|---|---|
| `quickwin.md` | 11.6 KB | **三档分类法**、源 × 题矩阵、A 档验证 |
| `traps.md` | 20.9 KB | **35 条失分陷阱** + 26 项开工检查表 |
| `windows.md` | 38.0 KB | 注册表/事件日志/$J/时间戳三道/DPAPI/ShellBags/**hive 损坏诊断**/shellcode |
| `linux.md` | 31.6 KB | 配置/账号/**cron**/**bash_history**/**SSH**/Docker/Web/**反取证识别**/Go-Rust 判别 |
| `mobile.md` | 30.1 KB | iOS/WhatsApp/**MIUI .bak**/protobuf/**明文库普查**/Android 特有/OCR |
| `automotive.md` | 24.3 KB | CAN/CAN-FD/UDS/DBC/GPS/**DoIP-SOMEIP**/传感器融合/**充电桩**/T-Box |
| `iot.md` | 21.4 KB | eMMC/固件/TLV/**26 个协议族全表**/审计链/定目标事件/NOR-FRAM |
| `network.md` | 21.3 KB | pcap/自定义协议/SCTP/时钟阶跃/**协议伪装识别** |
| `containers.md` | 18.0 KB | VeraCrypt/LUKS/BitLocker/LVM2/**密钥链断了怎么办** |
| `case2.md` | 6.6 KB | **加密库密钥不在检材**：微信/抖音/SQLCipher 系统排查 |
| `howto.md` | 6.2 KB | 高手方法论：解析作者的实操路径与工具偏好 |
| `parallel.md` | 4.9 KB | 子智能体调度：什么时候分包有收益 |

### scripts/ —— 6 个工具集

| 工具 | 子命令 | 用途 |
|---|---|---|
| `toolcheck.py` | — | 工具链自检（开新题先跑） |
| `winkit.py` | 12 | Windows：hive 导出/账号/痕迹/USB/事件日志 |
| `srvkit.py` | 9 | 服务器：账号/cron/history/SSH/Docker/Web |
| `phonekit.py` | 7 | 手机：明文库普查/聊天库/埋点 |
| `netkit.py` | 8 | 流量：体检/伪装识别/字段验证 |
| `iotkit.py` | 7 | 嵌入式：魔数扫描/GPT/多介质对齐 |
| `hexins.py` | 6 | 十六进制：魔数/TLV/熵/雕刻 |
| `forensic.py` / `registry.py` / `sqlite_tools.py` | — | 底层访问层 |

---

## 快速开始

```bash
git clone https://github.com/<you>/forensic-master.git
cd forensic-master

# 1. 工具链自检
python scripts/toolcheck.py

# 2. 读这两份（按顺序）
#    references/quickwin.md   —— 三档分类法
#    references/traps.md      —— 35 条陷阱

# 3. 开工
#    读题 → 三档分类 → 源×题矩阵 → 清点检材 → A 档全清 → B 档 → C 档
```

### 环境变量（可选）

脚本默认指向作者机器的路径，可用环境变量覆盖：

| 变量 | 默认 | 说明 |
|---|---|---|
| `CASE_DIR` | `.` | 案件工作目录（放 `ev.py` 之类的访问层） |
| `FORENSIC_TOOLS` | `D:\ForensicTools` | 取证工具根目录 |
| `EZTOOLS` | `%FORENSIC_TOOLS%\eztools` | EzTools 位置 |
| `WIRESHARK_DIR` | `C:\Program Files\Wireshark` | tshark 位置 |
| `BINUTILS_DIR` | `E:\bianyiqi\mingw64\bin` | strings/objdump 位置 |
| `WIN_OUT` / `PHONE_OUT` / `NET_OUT` | `./win_out` 等 | 输出目录 |

### Python 依赖

```bash
pip install pyewf pytsk3 dissect.target regipy volatility3 pypykatz oletools \
            yara capstone pefile pyelftools lief unicorn pwntools \
            scapy dpkt pyshark requests pandas \
            pycryptodome cryptography pynacl \
            Pillow rapidocr_onnxruntime exifread \
            python-can cantools canmatrix asammdf udsoncan pyserial obd \
            binwalk
```

---

## 关于 35 条陷阱

每条都是真实失误换来的，比如：

- **陷阱 20**：密码「看起来是编码」就去解码 —— 花了 25 分钟试 15 种 KDF 组合全败，真密码就是那串 Base64 字面量
- **陷阱 21**：加密容器整卷解密 —— 写了 105 GiB 全量解密脚本跑了 40 分钟，而挂载只要 3 秒
- **陷阱 28**：不判二进制语言就按 Go 的思路啃 —— `kms`/`gateway` 是 Go，`crypto-agent.core` 是 Rust，找 `gopclntab` 白费半天
- **陷阱 30**：把题面 `[标准格式：xxx]` 当答案 —— 示例是「支付宝」，真答案是「行情学习」
- **陷阱 31**：`mov reg,imm64` 只取到 IP 就收工 —— 端口在 `imm[2:4]` 按大端取，`0x038F`=911 不是 257
- **陷阱 32**：拿通用指令字节当框架指纹 —— `AQAPRQVH1` 是 `push` 指令，任何 shellcode 都有，不是 Cobalt Strike 独有
- **陷阱 33**：`tshark -T fields` 一个字段名无效 → **整条命令静默返回 0 行**（返回码 0、stdout 空、stderr 空）
- **陷阱 34**：按 `len` 字段推二进制偏移 —— 用 `find(已知16字节值)` 定位实测偏移
- **陷阱 35**：同名多服务取第一个就错 —— `dq-bootstrap-guard.service` 是故障保护，`dq-bootstrap.service` 才是主服务

完整清单见 `references/traps.md`。

---

## 能力边界

这套流程能稳定拿下 **85–90%**。剩下 10% 不是技术问题：

| 类型 | 表现 |
|---|---|
| 口径歧义 | 「排除后续更新」到底排不排某个注册表值 |
| 多源冲突 | WiFi 信道在 3 个文件里记了 3 个值 |
| 跨检材依赖 | 题目要的数据在另一份检材里 |
| 官方答案错误 | 答案值在检材里根本不存在 |

遇到这四类，**如实说明**比硬猜更有价值。

### 已知技术死锁（遇到直接跳过）

| 场景 | 原因 |
|---|---|
| WeChat 4.x + MIUI 备份 | 4.x 需 androidId，MIUI 不备份 |
| FDE 加密的 PC 存着手机库密钥 | 两层加密，外层无密钥 |
| 源码被 shred + journal 无数据块 | ext4 journal 只保元数据 |
| docker 镜像层被清 | 只能读宿主机侧挂载 |

---

## 免责声明

本手册用于**授权的电子数据取证**：取证竞赛、CTF、以及取得合法授权的取证分析。

所有案例数据在发布前已脱敏（密码、手机号、内网 IP、个人路径已替换为占位符）。

## License

MIT
