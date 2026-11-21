# 失分陷阱清单（考前必读）

两个来源，共 35 条：

- **一至六（陷阱 1–19）**：来自 2026 美亚杯 128 题的复盘。13 个错题里**没有一个是因为不会技术**，全是判据选错或读题偏差。
- **六A（陷阱 20–35）**：来自 2026 龙信杯 75 题的复盘。48 道未解题里**一半以上是流程问题**——密码理解错、工具白装、源挑错、协议先全量解析。这 16 条按浪费的时间排序，第 20 条一条就烧掉 25 分钟。

**读法**：考前把「七、开工前检查表」打印出来，对着检材一条条打勾。技术手册可以查，这 27 条必须背下来。

## 一、时间戳（5 题）

### 陷阱 1：FILETIME 当成本地时间

**现象**：注册表、事件日志、MFT 里的 FILETIME，转成 datetime 后直接当本地时间用，或反之。

**正确**：Windows FILETIME 一律是 **UTC**。要本地时间就 +8。

**验证**：拿注册表键自身的 `last_modified` 交叉校验。算出的事件时间若比键写入时间还晚，方向就反了。

> 实战：蓝牙 `LastConnected` 解出 `11:34:56`，同键写入 `03:35:04 UTC` = 本地 `11:35:04`。二者差 8 秒自洽 → 该值已是本地时间，不能再 +8。

### 陷阱 2：$SI atime 当成真实访问时间

**现象**：直接用 `en.atime` 排序找"最后访问的文件"。

**问题**：镜像被 TimeStamp Changer 类工具批量改过，一批文件 atime 落在**同一秒**。

**正确**：改用 LNK 的 `TargetAccessed`（LECmd 输出），或 JumpList。

**识别**：`ls` 一下，若多个文件的 atime 完全相同 → 批量改写。

> 实战：Q36 用 $SI 判出 `videoplayback (1).mp4`，实际答案 `image2.jpg`。$SI 全是 `11:11:43`（工具最后运行 11:11:39 之后）。

### 陷阱 3：用户目录 crtime 当账号创建时间

**现象**：比较 `C:\Users\<name>` 的 crtime 判账号创建先后。

**问题**：目录 crtime 是**首次登录**时间。

**正确**：查 Security.evtx **EventId 4720**。

> 实战：目录 crtime 显示 Wah 09:32:50 < WONGKH 09:33:46，但 4720 显示 WONGKH 01:26:56 先建、Wah 01:31:53 后建，**结论相反**。

### 陷阱 4：应用日志首行当程序启动时间

**现象**：读 Telegram `log.txt` 首行时间当启动时刻。

**问题**：那是日志初始化时刻，晚于进程真实启动。

**正确**：Prefetch 的 `LastRun`（PECmd）。

> 实战：log.txt `10:06:18`，Prefetch `10:06:12`。官方取后者。

### 陷阱 5：多个时间源不一致时没做交叉验证

**现象**：同一事件在注册表、事件日志、文件系统里有三个不同值。

**正确**：全部列出，用"逻辑自洽性"裁决（哪个不会导致因果倒置）。

## 二、证据源选错（3 题）

### 陷阱 6：外置存储只查 USBSTOR

**正确**：三条通道都查
- `Enum\USBSTOR` — U 盘、读卡器
- `Enum\SCSI` — **外置 SSD/移动硬盘走这里**
- `Portable Devices` — 卷标 + 最后连接

> 实战：Q66 只查 USBSTOR 得 Kingston，实际 SCSI 里有 SanDisk Extreme，晚两天。

### 陷阱 7：Web 端口与应用端口混淆

**现象**：看到 `.env` 里 `PORT=3000` 就答 3000。

**正确**：题目问"Web 服务器 LISTEN 端口"→ 查 nginx/apache 配置的 `listen`。

> 实战：nginx `listen 80` 反代 `127.0.0.1:3000`。答案 80。

### 陷阱 8：查错用户

**现象**：题目指定某用户，却查了另一用户的浏览器库/注册表。

**正确**：题面出现用户名就**只查那个用户**。多用户镜像里每个用户都有一套完整数据。

> 实战：Q54 问 Tronic_Guest，但 Tronic_Office 也有 Chrome 库。查错人全盘错。

## 三、读题偏差（3 题）

### 陷阱 9：答了相邻概念

**现象**：题目问"通话记录里诈骗分子来电显示名称"，答了短信通知的发送方。

**正确**：读题时圈出**三个要素**——问的对象、在哪、什么属性。

> 实战：Q3 问通话记录来电名称 = `KaHo`（Telegram 联系人），不是短信抬头。

### 陷阱 10：多选口径没交代

**现象**："哪些电话号码由 X 使用"——只认实际注册，还是含通讯录登记？

**正确**：两种口径都算出来，答案写一个，备注写另一个。

### 陷阱 11：答案格式不符

**现象**：题目要求 `MMM-DD_hhmm`，答成 `2026-08-07 09:47`。

**正确**：逐字照格式。特别注意：
- 大小写（`TELEGRAM` vs `telegram`）
- 分隔符（`_` vs `-` vs 空格）
- 括号（HKID 要 `R345789(0)`）
- 要不要加号（电话号码 `+852...`）
- 要不要前导零

## 四、过度推理（1 题）

### 陷阱 12：替出题人做语义修正

**现象**：Q70 的 1074 事件 param5 写 `power off`，但 Kernel-Power 42 写 `Sleep initiated`。我判定"是睡眠不是关机"，答了另一条时间。

**问题**：题目问"日志记录的关机时间"，就以日志为准。

**正确**：题面怎么说就怎么查。除非题面明确要求"排除干扰项"，否则不要自己加判断条件。

## 五、解析工具坑（导致数据读不到）

### 陷阱 13：sqlite3.connect 触发 checkpoint

**现象**：打开 `Photos.sqlite` 后 `-wal` 文件消失，已删记录永久丢失。

**正确**：三件套一起复制到独立目录，用 `mode=ro&immutable=1` 打开主库，WAL 用帧级解析。

### 陷阱 14：/etc/os-release 是符号链接

**现象**：直读得 21 个 `\x00`。

**正确**：读 `/usr/lib/os-release`。

### 陷阱 15：目录遍历静默跳过

**现象**：tskwalker 对某些目录报 `Unable to open directory`，代码里 `except: pass` 跳过，漏掉关键文件。

**正确**：记录 `errors`，遍历结束后回补。或用多路径重试。

> 实战：漏了桌面 `TronicData/nginx-tronic.conf`，Q103 答错。

### 陷阱 16：regipy 返回值类型不一致

**现象**：同一个值的类型，有时 `bytes`，有时 `str`（hex 字符串）。

**正确**：统一用 `tb()` 转换函数兼容。

### 陷阱 17：哈希算法前缀看反

`$5$` = SHA-256，`$6$` = SHA-512。容易记成 5=512。

## 六、逻辑关联坑

### 陷阱 18：前后题强关联

**现象**：Q120 问笔数、Q121 问总金额。笔数错一笔，金额必然错。

**正确**：关联题做成对，先确认前者再算后者。

### 陷阱 19：回执/日志类数据本就不存在

**现象**：WhatsApp 的 `ZRECEIPTINFO` 只对本机发出的消息有值，别人发的消息回执为 NULL。

**正确**：先确认数据结构是否支持题目所问。**题目本身可能无解**（跨检材依赖）。

## 六A、流程性失分（2026 龙信杯，16 条，占总失分一半以上）

这 8 条**与技术无关**，全是流程问题。按浪费的时间排序。

### 陷阱 20：密码"看起来是编码"就去解码

**现象**：用户给的密码是 `<BASE64_PASSWORD>`，一眼 Base64。解码后得到一个"看起来合理"的字符串，用解码值试了 15 种 KDF 组合全败。

**正确**：**真实密码就是那串 Base64 字面量本身**。

```
候选顺序（每个 1 秒，全试）：
1. 原样字符串
2. Base64 解码值
3. 原样 + 换行 / 去尾空字节
```

**判据**：解出的头 4 字节是 `VERA`/`TRUE`/`LUKS` 即命中。成本对称，不要做"哪个更合理"的推断。

### 陷阱 21：加密容器整卷解密

**现象**：拿到密码后先写了 105 GiB 全量 AES-XTS 解密脚本，跑了 40 分钟、写了 105 GiB。

**正确**：VeraCrypt/LUKS 拿到密码后**立刻挂载成盘符**，秒级可读。全量解密只在容器不支持随机读、或下游工具必须吃 raw 时才做。

**代价对比**：挂载 3 秒 vs 全量解密 40 分钟 + 105 GiB 磁盘。

### 陷阱 22：装工具前不查本机

**现象**：花 581 秒从 GitHub 下 VeraCrypt 安装包，装完发现 `D:\ForensicTools\VeraCrypt.exe` 早就有了。

**正确**：开工前一条命令核对常用工具路径。见 SKILL.md 铁律 3。

### 陷阱 23：随机挑一个应用开始挖

**现象**：手机 15 题，先啃微信（SQLCipher）、抖音（`encrypted_*`）、高德（1600 文件），30 分钟零产出。真正的答案全在一个明文库 `sy_chat_imPROD_SY.db` 里，一个文件答了 6 题。

**正确**：先做「源 × 题」矩阵，从覆盖题数最多的源打起。见 `quickwin.md`。

**识别信号**：题面有"核心""最""明确"这类限定词 → 答案在少数关键记录里，不在主流 app 的海量数据里。

### 陷阱 24：自定义协议先全量解析

**现象**：360 MB pcapng，先把 11835 条 `TLM4` 记录全解一遍（导出 111594 行），结果 `TLM4` 是干扰协议；真正要答的 `IN7`/`UI7`/`PMU7` 按题面关键词一搜就出来了。

**正确**：先做前缀分布统计 + 按题面关键词过滤，再全量解析。见 `network.md` 第十一节。

**判据**：前缀数量最多的往往是背景噪声；数量少但成对出现的才是问答对。

### 陷阱 25：二进制格式靠猜字节序

**现象**：eMMC 固件里的 TLV 元数据，先按小端解出 len=57141（越界），又试单字节 len，试了三轮。

**正确**：用「len == 到下一条 tag 的起始距离」这条强判据验证，再用**同族样本**（多个固件的同位置）交叉确认。见 `iot.md` 第三节。

### 陷阱 26：多部件/多版本取错对象

**现象**：三个固件各有版本（`fw-38.20` / `fw-66.01` / `fw-49.07`），题面问"**主控**实际运行的固件版本"。

**正确**：读题时圈出限定词。主控=main_soc，门锁=lock_mcu，电机=motor_controller。同理"真实控制终端"要按"是否进入核心接口"判，不是按流量大小。

### 陷阱 27：把哈希不符当成镜像损坏

**现象**：`MD5.txt` 记录 `ded3847f…`，实算 `24da52b7…`，一度怀疑映像不完整。

**正确**：先验证**内部一致性**——VeraCrypt 主/备两份头部 CRC 是否都通过、解出的引导扇区是否有文件系统魔数。内部全对但外部哈希不符 → 是**清单与发放件不配套**，映像本身可用。这条要写进交付物。

### 陷阱 28：不判断二进制语言就按 Go 的思路啃

**现象**：`kms`、`gateway-401` 都是 Go（符号形如 `main.(*server).decrypt`），于是默认 `crypto-agent.core` 也是 Go，去找 `gopclntab`——其实它是 **Rust**（符号 `_ZN...17h<hash>E`，路径 `/rustc/<hash>/library/...`）。

**正确**：反汇编前一条命令判语言。

```powershell
& strings.exe -n 6 app.bin | Select-String -Pattern '/rustc/|_ZN.*17h[0-9a-f]{16}E|runtime\.mallocgc'
```

命中 `/rustc/` → Rust；命中 `runtime.` → Go。见 `linux.md` 第十三节。

**顺手的收获**：两种语言的 `Debug` 派生都会把**结构体字段名连串**编译进 `.rodata`：

```
struct Config with 12 elements  node_id challenge_id dataset_id schema_rev
generation db_generation manifest_hash runtime_epoch crypto_endpoint
renew_interval grace_deadline server_cert_pin
```

→ 题面问「第 N 个字段名」时，**这一步就能直接答，不用反汇编**。

### 陷阱 29：拿配置 JSON 的数字回答"常量"题

**现象**：题面问「请求时间与服务器时间允许相差最大秒数」，配置文件里有 `grace_deadline=90`、`lease_ttl=120`、`renew_interval=60`，随便挑一个填。

**正确**：这三个都是**业务参数**——宽限期、有效期、续租间隔，没有一个是时钟容差。真正的容差通常是代码里的硬编码常量或另一份 schema。

**判据**：配置字段名带 `ttl` / `deadline` / `interval` / `grace` 的都是业务语义；`skew` / `tolerance` / `drift` / `max_age` 才是时钟语义。找不到就标 🟡 并写清"配置里只有业务参数"。

### 陷阱 30：把题面的「标准格式：xxx」当成答案

**现象**：龙信杯手机第 5 题写「嫌疑人收到的安装包名称？[标准格式：支付宝]」，我直接填了 `支付宝`。真答案是 `行情学习`。同一份卷子里 `[标准格式：Nuitka]` 的答案也不是 Nuitka，是 `PyInstaller`。

**正确**：`[标准格式：...]` 只是**格式与长度的示例**，出题人随手写的占位词。

**判据**：
- 方括号里是「格式」二字 → 纯格式示例，值必须自己算
- 示例值常是**干扰项**（甚至故意写一个同类但错误的答案）
- 例外：解析里明确说"格式示例即答案"的极少

**自查**：每个答案填之前问一句——「这个值是我从检材里提取的，还是我从题面抄的？」凡是从题面抄来的，一律重新核。

### 陷阱 31：`mov reg, imm64` 只取到 IP 就收工

**现象**：龙信杯计算机第 14 题问恶意程序回传地址。我在 shellcode 里找到 `c0 a8 02 6f`（192.0.2.111），又从旁边 `68 01 01 00 00`（`push 0x101`）取了 257，答 `192.0.2.111:257`。真答案是 **`:911`**。

**正确**：8 字节立即数的布局是 `[pad 2B][port 2B 大端][ip 4B]`：

```python
imm = seg[i-4:i+8]                      # i 是 IP 的起始位置
port = int.from_bytes(imm[2:4], 'big')  # 0x038f = 911
```

| 错误取法 | 得到 |
|---|---|
| `imm[0:2]` | 512（pad） |
| `imm[2:4]` 小端 | 36611 |
| 相邻 `push 0x101` | 257 |

**判据**：反连地址是**一条 `mov` 指令装载的 8 字节**，IP 和端口在同一个立即数里。找到 IP 后必须回退 4 字节取完整立即数，按字段切开。见 `windows.md` 第七节。

### 陷阱 32：拿通用指令字节当框架指纹

**现象**：看到 `AQAPRQVH1` 就判成 Cobalt Strike。其实它是 `push r9 / push r8 / push rdx / push rcx`（`51 50 52 51 56 48`）的指令字节，**任何 x64 shellcode 都有**。真正答案是 **Metasploit**。

**正确**：判框架看 **prologue + API 哈希循环**，不看单个串。

```python
msf = bytes.fromhex('fc4883e4f0e8c0000000415141505251564831d2'
                    '65488b5260488b5218488b5220488b7250480fb74a4a4d31c9')
is_msf = seg.find(msf) >= 0
# 紧随其后的 ac3c617c022c20 + 41c1c90d4101c1e2ed = djb2 block_api
is_cs = any(k in seg for k in (b'beacon', b'ReflectiveLoader'))
```

**判据**：
- `AQAPRQVH1`、`ws2_32`、`VirtualAlloc`、`ExitProcess` → **通用，不能定框架**
- msfvenom 标准 48 字节 prologue 命中 → Metasploit
- `beacon` / `ReflectiveLoader` / XOR 配置块 → Cobalt Strike
- 两者都不中 → 别硬判，标 🟡 写明依据

**通用教训**：任何"黑客工具指纹"都要满足「**只有该工具才会产出**」才可用。出现在所有同类样本里的字节串不是指纹。


### 陷阱 33：`tshark -T fields` 一个字段名无效，整条命令静默返回 0 行

**现象**：`sctp.i_forward_tsn_mid` 在 Wireshark 4.x 不存在，导致

```powershell
tshark -r x.pcapng -Y sctp -T fields -e frame.number -e ... -e sctp.i_forward_tsn_mid
```

**返回码 0、stdout 空、stderr 空**。看起来像"过滤器没命中"，实际是字段名非法，tshark 静默放弃整条输出。我为这一个字段浪费了三轮排查。

**正确**：
1. 先 `tshark -G fields | Select-String 'sctp\.'` 核对字段名
2. 或**逐字段单独跑一遍**验证有效性，再组合

```powershell
foreach($f in 'sctp.data_sid','sctp.data_mid','sctp.i_forward_tsn_mid'){
  $o = & tshark -r x.pcapng -Y sctp -T fields -e frame.number -e $f 2>&1
  "{0,-32} {1}" -f $f, $(if($o.Count -gt 0 -and $o[0] -notmatch 'valid'){"OK"}else{"INVALID"})
}
```

**判据**：`-T fields` 输出为空时，先怀疑字段名，再怀疑过滤器。

### 陷阱 34：按 `len` 字段推二进制记录偏移

**现象**：SSB5 会话记录里 `len=417`，我据此算者 challenge 在 `@32`，实际在 `@36`（前面 pad 字段宽度不同）。

**正确**：**用已知值定位实测偏移**。

```python
ic = record.find(challenge_bytes)   # 已知 16B 挑战值
ii = record.find(ident_bytes)
print('challenge @0x%02x, ident @0x%02x' % (ic, ii))
```

然后从实测偏移往回看前面有几个字段，反推出结构。龙信杯 SSB5 的 challenge 在记录内 `0x24`、ident 在 `0x34`，与按 `len` 推算的差 4 字节。

**通用做法**：只要记录里有「一眼能认出的固定值」（挑战值、UUID、时间戳、0x1122334455667788 这类填充值），就用 `find()` 定位，别算偏移。


### 陷阱 35：同名多服务/多二进制，取第一个就错

**现象**：龙信杯问「负责完整启动查询系统的 systemd 服务名」。`for f in *dq*.service` 拿到的
第一个是 `dq-bootstrap-guard.service`，但那是**故障保护**，真正的是 `dq-bootstrap.service`。

```
dq-bootstrap.service         Description=DQ Main Bootstrap
                             ExecStart=/opt/delivery-query/bin/crypto-agent
                             ExecStopPost=/usr/local/libexec/dq-cleanup
dq-bootstrap-guard.service   Description=DQ Main Fail-Closed Guard V3.4.7
                             ExecStart=/opt/delivery-query/bin/dq-bootstrap-guard
```

**正确**：候选全部打印 `Description` + `ExecStart` 再选。

| 后缀/关键词 | 通常是 |
|---|---|
| `-guard` / `-watchdog` / `-monitor` | 防护服务 |
| `Fail-Closed` / `Health` / `Proxy` | 辅助服务 |
| 带 `ExecStopPost` + `WantedBy=multi-user.target` | **主服务** |

**同类坑：同目录多个二进制看 mtime**

```
crypto-agent.core   02:53:52   ← 原始核心（题问"原始"取这个）
crypto-agent        03:50:05   ← wrapper（题问"当前 ExecStart"取这个）
```

**判据**：题面有「原始」「最初」「后期调整前」→ 按时间取旧；
有「当前」「实际执行」→ 按 `ExecStart` 取。两个问法答案不同。

## 七、开工前检查表（2026 龙信杯增补 16 条）

```
—— 基础（美亚杯）——
□ 所有时间戳的基准都标注了吗？（UTC / 本地 / epoch / 天数）
□ 有没有一批文件 atime 相同？（篡改信号）
□ 账号创建顺序用的是 4720 吗？
□ 程序启动时间用的是 Prefetch 吗？
□ 外置存储查了 USBSTOR + SCSI + Portable 三条通道吗？
□ 题目指定了用户名吗？查的是该用户的数据吗？
□ 端口题分清是应用层还是服务层了吗？
□ 有没有前后关联题（笔数↔金额、时间↔顺序）？
□ 答案格式逐字对过题面要求了吗？
□ 多选题的口径写进备注了吗？
—— 2026 龙信杯增补 ——
□ 密码按「原样 / Base64解码后 / 加换行」全试过吗？（各 1 秒）
□ 加密容器是挂载的还是整卷解密的？（必须挂载）
□ 装工具前查过 D:\ForensicTools 了吗？
□ 做过「源 × 题」矩阵吗？先打覆盖题数最多的源了吗？
□ 自定义协议先按题面关键词定位了吗，还是先全量解析了？
□ TLV/二进制的字节序用同族样本验证过了吗？
□ 一个数据源超过 20 分钟没产出 → 换源标 🟡 了吗？
□ 多个固件/多个会话时，按题面的限定词（主控/真实/最后）取对了吗？
□ 二进制反汇编前判过是 Go 还是 Rust 吗？
□ 配置 JSON 里的数字，确定是题面问的那个语义吗？
□ 答案是检材里提取的，还是从题面 [标准格式] 抄的？
□ shellcode 的端口从 imm[2:4] 按大端取了吗？
□ 框架指纹是独占特征，还是通用指令字节？
□ tshark -T fields 输出为空时，先查字段名而不是过滤器？
□ 二进制记录的偏移是用 find(已知值) 定位的，不是按 len 算的？
□ 同名多服务/多二进制时，是否全部打印对比过？
```

## 八、必须警惕的"题面陷阱"信号词

| 信号词 | 含义 |
|---|---|
| **"排除…后"** | 数据里有干扰项，要找原始值而非更新后的值 |
| **"最后"** / **"最早"** | 要有明确排序依据，且依据要有旁证 |
| **"实际"** / **"真实"** | 存在伪造值，要找原始记录 |
| **"全部"** / **"合计"** | 多源合并，别漏 |
| **"成功"** / **"有效"** | 要过滤失败记录 |
| **"未加密"** | 明文 HTTP，不是 HTTPS |
| **"唯一"** / **"只有"** | 答案应当唯一，如果有多个说明查错了 |

## 九、无法避免的失分

以下四类**不是能力问题**，遇到如实说明比硬猜有价值：

1. **口径歧义**：题面本身有多种合理解释
2. **多源冲突**：同一事实在不同文件里有不同值，且无优先级提示
3. **跨检材依赖**：题目要的数据在另一份检材里
4. **官方答案错误**：答案值在检材里根本不存在

这四类要写进交付物的备注，让用户知道"这题可能不是我的错"。


## 相关章节

- `quickwin.md` —— 三档分类
- `windows.md` —— Windows 具体操作
- `linux.md` —— Linux 具体操作
- `mobile.md` —— 手机具体操作
- `network.md` —— 流量具体操作
- `iot.md` —— 嵌入式具体操作

### 陷阱 36：日志从头读 = 拿到最旧的内容

**现象**：`read_random(0, 2MB)` 读 `auth.log`。日志是**追加写**的，
offset 0 是最旧的。于是「最后一次成功登录」拿到很早以前那次，
「爆破次数」只统计了开头一小段。结果看起来完整，方向却是反的。

**实测**（3.4 MB 构造日志）：

```
旧做法 read_random(0, 2MB)：
   Accepted 24768 条，最后一条 old24767（8月1日）
   含 FINAL_USER: False        ← 最新登录完全没读到

新做法 read_log(tail=2MB)：
   Accepted 24508 条，最后一条 FINAL_USER（9月3日）
   含 FINAL_USER: True         ← 正确

全量 read_log()：
   40001 条（真值 40001）      ← 统计也对
```

**判据**：
- 找「最近/最后一次/最后一个」→ 读**尾部**（`read_log(tail=N)`）
- 统计「总共多少次/有多少」→ 读**全量**（有上限，超限报警）
- 绝不用 `read_random(0, N)` 当"读日志"

```python
import fsio
# 找最近
tail = fsio.read_log(fs, '/var/log/auth.log', tail=2 << 20)
# 全量统计
full = fsio.read_log(fs, '/var/log/auth.log')
```

**这比报错恶劣**：不报错、不空、看着完整，方向反了。

### 陷阱 37：hive 静默截断到 64 MB

**现象**：`read(fs, path, limit=64 << 20)` 读 SOFTWARE hive。
实际 71565312 字节（68 MB），**超了 4 MB**，写出来是半截 hive。
喂给 regipy → `Bad subkey at offset N` 或只读到部分键。
而它只会打印 `len(d)`，67108864 这个数字不会报警。

**实测**（龙信杯驿站 PC）：

```
SOFTWARE  71565312 字节 → 旧上限 64 MB 截断 4 MB
SYSTEM    12058624 字节 → 未超，正常
```

**修法**：hive 用独立上限，超限明确警告。

```python
data = fsio.read_hive(fs, path)   # 默认 512 MB，超限警告
# 需要更大: set FSIO_MAX_HIVE=1073741824
```

**判据**：hive 读取后先比 `len(data)` 与 `meta.size`，不等就是截断。
**同类：evtx 落回文本上限**

比 hive 更隐蔽 —— `cmd_evtx` 走 `read()` 的 text 上限（8 MB），
而 `Security.evtx` 动辄几十 MB。截断后 EvtxECmd 解析**缺事件但不报错**，
导出的 CSV 看着完整，实际少了记录。

**实测**（龙信杯驿站 PC，150 个 evtx）：

```
Microsoft-Windows-Store%4Operational.evtx   11,603,968 字节
  read_text  (8 MB)  → 8,388,608  truncated=True   缺 3,215,360 字节
  read_evtx  (512MB) → 11,603,968 truncated=False  完整
```

**修法**：类型即函数，各自写死上限。

```python
fsio.read_text(fs, p)   # 8 MB
fsio.read_evtx(fs, p)   # 512 MB  ← evtx 必须走这条
fsio.read_hive(fs, p)   # 512 MB
fsio.read_log(fs, p)    # 256 MB
```

**截断语义**：返回 `ReadResult(data, truncated, size_expected, size_actual)`。
`truncated=True` 时调用方在**程序里**能判断，不只在 stderr 吼一声。
要求完整用 `check_complete(r)`，截断则抛 IOError。

### 陷阱 38：已删除文件混在正常文件里

**现象**：`ls()` 只看 `m.type == TSK_FS_META_TYPE_DIR`，从不看
`m.flags & TSK_FS_META_FLAG_UNALLOC`。而 TSK 的 `open_dir` 会**把已删除条目
也吐出来**，于是删的和没删的混在同一张表里。

「最后访问的文件是哪个」「某文件何时被删」这类题，混进一条已删除项就是错答。

**修法**：删除状态放字段，**不改 name**。

```python
import fsio
rows = fsio.ls(fs, '/path')             # 默认已排除删除项
for e in fsio.ls_all(fs, '/path'):      # 显式要全部
    if e.deleted:
        print(fsio.fmt(e))              # 展示时才加 [D] 标记
```

**绝不能用改名字来传状态**（`nm + ' [DELETED]'`），四处会炸：

| 后果 | 具体 |
|---|---|
| 切断格式化 | `n[:44]` 把 `foo.pf [DELETED]` 截成 `foo.pf [DELET`，标记残半 |
| 名字打不开文件 | `'/Windows/Prefetch/' + n` 拼出不存在路径 |
| 统计碰巧正确 | `n.endswith('.pf')` 因标记后缀失效，这次恰好过滤对了，下次不一定 |
| 排序被打乱 | `' [DELETED]'` 以空格开头，字典序排在最前 |

**常量对照**：

| flags | 含义 |
|---|---|
| `0x0001` | `TSK_FS_META_FLAG_ALLOC` 正常 |
| `0x0002` | `TSK_FS_META_FLAG_UNALLOC` **已删除** |
| `0x0003` | 两者都有（不合规，按已删除处理） |

**判据**：`flags & 0x2` 为真 = 已删除。

### 陷阱 39：两套时间口径用同一个格式打印

**现象**：`ft2dt()` 返回 naive datetime（隐式 UTC），
`dt_utc()` 返回带 tz 的 UTC。两者都过同一个 `%-28s crtime=%s` 打印，
输出里没有任何标记。一个表里既有 epoch 秒又有 FILETIME 转换值，
看的人分不清哪个该 +8。

**修法**：统一带 tz，打印时标注。

```python
import fsio
fsio.fmt_epoch(m.crtime)              # 2026-09-01 06:13:20 UTC
fsio.fmt(fsio.ts_epoch(t), local=True)  # 2026-09-01 14:13:20 LCL
fsio.fmt_filetime(ft)                 # FILETIME 也走同一格式
```

**判据**：输出里必须能看到 `UTC` 或 `LCL`。没有标记的时间戳不可信。

**实测一致性**（同一时刻两种来源）：

```
FILETIME 134326944000000000 → 2026-09-01 00:00:00 UTC
epoch    1788220800         → 2026-09-01 00:00:00 UTC
本地                          → 2026-09-01 08:00:00 LCL
```

### 陷阱 40：except 全吞，三种故障一个样

**现象**：

```python
except Exception:
    pass          # ls()     → 返回空列表
except Exception:
    return ''     # read_text() → 返回空字符串
```

「文件不存在」「权限拒绝」「读到一半失败」全变成空值。
和陷阱 33 的「tshark 静默返回 0 行」是同一类错误。

**修法**：分类提示到 stderr。

```python
try:
    n = fs.open(path)
except FileNotFoundError:
    fsio.warn('文件不存在: %s' % path)     # 区分
except PermissionError:
    fsio.warn('权限拒绝: %s' % path)       # 区分
except Exception as e:
    fsio.warn('打开失败 %s: %s' % (path, e))
```

**判据**：返回值空 + stderr 无提示 = 假阴性。必须能看到原因。
