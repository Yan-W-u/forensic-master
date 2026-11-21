# IoT / 嵌入式 / 自定义二进制协议

覆盖：智能门锁、路由器、摄像头一类检材——eMMC/NOR/FRAM 镜像、MCU 固件、总线抓包（UART/I2C/SPI/BLE/NFC）。

**核心方法**：**先扫魔数分布，再按记录切分，最后用同族样本对齐字节序**。不要凭感觉猜结构。

---

## 一、检材清点

一份 IoT 检材通常长这样：

```
evidence/
├── main_soc/          ← 主控（Linux 或 RTOS）
│   ├── device_emmc.raw        ← 整片 eMMC
│   ├── main_soc_firmware.bin   ← 固件（可能是 ELF）
│   ├── ota_cache.bin
│   └── session_store.bin
├── lock_mcu/          ← 单片机
│   ├── lock_mcu_firmware.bin   ← ELF/裸二进制
│   ├── lock_mcu_spi_nor.bin    ← 片外 NOR
│   ├── lock_uart.bin           ← UART 抓包
│   └── rtc_trace.bin
├── motor_controller/
├── secure_element/    ← SE / SIM 形芯片
├── gateway/           ← 网关（可能有 pcapng）
└── wireless/          ← BLE HCI、NFC
```

**第一步永远是扫魔数**：

```python
import os, re, collections
BASE = r'...\evidence'
for root, dirs, fs in os.walk(BASE):
    for fn in fs:
        p = os.path.join(root, fn)
        d = open(p, 'rb').read()
        c = collections.Counter()
        for m in re.finditer(rb'[A-Z][A-Za-z0-9_\-]{2,15}', d):
            s = m.group().decode()
            if sum(ch.isupper() or ch.isdigit() for ch in s) >= 2:
                c[s] += 1
        print('%-50s %10d  %s' % (fn, len(d), c.most_common(10)))
```

输出会直接暴露每条流的记录魔数（如 `AUT5` / `MOT5` / `TEL5` / `SEV4` / `SSB5` / `OTA5` / `VH6H` / `JRN6` / `FDM4` / `BGX4` / `GWN6`）。

**判据**：4 字符全大写 + 数字 = 记录魔数；出现在多个文件里的是协议族，只出现一次的是头部。

---

## 二、eMMC / 存储镜像

### 2.1 分区表

eMMC 基本都是 **GPT**（MBR 兜底）：

```python
f.seek(512); h = f.read(92)
assert h[:8] == b'EFI PART'
parts_lba = struct.unpack('<Q', h[72:80])[0]
n         = struct.unpack('<I', h[80:84])[0]
sz        = struct.unpack('<I', h[84:88])[0]
f.seek(parts_lba * 512); tbl = f.read(n * sz)
for i in range(n):
    e = tbl[i*sz:(i+1)*sz]
    if e[:16] == b'\x00'*16: continue
    first = struct.unpack('<Q', e[32:40])[0]
    last  = struct.unpack('<Q', e[40:48])[0]
    name  = e[56:128].decode('utf-16-le','ignore').rstrip('\x00')
    print('%s first=%d last=%d size=%.1fMB' % (name, first, last, (last-first+1)*512/1e6))
```

Android 风格的分区名很好用：`factory` / `bootctrl` / `state` / `userdata` / `audit` / `recovery` / `efi` / `boot` / `system_a` / `system_b` / `userdata_ext`。

**判据**：题面问"审计"、"记录标识" → 直奔 `audit`；问"状态"、"凭据" → `state`；问"用户数据"、"数据库" → `userdata`（常是 SQLite）。

### 2.2 各分区内容识别

```python
PARTS = {'factory':(40,199), 'state':(400,799), 'userdata':(800,1799),
         'audit':(1800,3199), 'recovery':(3200,4095)}
for name,(a,b) in PARTS.items():
    f.seek(a*512); d = f.read((b-a+1)*512)
    print(name, d[:16].hex(), d[:16])
```

| 头魔数 | 含义 | 处理 |
|---|---|---|
| `FDM4` | 出厂数据（型号/序列/校准） | TLV 解析 |
| `SQLite format 3` | 用户数据库 | 直接 sqlite3 只读 |
| `VH6H` | 审计视图头 | 读头 + 记录区 |
| `JRN6` | 审计日志记录 | 按固定间距切 |
| `SEV4` | 安全元件交互 | 槽号/挑战值 |
| `ST5R` / `DID5` | 状态与设备 ID | |
| `BGX4` | 分区封装（内嵌 `emmc/<name>`） | 头部 64B 后是内容 |
| `OTA5` | OTA 缓存 | |
| `SSB5` | 会话库 | |

### 2.3 BGX4 容器

```
BGX4 | ver(u32) | len(u32) | flags(u32) | ?(4) | name(32, 如 "emmc/boot") | ... | 内容
```

内容常是高熵（固件镜像），要提字符串用 `strings`。

---

## 三、TLV 元数据解析（最容易卡住的地方）

固件里的元数据区常是 TLV，但 **tag 长度、len 字节序、len 宽度**三种都可能不同。**别猜，用同族样本对齐。**

### 3.1 三步定位

```python
d = open(fw, 'rb').read()
i = d.find(b'XALG')             # 先用已知 tag 锚定
print(d[i:i+32].hex())          # 看 tag 后紧跟的字节
```

假设看到 `58 41 4c 47 | 01 | 00 | c6 | 01 | 35 df 64 10 | 01 | 16 00 | "XUANSHU..."`

从 `XUANSHU` 往前推：它前面是 `16 00`（=22，正好等于字符串长度），再往前是 `01`，再往前是 `c6`。

→ 结构是 **`TAG(4) | ver(1) | len(2 BE) | value`**，其中 `0x00c6 = 198` 是整段 value 长度。

### 3.2 验证判据（必做的三条）

```
1. len 是否等于「从 value 起点到下一条 tag 起点」的距离？  ← 强判据
2. 两个同族文件（main_soc / lock_mcu）同位置是否结构一致？ ← 强判据
3. 按此结构能否连续解析 >= 3 条且不越界？                ← 中判据
```

三条全过才用。**只过第 1 条也可能巧合**——龙信杯我第一次按小端解，len 解出 `57141` 显然越界，立刻否掉。

### 3.3 内层嵌套

value 里常还有一层 TLV，**key 是 1 字节**：

```python
val = d[i+7:i+7+198]
k = 0
while k < len(val) - 3:
    key = val[k]
    ln  = struct.unpack('>H', val[k+1:k+3])[0]     # 这里是大端
    if ln > 0x90 or k+3+ln > len(val): break
    print('key=0x%02x len=%d %s' % (key, ln, val[k+3:k+3+ln]))
    k += 3 + ln
```

龙信杯实测：
```
key=0x01 len=22  "XUANSHU-2026-LOCK-CASE"      ← 项目/型号名
key=0x02 len=11  "FDM4-DEVICE"                 ← 设备类
key=0x03 len=14  f817984a3622855d681a7136be4704 ← 设备序列
```

**判据**：能连续解析且全部 len 合理（< 0x100）就是对的。

---

## 四、定长记录切分

总线抓包（UART/I2C/SPI）是一串定长记录：

```python
idx = [m.start() for m in re.finditer(b'MOT5', d)]
print('count', len(idx))
# 相邻间隔 = 记录长度
gaps = [idx[i+1]-idx[i] for i in range(len(idx)-1)]
print('record len', collections.Counter(gaps).most_common(5))
```

间隔恒定 → 定长记录。间隔有多个值 → 变长（TLV 或带 len 字段）。

### 示例：`MOT5`（电机控制）24 字节

```
MOT5 | seq(u32 LE) | value(u32 LE) | ts/param(u32 LE) | crc(u32)
```

**脉冲类题目的判据**：题面问"有效机械驱动脉冲数"，找记录里**递增的计数值字段**，看同一事件序列的**首尾差**，不是取最大值。

龙信杯实测两条事件：
```
事件 A: 22530 → 22550 → 22568 → 22656 → 22680 → 22980
事件 B: 27906 → 27926 → 27944 → 28032 → 28056 → 28356
```
→ 差值 450，两个事件差值相同，说明单次动作 450 脉冲。

### 示例：`AUT5`（认证）变长

```
AUT5 | 0500(u16) | ts(u32 LE) | f1(u16) | slot/seq(u16) | f3(u16) | proto(u32 LE) | 结果(变长)
```

`f1` 是**认证传输方式**（`0x0704` / `0x0b02`），`f2` 是**槽号+序号**，`proto` 是凭据协议（`0x9f06` / `0xa006` / `0xa206` / `0xa406`）。

**判据**：题面问"传输方式"就填 `f1`；问"槽号"就填 `f2` 的高字节；问"凭据编号"就填 `proto`。

### 示例：`SEV4`（安全元件）定长 68 字节

```
SEV4 | ver(1) | slot(1) | proto(2 BE) | g0(2) | g1(2) | g2(2) | len(2 BE)
     | challenge(16) | key_or_cred(16) | ts(4) | crc(4)
```

题面问"16 字节认证挑战值" → 直接取 `challenge(16)`。

---

## 五、审计链（VH6H + JRN6）

```
audit 分区起点:
  VH6H | ver(u32 LE) | len(u32 LE) | id(16B) | 保留 ... | 记录区
                                                  ↓
                              偏移 0x1000 / 0x2000 / 0x3000 ... 每 4 KiB 一条
  JRN6 | seq(u16) | ver_hi(u16) | ver_lo(u16) | f(u16) | kind(u16) | len(u32)
       | id(16B) | ... | crc
```

**关键**：`userdata` 里的 `audit_meta` 表存着索引：

```sql
select * from audit_meta;
-- (1, x'a1010000a2060000')   ← 键1 = 当前视图版本 0x000001A1
-- (2, x'2f1b872d...')        ← 键2 = 记录数或根哈希
```

题面问"最终审计视图中的记录标识" → 填 `audit_meta` 键 1 的 u32（如 `0x00A1`），或 `VH6H` 头的 `ver` 字段，两者应一致。

**判据**：`audit_meta(1)` 的 u32 = `VH6H.ver` → 互相印证，答案取题面要求的格式。

---

## 六、网关抓包（pcapng）

```python
i = 0
while i < len(d) - 8:
    bt, bl = struct.unpack('<II', d[i:i+8])
    if bl < 12 or i+bl > len(d): break
    body = d[i+8:i+bl-4]
    if bt == 6:                                   # EPB
        cap = struct.unpack('<I', body[12:16])[0]
        ts_hi, ts_lo = struct.unpack('<II', body[4:12])
        pkt = body[20:20+cap]
        print('ts=%d us' % ((ts_hi << 32) | ts_lo))
        # 以太网 14B + IP 20B + TCP 20B → payload
    i += bl
```

### 时间戳换算

pcapng 的 `if_tsresol` 默认 **微秒**（option code 9 = 6）。`ts = (hi<<32)|lo` 直接是 epoch 微秒：

```python
import datetime
dt = datetime.datetime.fromtimestamp(ts/1e6, datetime.timezone.utc)   # UTC
dt_local = dt + datetime.timedelta(hours=8)                            # 本地
```

**判据**：文件名带日期（如 `lan_capture_0812`）可以交叉验证。龙信杯算出 UTC `2026-08-11 18:15:40`、本地 `2026-08-12 02:15` → 与 `0812` 吻合。

### 应用层自定义帧

```
L2C5 | tag(1) | len(2 BE) | body
body:
  FRG5 | ts(4) | 业务字段 ...
```

**注意 tag 和 len 之间可能有 1 字节保留位**——用「body 里业务魔数出现位置」反推。龙信杯第一次按 `tag+len` 解出 body 以 `\x00FRG5` 开头，说明前面多了 1 字节。

---

## 七、固件字符串提取（型号 / 版本）

```powershell
& 'E:\bianyiqi\mingw64\bin\strings.exe' -n 6 -t x firmware.bin |
  Select-String -Pattern 'XUANSHU|fw-|version|model|MODEL|runtime'
```

**判据**：
- `fw-38.20` 这类 `字母-数字.数字` = **固件版本**
- `<厂商>-lock-runtime` / `<项目>-2026-<用途>` = **项目/型号名**
- `AARCH64` / `ARM` / `thumb` = 架构
- 算法串（`HKDF-SHA256|HMAC-SHA256|CTR-LE|...`）= 加密方案说明，**题目问"算法"时直接抄**

**多个固件的版本要分清**：龙信杯 `main_soc=fw-38.20` / `lock_mcu=fw-66.01` / `motor=fw-49.07`。题面问"**主控**实际运行的固件版本" → 取 main_soc。

---

## 八、日志类镜像（rtc_trace / session_store）

### RTC / 遥测（`TEL5`）

```
TEL5 | seq(u16 LE) | type(u16) | value(u32) | param(u32) | crc32
```

`type=2` 多为事件，`value` 是事件码，`param` 是参数（如 `0x000000b0` = 176）。

### 会话（`SSB5`）

```
SSB5 | ver(1) | flags(1) | len(2) | ... | nonce(16) | mac(16) | ts(4) | crc
```

`nonce` 常是 `112233445566778899aabbccddeeff11` 这种可辨认模式。

---

## 九、嵌入式取证检查清单

```
□ 全检材扫过 4 字符魔数分布，列出所有协议族
□ eMMC 分区表解出，按题面词映射到分区（审计→audit，用户数据→userdata）
□ 每类记录的长度用「相邻魔数间隔」验证过
□ TLV 的 len 字节序用「len == 到下一条 tag 的距离」验证过
□ 同族样本（多份固件）对比过，结构一致才采信
□ 固件 strings 提过版本/型号/算法串
□ 多部件的版本分清，按题面限定词（主控/电机/门锁）取值
□ 计数类题目取「首尾差」而非最大值
□ 时间戳标了 UTC / 本地，并与文件名等外部线索交叉验证
□ 定不出「哪个事件是目标事件」时标 🟡，写清候选值，不硬猜
```

## 十、定「目标事件」的方法（龙信杯实战）

门锁/汽车/工控类题目常有一串「目标事件使用的 X 是什么」，**7–8 道题共用一个锚点**。锚错了全盘皆错。

### 10.1 四源交叉印证

同一事件会在多处留痕，**只有时间戳/编号能对齐的那条才是目标**：

```
session_store（会话库）   ← 主体、凭据、挑战值、时间戳
audit（审计分区）         ← 视图版本、记录序号
<总线日志> AUT5/TEL5      ← 传输方式、动作阶段
<执行器> MOT5             ← 脉冲数
```

龙信杯实测：

| 源 | 字段 | 目标事件值 |
|---|---|---|
| `SSB5 #3` | ts | `0x0A17C2` (661442) |
| `TEL5` | ts | `0x0A17C2` |
| `MOT5` | ts | `0x0A17C2` |
| `AUT5` | proto | `0x6A2` = 1698 |
| `SSB5 #3` | @28:32 | 1698 ← **与 AUT5 proto 一致** |
| `audit` | JRN6 seq=9 lo | `0x01A1` = 视图版本 |

**判据**：当「会话库的某字段」== 「总线日志的某字段」时，这两个字段互为锚点，锁定同一事件。

### 10.2 SSB5 会话记录格式（小米/玄枢系门锁）

```
SSB5 | ver(u16) | tag(u16) | len(u32) | a(u32) | b(u32) | seq(u32)
     | 主体(u32) | 凭据(u32) | 0(u32) | challenge(16) | ident(16) | ts(u32) | 0(u32) | crc(u32)
```

偏移（洞：challenge 在记录内 0x24、ident 在 0x34，**以实测偏移为准**）：

| 偏移 | 字段 | 例 |
|---|---|---|
| 4:6 | 版本 | `0x0301` |
| 8:12 | 视图版本 | `0x01A1` |
| 12:16 | 编号 | 1538 |
| 20:24 | 序列 | 2719 |
| **24:28** | **发起主体编号** | 8842 |
| **28:32** | **凭据编号** | 1698 |
| **36:52** | **16 字节挑战值** | `0f1e2d3c…` |
| 52:68 | 标识 | `eb7cf322…` |
| 68:72 | 时间戳 | `0x0A17C2` |

**别按 `len` 字段推偏移**，直接用 `record.find(challenge_bytes)` 定位实测偏移。

### 10.3 挑「有效」的那个动作

一个时间戳下可能有多个动作（成功 + 中断 + 失败）。判据是 **TEL5 的阶段编号是否走全**：

```
参照（正常动作）: val = 1,2,3,4,5,6,7 全齐
目标事件动作1:   val = [1,2,5]        ← 中断
目标事件动作2:   val = [1,2,3,4,5,6]  ← 完整，取它
目标事件动作3:   val = [1,5,7]        ← 中断
```

对应 `MOT5` 的 `sub` 字段（seq=1 时给出本次脉冲总数）：取与**完整动作**对应那条。

### 10.4 审计视图链

```
userdata 库 audit_meta 表
  key=1 → u32[0]=视图版本(0x01A1)  u32[1]=记录数(0x06A2)
  key=2 → 根哈希 32B

audit 分区
  VH6H | ver(u32)=0x01A1 | len(u32) | id(16B) | [28:32]=衔接值
  body 内每 4KiB 一条 JRN6
    JRN6 | seq(u16) | hi(u16) | lo(u16) | f(u16) | kind(u16) | len(u32) | id(16B) | tail(16B) | crc(u32)
```

**找「最终审计视图记录」的判据**（两条同时满足）：
1. `JRN6.lo == VH6H.ver == audit_meta.key1[0:4]`
2. `JRN6.tail[0:4]` 与 `VH6H[28:32]` 字节相同（衔接）

龙信杯：4 条 JRN6 里只有 `seq=9` 同时满足两个条件。

### 10.5 题面格式示例要按位数反推

| 题面示例 | 反推 |
|---|---|
| `[标准格式：ABC1]` | 4 字符，可能是短码/型号缩写 |
| `[标准格式：lx-01.02]` | 固件版本，形如 `fw-38.20` |
| `[标准格式：ABC]` | 3 字符，可能是协议缩写 |
| `[标准格式：1]` | 单个数字，槽号/序号 |
| `[标准格式：0x00A1，0x为固定格式]` | 十六进制 4 位，**示例值本身不是答案** |

**注意**：示例值可能恰好等于答案（如 Q75 的 `0x00A1` 形似 `0x01A1`），也可能完全不同（如 Q5 的 `支付宝`）。判据仅用于判断**格式长度**，不用于判断**内容**。


## 相关章节

- `automotive.md` —— 车联网总线（同属嵌入式）
- `containers.md` —— 固件加密与签名
- `network.md` —— 网关 pcapng 分析
- `windows.md` —— 固件里的 PE / ELF 组件
- `traps.md` —— 二进制字节序陷阱（陷阱 25）

## 十一、协议族全表（龙信杯 17 个检材实测）

嵌入式检材的**每个存储介质都有自己的魔数**。不扫全表就会漏。

### 11.1 必须先做的事：全检材魔数扫描

```python
import os, re, collections

for p in all_files:
    d = open(p, 'rb').read(32 << 20)
    c = collections.Counter()
    for m in re.finditer(rb'[A-Z][A-Z0-9]{3}', d):
        c[m.group().decode()] += 1
    top = [(k, v) for k, v in c.most_common(12) if v >= 3]
    print('%-46s 头16B=%s' % (os.path.basename(p), d[:16].hex()))
    print('   魔数: %s' % ', '.join('%s(%d)' % (k, v) for k, v in top))
```

**龙信杯实测产出**（17 个文件，扫出 20+ 个协议族）：

| 文件 | 头 16B | 协议族 |
|---|---|---|
| `gateway_capture.bin` | `47574e36 c2170a00` | **GWN6**（网关记录） |
| `lan_capture_0812.pcapng` | `0a0d0d0a` | pcapng |
| `lock_mcu_firmware.bin` | `7f454c46 01010100` | ELF 32 + **LMLL/AUTH/BOOT/NCE4** |
| `lock_mcu_spi_nor.bin` | `ffffffff...` | **EL5R / JRN6** |
| `lock_uart.bin` | `41555435 05008217 0a00` | **AUT5 / LMC5** |
| `rtc_trace.bin` | `52544335 0000f0ff` | **RTC5 / TEL5** |
| `device_emmc.raw` | 全 0（GPT） | **MV6R/AU6R/BCT5/BOK5/JRN6/FDM4/BGX4** |
| `main_soc_firmware.bin` | `7f454c46 02010100` | ELF 64 + **LMLL×27/AUTH/GWN6** |
| `ota_cache.bin` | `4f544135 9d010000` | **OTA5** |
| `session_store.bin` | `53534235 01015000` | **SSB5** |
| `motor_controller_firmware.bin` | `7f454c46 01010100` | ELF 32 + LMLL/AUTH/BOOT |
| `motor_controller_fram.bin` | `4d465236 5a000000` | **MFR6** |
| `motor_controller_nor.bin` | `4d4e5236 06000000` | **MNR6** |
| `motor_uart.bin` | `4d4f5435 01000000` | **MOT5** |
| `secure_element_i2c.bin` | `53455634 04019f06` | **SEV4** |
| `ble_hci_0812.bin` | `48434935 00020000` | **HCI5 / L2C5 / FRG5 / LKT5** |
| `nfc_reader_trace.bin` | `4e364643 2645` | **NFC5** |

### 11.2 公版记录结构（各家一致）

```
MAGIC(4) | seq(u16/u32) | ... | crc(u32)
```

龙信杯各协议的实测布局：

**GWN6（网关，44 字节/条）**
```
GWN6 | ts(u32)=0x0A17C2 | 0x00000002 | payload(16) | crc
      两个 GWN6 记录的 payload 不同但 ts 相同 → 同一事件的两个方向
```

**MFR6（电机 FRAM，36 字节/条）**
```
MFR6 | 序号(1B) | value(u32) | a(u32) | b(u32) | c(u32) | d(u32) | crc
       例：MFR6 5a000000 02580000 ...  → 序号 0x5a，值 0x58=88
```

**MNR6（电机 NOR，32 字节/条）**
```
MNR6 | ver(u32) | 0x00000003 | ts(u32)=0x0A17C2 | 0x00404302 | 0x00006520 | 0x0101 | crc
       每条都有 ts，可与其他源交叉对齐
```

**RTC5（RTC 快照，27 字节/条）**
```
RTC5 | 0x0000 | 0xf0ff | 0x00 | 0x01 | ts_frac | ...
```

**LMC5（MCU 事件，18 字节/条）**
```
LMC5 | ts(u32) | type(u32) | val(u32) | crc
       例：LMC5 82170a00 01000000 01007c1d
           ts=0x0A1782  type=1  val=0x1d7c
```

**L2C5 + FRG5（蓝牙 L2CAP 分片）**
```
L2C5 | 方向(1B: 0x40/0x41) | len(u16) | FRG5 | handle(u16) | conn(u32) | ...
FRG5 | ...
```

**LKT5（蓝牙密钥交换）** ← 题可能问"配对密钥"
```
LKT5 | 0x0500 | 0x22 | 0x01a413 | 0x11082520 | 0x9f060000 | 0x1804 | ...
```

**EL5R（事件日志，NOR）**
```
EL5R | ...
```

**MV6R / AU6R / BCT5 / BOK5（eMMC 内）**
```
MV6R | ...   （测量值/移动记录）
AU6R | ...   （审计单元）
BCT5 | ...   （启动计数/标定）
BOK5 | ...   （书签/检查点）
```

**OTA5（OTA 缓存）**
```
OTA5 | len(u32) | ver(u16) | 0x111a | 0x0000 | crc
```

**NFC5（NFC 读卡器）**
```
NFC5 或 N6FC | ...
```

### 11.3 多介质同一事件的交叉印证

龙信杯的关键：**同一个 ts 出现在 6 个介质里**。

```
ts = 0x0A17C2 (661442)

SSB5 (session_store)       : 会话记录，cred=1698
AUT5 (lock_uart)           : 认证，proto=0x6A2=1698
TEL5 (rtc_trace)           : 遥测，val=1..7 阶段
MOT5 (motor_uart)          : 电机，sub=450
MNR6 (motor_nor)           : 电机 NOR，ts=0x17C2
GWN6 (gateway_capture)     : 网关，ts=0x17C2
```

**判据**：先找出**哪些协议族带 ts 字段**，按 ts 分组，同一 ts 的记录就是同一个事件。

```python
import collections
events = collections.defaultdict(list)
for path, magic, ts_offset, ts_fmt in SCHEMA:
    d = open(path, 'rb').read()
    for m in re.finditer(magic.encode(), d):
        o = m.start()
        ts = struct.unpack(ts_fmt, d[o + ts_offset:o + ts_offset + 4])[0]
        events[ts].append((os.path.basename(path), magic, o))
for ts, items in sorted(events.items()):
    if len(items) >= 3:
        print('ts=0x%08X  证据 %d 处: %s' % (ts, len(items), items))
```

**龙信杯结果**：`0x0A17C2` 命中 6 个介质，这是「目标事件」的铁证。

### 11.4 之前漏掉的原因

我第一版只扫了 `main_soc/device_emmc.raw` 一个文件的几个魔数，漏掉了：
- `gateway/`（GWN6）
- `motor_controller/*_fram.bin` / `*_nor.bin`（MFR6/MNR6）
- `wireless/`（L2C5/FRG5/LKT5）
- `main_soc/ota_cache.bin`（OTA5）
- `lock_mcu/lock_mcu_spi_nor.bin`（EL5R）

**教训**：`os.walk` 扫全部文件，不要凭目录名猜哪个重要。

## 十二、NOR / FRAM / eMMC 的区别

| 介质 | 特点 | 取证要点 |
|---|---|---|
| **eMMC** | 有 GPT/分区表，文件系统 | 按分区找，同 `iot.md` 第二章 |
| **SPI NOR** | 无分区，全片顺序记录 | 从头 `re.finditer(magic)`，注意 `0xff` 填充 |
| **FRAM** | 小容量（几 MB），定长记录环形覆盖 | 找记录的序号回绕点 |
| **I2C 从设备** | 8 MB 定长记录，如 SEV4 | 按记录长度切 |

**判据**：
- 开头全是 `0xff` → SPI NOR 空白区，记录在后面
- 记录序号（seq）会**回绕**（大值跳小值）→ 环形缓冲，最新记录不在末尾

```python
# 找 seq 回绕
seqs = [parse_seq(rec) for rec in records]
for i in range(1, len(seqs)):
    if seqs[i] < seqs[i-1]:
        print('回绕点 @record %d: %d -> %d' % (i, seqs[i-1], seqs[i]))
```

**判据**：「最新一条记录」在环形缓冲里**不是最后一条**，而是回绕点前一条。
