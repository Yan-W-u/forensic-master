# 车联网 / 车载电子取证手册

覆盖：车机（IVI/head unit）、T-Box、IVI eMMC、CAN/CAN-FD 总线抓包、UDS 诊断日志、GPS 轨迹、行车记录仪、充电桩/桩端数据。

---

## 一、检材形态与处理路径

| 检材 | 特征 | 处理 |
|---|---|---|
| **车机 eMMC/NAND 镜像** | `.bin/.img`，GPT 或 raw NAND | 同 `iot.md` 第二章（GPT 分区 + TLV） |
| **T-Box 固件** | `.bin`，常是 UBI/squashfs/ELF | `binwalk -e` / `unsquashfs` / `strings` |
| **CAN 抓包** | `.asc` / `.blf` / `.mf4` / `.trc` / `.log` / `.pcap(ng)` with SocketCAN | `python-can` 的 Reader 系列 |
| **UDS 诊断日志** | 文本或 `.pcap`，含 `22 F1 90` 这类请求 | `udsoncan` 解服务码 |
| **GPS 轨迹** | NMEA-0183 文本、`.gpx`、数据库 | 正则提 `$GPRMC/$GPGGA` |
| **行车记录仪** | MP4 + GPS 内嵌轨道 | `ffprobe` + EXIF |
| **手机 App 侧** | 车辆 App 数据库 | 同 `mobile.md` |

**先判类型再动手**：

```python
SIGS = {
    b'ANDROID!':      'Android boot image',
    b'UBI#':          'UBI (NAND)',
    b'hsqs':          'squashfs (LE)',
    b'sqsh':          'squashfs (BE)',
    b'\x27\x05\x19\x56': 'uImage',
    b'QCDT':          'Qualcomm DT',
    b'\x7fELF':       'ELF 固件',
}
```

---

## 二、CAN 总线抓包分析（核心）

### 2.1 格式识别

| 扩展名 | 格式 | Reader |
|---|---|---|
| `.asc` | Vector ASCII | `can.ASCReader` |
| `.blf` | Vector Binary | `can.BLFReader` |
| `.mf4` / `.mdf` | ASAM MDF4 | `can.MF4Reader`（需 `asammdf`） |
| `.trc` | PEAK TRC | `can.TRCReader` |
| `.log` / `.txt` | candump 格式 | `can.CanutilsLogReader` |
| `.csv` | 自定义 | `can.CSVReader` |
| `.pcap`/`.pcapng` | SocketCAN | `scapy` / `tshark` |
| `.db` / `.sqlite` | can-utils 的 `canlog` | `can.SqliteReader` |

```python
import can
for name, Reader in [('x.asc', can.ASCReader), ('x.blf', can.BLFReader),
                     ('x.log', can.CanutilsLogReader)]:
    with Reader(name) as r:
        for i, msg in enumerate(r):
            print('%.6f  %03X  %s  %s' % (
                msg.timestamp or 0, msg.arbitration_id,
                msg.data.hex(), 'EXT' if msg.is_extended_id else 'STD'))
            if i > 5: break
```

**坑**：`msg.timestamp` 可能是 `None`（candump 日志无时间戳）。统计时序题要先确认时间戳是否存在。

### 2.2 candump 文本格式（最常见）

```
(1612345678.123456) can0 123#DEADBEEF
(1612345678.123456) can0 18DAF110#62F19031323334
                                    ^^ 扩展帧 29 位
```

```python
import re
PAT = re.compile(r'\((\d+\.\d+)\)\s+(\S+)\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]*)')
for line in open('can.log', encoding='utf-8', errors='replace'):
    m = PAT.match(line.strip())
    if not m: continue
    ts, ch, cid, data = m.group(1), m.group(2), m.group(3), m.group(4)
    arb = int(cid, 16)
    ext = len(cid) > 3
    print(float(ts), hex(arb), 'EXT' if ext else 'STD', data)
```

**判据**：
- CAN 2.0 标准帧 ID ≤ `0x7FF`
- 扩展帧 ID ≤ `0x1FFFFFFF`，`len(cid) > 3` 即扩展
- CAN-FD 数据长度可为 12/16/20/24/32/48/64

### 2.3 用 DBC 解码物理值（**最常考的**）

```python
import cantools
db = cantools.database.load_file('vehicle.dbc')   # 也支持 .arxml/.kcd/.sym

# 按帧 ID 找报文
msg = db.get_message_by_frame_id(0x123)
print(msg.name, [(s.name, s.unit, s.scale, s.offset, s.minimum, s.maximum)
                 for s in msg.signals])

# 解一帧
sig = msg.decode(bytes.fromhex('401f922200000000'))
print(sig)   # {'EngineSpeed': 2000.0, 'VehicleSpeed': 88.5}

# 批量解码整个日志
import can
decoded = []
with can.ASCReader('x.asc') as r:
    for m in r:
        try:
            d = db.decode_message(m.arbitration_id, m.data)
            d['_t'] = m.timestamp
            decoded.append(d)
        except KeyError:
            pass   # 该 ID 不在 DBC 里
```

**判据**：
- `scale`/`offset` 决定物理值：`physical = raw * scale + offset`
- `@1+` = Intel（小端），`@0+` = Motorola（大端）
- 题目问「某时刻车速」→ 先按 DBC 找 `VehicleSpeed` 的报文 ID 与信号位置，再按时间戳定位

**没有 DBC 时**：从语义猜——车速字段常在 0–250 区间且随时间平滑变化，转速在 0–8000，档位是枚举小值。

### 2.4 ARXML / KCD / SYM 转换

```python
import canmatrix.formats
# ARXML -> DBC
db = canmatrix.formats.loadp('x.arxml')
canmatrix.formats.dumpp(db, 'out.dbc', 'dbc')
# SYM -> DBC
db = canmatrix.formats.loadp('x.sym')
canmatrix.formats.dumpp(db, 'out.dbc', 'dbc')
```

```powershell
# 命令行
python -m canmatrix.cli.convert -i x.arxml -o out.dbc
```

### 2.5 总线统计类题目

```python
import collections
cnt = collections.Counter()
first, last = {}, {}
for m in can.BLFReader('x.blf'):
    cnt[m.arbitration_id] += 1
    first.setdefault(m.arbitration_id, m.timestamp)
    last[m.arbitration_id] = m.timestamp

# 出现最多的 ID
print(cnt.most_common(10))
# 周期（ms）
for cid, n in cnt.most_common(20):
    if n > 10 and first[cid] and last[cid]:
        period = (last[cid] - first[cid]) / (n - 1) * 1000
        print('%03X  次数=%-6d 周期≈%.1f ms' % (cid, n, period))
```

**判据**：周期稳定在 10/20/50/100/1000 ms 的是正常周期报文；杂乱的是事件触发报文。

---

## 三、UDS 诊断（0x10/0x22/0x27/0x2E/0x31/0x3E）

### 3.1 服务码对照

| 请求 SID | 服务 | 正响应 | 负响应 |
|---|---|---|---|
| `0x10` | DiagnosticSessionControl | `0x50` | `0x7F 10 xx` |
| `0x11` | ECUReset | `0x51` | |
| `0x22` | ReadDataByIdentifier | `0x62` | |
| `0x27` | SecurityAccess | `0x67` | |
| `0x2E` | WriteDataByIdentifier | `0x6E` | |
| `0x31` | RoutineControl | `0x71` | |
| `0x3E` | TesterPresent | `0x7E` | |
| `0x19` | ReadDTCInformation | `0x59` | |
| `0x14` | ClearDiagnosticInformation | `0x54` | |

**判据**：`0x7F` 开头一定是负响应，第 2 字节是原 SID，第 3 字节是 NRC。

### 3.2 常见 NRC

| NRC | 含义 |
|---|---|
| `0x11` | serviceNotSupported |
| `0x12` | subFunctionNotSupported |
| `0x22` | conditionsNotCorrect |
| `0x31` | requestOutOfRange |
| `0x33` | securityAccessDenied |
| `0x35` | invalidKey |
| `0x36` | exceededNumberOfAttempts |
| `0x37` | requiredTimeDelayNotExpired |
| `0x78` | responsePending（不是错误，等后续帧） |

### 3.3 常用 DID（题目常问"读取了什么数据"）

| DID | 内容 |
|---|---|
| `F186` | ActiveDiagnosticSession |
| `F187` | VehicleManufacturerSparePartNumber |
| `F188` | **VIN**（VehicleIdentificationNumber） |
| `F18C` | ECUSerialNumber |
| `F190` | **VIN**（另一种写法，ISO 14229-1 推荐） |
| `F195` | SystemSupplierECUSoftwareVersionNumber |
| `F19E` | ODXFile |

**判据**：`22 F1 90` 的响应 `62 F1 90` 后面 17 字节 ASCII 就是 VIN。

### 3.4 从抓包里提 VIN

```python
import re

def find_vin(payload: bytes):
    """在 UDS 响应里找 17 位 VIN"""
    if len(payload) >= 3 and payload[0] == 0x62 and payload[1:3] in (b'\xf1\x90', b'\xf1\x88'):
        cand = payload[3:20].decode('ascii', 'replace')
        if cand.isalnum():
            return cand
    # 兜底：全文搜 17 位大写字母数字（排除纯数字）
    for m in re.finditer(rb'[A-HJ-NPR-Z0-9]{17}', payload):
        s = m.group().decode()
        if any(c.isalpha() for c in s):
            return s
    return None
```

**VIN 校验**：17 位，第 9 位是校验位，不含 `I/O/Q`。

### 3.5 安全访问（0x27）流程

```
请求 seed:  27 01
响应 seed:  67 01 <seed 4~16B>
发 key:     27 02 <key>
响应:       67 02          （成功）
            7F 27 35       （invalidKey）
```

**题目常问**：「尝试了几次安全访问」「最后是否成功」→ 数 `27 01` 的次数与 `67 02` 的出现。

### 3.6 udsoncan 解日志

```python
from udsoncan import Request, Response
# 需配合 udsoncan.client 或手工判 SID
def parse_uds(data: bytes):
    sid = data[0]
    if sid == 0x7F:
        return ('NEG', hex(data[1]), 'NRC=0x%02X' % data[2])
    table = {0x50: 'SessionCtrl', 0x62: 'ReadDID', 0x67: 'SecurityAccess',
             0x6E: 'WriteDID', 0x71: 'RoutineCtrl', 0x7E: 'TesterPresent',
             0x59: 'ReadDTC', 0x54: 'ClearDTC'}
    return (hex(sid), table.get(sid, '?'), data[1:].hex())
```

---

## 四、GPS 轨迹

### 4.1 NMEA-0183

```
$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A
$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47
```

| 字段 | GPRMC | GPGGA |
|---|---|---|
| 1 | UTC 时间 hhmmss | 同 |
| 2 | 状态 A=有效 V=无效 | — |
| 3,4 | 纬度 ddmm.mmmm + 半球 | 同 |
| 5,6 | 经度 dddmm.mmmm + 半球 | 同 |
| 7 | 速度（节） | — |
| 9 | UTC 日期 ddmmyy | — |

```python
import re

def nmea_to_dec(v: str, hemi: str) -> float:
    """ddmm.mmmm -> 十进制度"""
    if not v: return None
    dot = v.find('.')
    deg = int(v[:dot - 2])
    minutes = float(v[dot - 2:])
    dec = deg + minutes / 60
    return -dec if hemi in ('S', 'W') else dec

PAT = re.compile(r'\$GPRMC,(\d{6})[.,]?([AV])?,([\d.]+),([NS]),([\d.]+),([EW])')
for line in open('gps.txt', encoding='utf-8', errors='replace'):
    m = PAT.search(line)
    if not m: continue
    t, st, lat, ns, lon, ew = m.groups()
    if st != 'A': continue
    print(t, nmea_to_dec(lat, ns), nmea_to_dec(lon, ew))
```

**坑**：`ddmm.mmmm` 不是十进制度，必须先 `deg = int(v[:-7])` 再 `+ rest/60`。直接当小数读会偏差几十公里。

### 4.2 GPX

```python
import xml.etree.ElementTree as ET
ns = {'g': 'http://www.topografix.com/GPX/1/1'}
root = ET.parse('track.gpx').getroot()
for p in root.iterfind('.//g:trkpt', ns):
    print(p.get('lat'), p.get('lon'), p.findtext('g:time', namespaces=ns))
```

### 4.3 从数据库/日志提轨迹

题面问「某时间出现在哪」→ 先找时间列，再按时间排序，取最近点反查地名（需离线地名库或按坐标判省市）。

---

## 五、车机镜像特有位置

| 位置 | 内容 |
|---|---|
| `/data/vendor/` | 车厂数据（高德/百度车机版、语音助手） |
| `/data/local/tmp/` | 调试残留 |
| `/mnt/vendor/persist/` | **VIN、标定参数**（常明文） |
| `/system/etc/` | 配置文件、`*.prop` |
| `/data/misc/bluetooth/` | 配对手机记录 |
| `/data/data/com.android.providers.contacts/` | 同步过的手机通讯录 |
| `/data/data/com.google.android.gms/` | 位置历史（若有） |
| `/data/tombstones/` | 崩溃栈（可能含路径与时间） |

```python
# VIN 常在这些地方
for p in ('/mnt/vendor/persist/vin', '/mnt/vendor/persist/property/vin',
          '/system/etc/vin.cfg', '/data/vendor/vin.txt'):
    ...
```

**判据**：VIN 也可能出现在 `build.prop` 的 `ro.vin`、`ro.serialno` 附近，以及 `/proc/cmdline` 快照里。

### 5.1 T-Box 特有

```
/etc/tbox/          配置、服务器地址、APN
/var/log/tbox/      通信日志（含与 TSP 平台的交互）
/data/tbox/         缓存、证书
```

题目常问「T-Box 上传到哪个服务器」→ 找 `tsp`/`server`/`host` 配置，或日志里的 URL。

### 5.2 证书与密钥

```
*.pem *.crt *.key *.p12 *.jks
```

车联网 mTLS 常见：`client.crt` + `client.key` + `ca.crt`，可能在 `/etc/ssl/` 或固件内嵌。

---

## 六、行车记录仪

```powershell
# 视频流信息（含 GPS 轨道）
ffprobe -v quiet -print_format json -show_format -show_streams rec.mp4

# 提取内嵌 GPS（部分记录仪用 G-sensor + GPS 私有 box）
ffmpeg -i rec.mp4 -map 0:2 -f data gps.bin

# 抽帧 OCR 识别车速/时间水印
ffmpeg -i rec.mp4 -vf "fps=1/5,crop=iw:ih/8:0:0" f%04d.png
```

**判据**：记录仪时间水印常是本地时间，需与文件名/文件系统时间交叉校验。

---

## 七、检查清单

```
□ 检材类型判过（eMMC / T-Box 固件 / CAN 抓包 / UDS 日志 / GPS）
□ CAN 文件格式识别对（asc/blf/mf4/trc/log/pcap）
□ 有 DBC 就先加载 DBC，别手算 scale/offset
□ DBC 的 @1+/@0+ 判过小端/大端
□ CAN-FD 帧长可能是 12/16/20/24/32/48/64，不是固定 8
□ UDS 的 0x7F 是负响应，NRC 0x78 是"等后续"不是错误
□ DID F190/F188 是 VIN，响应 62 F190 + 17 字节 ASCII
□ GPS 的 ddmm.mmmm 转十进制再算距离
□ 时间戳标 UTC / 本地，与文件名、水印交叉校验
□ 车机镜像先找 /mnt/vendor/persist 的 VIN 与标定参数
□ T-Box 找 /etc/tbox 的服务器地址与 APN
```

---

## 八、本机可用工具与库

### Python（全部已验证）

| 库 | 版本 | 用途 |
|---|---|---|
| `python-can` | 4.6.1 | 读 asc/blf/mf4/trc/log/sqlite，`can.Message` 构造 |
| `cantools` | 45.2.0 | **DBC/ARXML/KCD/SYM 解码物理值** |
| `canmatrix` | 1.3.3 | 格式互转（ARXML→DBC、SYM→DBC） |
| `udsoncan` | 1.26.1 | UDS 服务定义、NRC |
| `pyserial` | 3.5 | 串口（直连 OBD 适配器） |
| `obd` | 0.7.3 | ELM327 OBD-II |
| `scapy` | 2.8.0 | `scapy.layers.can`、`CANSocket` |
| `dpkt` | 1.9.8 | 轻量 pcap 解析 |
| `pyshark` | 0.6 | tshark 封装 |
| `lief` | 1.0.0 | ELF/PE/Mach-O 解析 |
| `pyelftools` | 0.33 | ELF 深解析 |
| `unicorn` | 2.1.4 | 固件模拟执行 |
| `pwntools` | 4.15.1 | 二进制利用/ROP |
| `capstone` | 5.0.7 | 反汇编 |
| `frida` | 17.27.3 | 车机 App 动态插桩 |
| `binwalk` | 2.1.0 | 固件解包 |

### GUI / CLI

| 工具 | 路径 | 用途 |
|---|---|---|
| **SavvyCAN** | `D:\ForensicTools\carlink\SavvyCAN\` | CAN 抓包浏览、DBC 解码、图形化 |
| caringcaribou | `D:\ForensicTools\carlink\caringcaribou\` | UDS 扫描、DCM、fuzz（Python） |
| can-utils 源码 | `D:\ForensicTools\carlink\can-utils\` | `candump/cansniffer/cangen` 参考实现 |
| Wireshark | `C:\Program Files\Wireshark\tshark.exe` | pcap 里的 SocketCAN |
| 7z | `C:\Program Files\7-Zip\7z.exe` | 固件解包 |
| strings / objdump / readelf | `E:\bianyiqi\mingw64\bin\` | 固件 ELF 分析 |
| hashcat | `D:\ForensicTools\Toolset\FileDecryptTool\hashcat.exe` | 密钥爆破 |
| VeraCrypt | `D:\ForensicTools\VeraCrypt.exe` | 加密分区 |

### 一条命令核对

```powershell
python "$env:USERPROFILE\.dsh\skills\forensic-master\scripts\toolcheck.py"
```

输出会分三段（Python 库 / 命令行工具 / 命令入口），缺关键项会标 `CRIT` 并给修复命令。

### 装了什么、从哪来的、为什么要装

| 项 | 来源 | 为什么需要 |
|---|---|---|
| `python-can` 4.6.1 | pip 清华源 | **唯一能统一读 asc/blf/mf4/trc/log 的库**，没有替代 |
| `cantools` 45.2.0 | pip | DBC 解码物理值，题目问"某时刻车速"必备 |
| `canmatrix` | pip | ARXML/SYM/KCD → DBC 转换（车厂给的多是 ARXML） |
| `asammdf` | pip | MDF4 是 INCA/CANape 标准输出格式，比赛常给 `.mf4` |
| `udsoncan` | pip | UDS 服务码/NRC 对照，避免手查标准 |
| `scapy` 2.8.0 | pip | `scapy.layers.can` 处理 pcap 里的 SocketCAN |
| `pyserial` / `obd` | pip | 接 ELM327 读实车（有硬件时） |
| **SavvyCAN** 20 MB | GitHub `collin80/SavvyCAN` V220 | GUI 浏览 CAN、波形、DBC 解码，**人眼找异常帧最快** |
| **caringcaribou** v0.7 | GitHub `CaringCaribou` | UDS 服务扫描、DCM、fuzz，CLI 效率高 |
| can-utils 源码 | GitHub `linux-can/can-utils` | Linux 侧 candump/cansniffer 参考实现 |

**GitHub 下载实测（2026-11-20）**：

```
直连 raw.githubusercontent.com  1.4 s / 5.8 KB   ✅ 可用
ghfast.top 镜像                  2.1 s           可用但更慢
gh-proxy.com 镜像                3.9 s           可用但更慢
```

→ **直连最快，不要套代理**。用 aria2 多线程：

```powershell
$aria='D:\ForensicTools\aria2\aria2-1.37.0-win-64bit-build1\aria2c.exe'
& $aria --no-conf --max-connection-per-server=8 --split=8 `
   --out SavvyCAN.zip `
   'https://github.com/collin80/SavvyCAN/releases/download/V220/SavvyCAN-Windows_x64_CIBuild.zip'
```

**坑**：先查 release 的真实资产名，别猜。

```powershell
(Invoke-RestMethod 'https://api.github.com/repos/collin80/SavvyCAN/releases/latest').assets |
  Select-Object name, @{n='MB';e={[math]::Round($_.size/1MB,1)}}
```

我第一版猜 `SavvyCAN-Win64.zip`，404；真名是 `SavvyCAN-Windows_x64_CIBuild.zip`。

**坑**：`caringcaribou` 用相对导入（`from .utils import ...`），**不能直接 `python caringcaribou.py`**，
必须装成包：

```powershell
cd D:\ForensicTools\carlink\caringcaribou\caringcaribou-master
python -m pip install --no-build-isolation -e .
# 之后用 caringcaribou.exe
```

**坑**：`asammdf` 会把 `canmatrix` 从 1.3.3 降到 1.2。1.2 仍有 `loadp/dumpp`，转换功能正常，
但如果你依赖 1.3 的新 API 会被破坏。装完跑一次 `canmatrix.formats.loadp` 验证。


## 九、车载以太网（DoIP / SOME-IP / AVB）

新车普遍用以太网替代 CAN。**抓包仍是 pcapng，但协议完全不同**。

### 9.1 DoIP（Diagnostic over IP，ISO 13400）

| 项 | 值 |
|---|---|
| 端口 | **TCP/UDP 13400** |
| 用途 | 以太网上的 UDS 传输（UDS on IP） |
| 报文头 | `02 FD | type(2) | len(4) | payload` |

**payload type**：

| 值 | 含义 |
|---|---|
| `0x0000` | Generic DoIP header NACK |
| `0x0001` | Vehicle identification request |
| `0x0004` | Vehicle announcement / identification response |
| `0x0005` | Routing activation request |
| `0x0006` | Routing activation response |
| `0x8001` | **Diagnostic message**（里面就是 UDS 的 0x10/0x22/0x27） |
| `0x8002` | Diagnostic message positive ack |
| `0x8003` | Diagnostic message negative ack |

```python
# 从 DoIP 里剥出 UDS
def doip_payload(pkt):
    if pkt[:2] != b'\x02\xfd':
        return None
    t = int.from_bytes(pkt[2:4], 'big')
    ln = int.from_bytes(pkt[4:8], 'big')
    body = pkt[8:8+ln]
    if t == 0x8001:
        # body = src_addr(2) | tgt_addr(2) | UDS...
        return body[4:]
    return None
```

**判据**：题问「用哪个协议传输 UDS」→ DoIP；「诊断端口」→ 13400。

### 9.2 SOME/IP

| 项 | 值 |
|---|---|
| 端口 | 自定义（常见 30490、30500+） |
| 报文头 | `msgid(4) | length(4) | reqid(4) | proto_ver(1) | iface_ver(1) | msg_type(1) | ret(1) | payload` |

**msg_type**：

| 值 | 含义 |
|---|---|
| `0x00` | REQUEST |
| `0x01` | REQUEST_NO_RETURN |
| `0x02` | NOTIFICATION |
| `0x80` | RESPONSE |
| `0x81` | ERROR |

```python
def someip_parse(d):
    if len(d) < 16:
        return None
    msgid = int.from_bytes(d[0:4], 'big')
    length = int.from_bytes(d[4:8], 'big')
    reqid = int.from_bytes(d[8:12], 'big')
    mtype = d[14]
    return dict(service=msgid >> 16, method=msgid & 0xffff,
                client=reqid >> 16, session=reqid & 0xffff,
                type=mtype, payload=d[16:])
```

**判据**：题问「哪个服务 ID」→ `msgid >> 16`；「方法 ID」→ `msgid & 0xffff`。

### 9.3 AVB / TSN（音视频桥）

| 协议 | EtherType | 用途 |
|---|---|---|
| AVTP | `0x22F0` | 音视频传输 |
| gPTP | `0x88F7` | 时间同步（**取证时要校准时钟**） |
| SRP | `0x22EA` | 流预留 |

**判据**：多设备时钟不一致时，先看 `gPTP` 的 sync 报文校准，否则时间线会错。

## 十、传感器融合与多源时间线

现代车辆的关键事件会在**多个 ECU 同时留痕**。这是汽车取证的核心方法。

### 10.1 五类时间源

| 源 | 精度 | 特点 |
|---|---|---|
| CAN 报文时间戳 | ms | 抓包工具打的，可能漂移 |
| ECU 内部 RTC | s | 断电归零，需校准 |
| GPS 时间 | μs | **最可信**，可作基准 |
| gPTP | ns | 车载以太网里最准 |
| 手机/GPS 轨迹 | s | 外部参照 |

**判据**：先确定一个**可信基准**（GPS 或 gPTP），再算其他源的偏移。

### 10.2 碰撞/急刹事件的多源印证

```
安全气囊 ECU : 碰撞信号（CAN ID 常见 0x0A0-0x0FF）
ESP/ABS ECU  : 轮速骤降 + 制动压力
发动机 ECU   : 转速骤降、节气门关闭
变速箱 ECU   : 档位变化
车身 ECU     : 车门解锁、双闪
T-Box        : 上报 eCall / 位置
行车记录仪    : G-sensor 触发 + 视频
```

**方法**：把这七条时间线画在同一坐标轴上，找**共同的时间窗**（通常 100–300 ms 内）。

```python
# 自动找共同时间窗
import collections
events = collections.defaultdict(list)   # ts -> [(source, event)]
WINDOW = 0.3   # 300 ms
cands = []
allts = sorted(events)
for i, t0 in enumerate(allts):
    hits = [(src, ev) for t in allts[i:] if t - t0 <= WINDOW
            for src, ev in events[t]]
    srcs = {s for s, _ in hits}
    if len(srcs) >= 3:
        cands.append((t0, len(srcs), hits))
```

### 10.3 里程表核对（最常见的矛盾）

```
仪表里程  ← 车身 ECU
ECU 里程   ← 发动机 ECU
T-Box 里程 ← 云端上报
保养记录   ← 4S 店系统
```

**判据**：四个值不一致 → 存在**里程篡改**或仪表更换。
差异方向和大小能区分：
- 全部偏小且差值相同 → 统一改写
- 某几个偏小 → 换过仪表/ECU

## 十一、充电桩与新能源特有

### 11.1 充电记录位置

| 位置 | 内容 |
|---|---|
| 车机 `/data/vendor/charge/` | 充电历史 |
| BMS ECU | 电池循环、SOC 曲线 |
| 充电桩日志 | 充电会话（时间、电量、卡号） |
| 云端 App | 订单、支付记录 |

**判据**：题问「某时间在哪充电」→ 车机日志 + 充电桩日志 + 支付记录三方对照。

### 11.2 电池数据

| 项 | 说明 |
|---|---|
| SOH | 健康度（%） |
| 循环次数 | 完整充放次数 |
| 单体电压差 | 判断是否换过电池 |
| 生产批次码 | 电池包身份 |

**判据**：SOH 与里程不匹配 → 电池被更换或数据被改。

### 11.3 充电桩侧检材

```
/app/logs/        充电会话日志
/app/data/*.db    本地数据库（卡号、余额）
/app/config/      服务器地址、密钥
```

**判据**：题问「谁用了这个桩」→ 卡号/手机号；「充了多少」→ 会话表。

## 十二、T-Box 深挖

### 12.1 T-Box 的关键作用

T-Box = Telematics Box，车上唯一**联网**的盒子。它记录：

| 数据 | 位置 |
|---|---|
| 上报的 TSP 服务器 | `/etc/tbox/*.conf` 的 `server`/`host` |
| APN / SIM | `/etc/tbox/apn.conf`、`/data/tbox/sim` |
| 上报日志 | `/var/log/tbox/` |
| 缓存的位置/状态 | `/data/tbox/cache/` |
| 证书 | `/etc/tbox/certs/`（mTLS） |

### 12.2 从 T-Box 日志还原轨迹

```
/var/log/tbox/upload.log
  [时间] POST https://tsp.example.com/api/pos  {"lat":..,"lon":..,"spd":..}
```

**判据**：题问「车去过哪」→ T-Box 上报日志比 GPS 轨迹更可靠（GPS 可被伪造，上报日志有服务器时间戳）。

### 12.3 SIM / IMEI / ICCID

| 项 | 位置 |
|---|---|
| IMEI | `/data/tbox/imei` 或 AT 命令回显 |
| ICCID | `/data/tbox/iccid` |
| IMSI | `/data/tbox/imsi` |

**判据**：题问「哪张卡」→ ICCID（20 位）；「设备身份」→ IMEI（15 位）。

## 十三、汽车取证标准流程

```
1. 断电前：抓取易失数据（RAM、正在写的日志）
2. 断电：按厂家规程（有的要先进入运输模式）
3. 镜像：
   ├─ 车机 eMMC/NAND（拆片或 ISP）
   ├─ T-Box 固件
   ├─ ECU 的 Flash（需 OBD 或拆片）
   └─ 行车记录仪 SD 卡
4. 总线抓包（若有条件）：
   ├─ OBD-II 口（CAN 6/14，CAN-FD 视车型）
   ├─ 网关直连（绕过 OBD 过滤）
   └─ 车载以太网（需专用的 100BASE-T1 转换器）
5. 分析顺序：
   ├─ 时间基准（GPS / gPTP）
   ├─ 多源时间线对齐
   ├─ 关键事件窗定位
   └─ 矛盾点（里程、时间、位置）
```

**判据**：「原始数据」优先于「解析后数据」；「多源一致」优先于「单源可信」。

## 十四、检查清单补充

```
□ 以太网流量：DoIP(13400) / SOME-IP / AVB 查过吗
□ 时间基准统一了吗（GPS / gPTP）
□ 多源时间线画在同一坐标轴了吗
□ 里程四源核对过吗（仪表/ECU/T-Box/保养）
□ 新能源：充电记录三方对照了吗
□ T-Box 上报地址与 SIM 查过吗
□ 传感器事件窗（碰撞/急刹）找过共同时间窗吗
```


## 相关章节

- `iot.md` —— eMMC / 固件 / TLV 通用方法
- `network.md` —— 车载以太网 / DoIP
- `mobile.md` —— 车机 App 数据
- `containers.md` —— 固件加密
- `traps.md` —— 字节序与多版本陷阱
