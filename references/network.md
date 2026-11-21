# 网络流量取证手册

## 一、工具与环境

```powershell
# tshark 路径
C:\Program Files\Wireshark\tshark.exe
```

常用导出：
```powershell
# 基本信息
tshark -r x.pcapng -q -z io,phs

# 提取 HTTP 请求
tshark -r x.pcapng -Y "http.request" -T fields -e frame.number -e ip.src -e http.host -e http.request.uri

# 导出对象
tshark -r x.pcapng --export-objects http,out_dir
```

## 二、菜单式题型

### 2.1 找明文凭据

```
http.request.method == "POST" && frame contains "password"
```

或直接：
```
frame contains "admin"
```

**要看响应是否成功**：`http.response.code == 200/302` 才算真登录。401 说明密码错（但明文仍是攻击者输入的真实值，题目常问"该密码为何"）。

### 2.2 统计某类请求笔数

```
http.request.method == "POST" && http.request.uri contains "/transaction/submit"
```

数结果行数。**注意**：
- 只算**成功**的（响应 200/201），失败的不算
- 多份 pcap 要合并统计（`-r` 不能接多个，用 `mergecap` 先合并，或分别统计再相加）
- 重复提交（同 IP 同金额）要判断是否为重传

### 2.3 求金额总和

```
tshark -r x.pcapng -Y "http.request.uri contains \"/transaction/submit\"" -T fields -e frame.number -e http.file_data
```

解 URL 编码或 JSON，累加金额字段。

**坑**：笔数错了金额必然错。先确认笔数。

### 2.4 提取表单字段

```python
import urllib.parse
body = "...name=Wong+Si+Fu&hkid=R345789(0)&amount=500000..."
d = urllib.parse.parse_qs(body)
```

JSON 体直接 `json.loads`。

### 2.5 用户代理判别浏览器

```
http.user_agent
```

| UA 特征 | 浏览器 |
|---|---|
| `Safari/605.1.15` + `Version/18.x` + `Mobile/` | iOS Safari |
| `CriOS/` | iOS Chrome |
| `Chrome/xxx` 无 `Safari/` 前缀 | Chrome |
| `Edg/` | Edge |
| `Firefox/` | Firefox |
| `MSIE` 或 `Trident/` | IE |

**坑**：iPhone 上的 Chrome 也会带 `Safari/` 字样，但会有 `CriOS/`。真 Safari 没有 `CriOS/`。

### 2.6 客户端 IP

```
ip.src && http.request
```

注意 NAT/代理：题目问"客户端 IPv4"通常指 `ip.src` 的原始值（可能是内网 `172.18.0.x`）。

### 2.7 特殊编码格式识别

```
http.content_type
```

| Content-Type | 格式 | 题面选项 |
|---|---|---|
| `application/x-www-form-urlencoded` | 表单 | Plain Text / Form |
| `application/json` | JSON | JSON |
| `application/xml` / `text/xml` | XML | XML |
| `application/x-protobuf` / `application/grpc` | Protobuf | Protobuf |
| `application/yaml` / `text/yaml` | YAML | YAML |

**判别 JSON 的特征**：包体是 `{"key":"value"}` 形式，Content-Type 也是 json。

## 三、DNS 分析

### 3.1 SRV 记录（服务发现）

```
dns.qry.type == 33          # SRV
dns.srv.port                # 端口字段
frame contains "teamviewer"
```

TeamViewer 的 mDNS 宣告：
```
_teamviewer._tcp.local  SRV  0 0 2020 hostname.local
```
→ 端口 2020

**坑**：SRV 记录里的 `0 0 2020` 分别是 priority/weight/port，要取**第 3 个数**。

### 3.2 mDNS / Bonjour

```
dns.flags.response == 0 && udp.port == 5353
```

### 3.3 域名解析记录

```
dns.qry.name
```

## 四、DHCP 分析

### 4.1 找某主机的分配 IP

```
dhcp.option.hostname contains "AE4A0O6"
```

拿到 MAC 后：
```
dhcp.hw.mac_addr == 20:79:18:dd:8b:eb
```

看 DHCP ACK（`dhcp.option.dhcp == 5`）里的 `dhcp.ip.your`。

### 4.2 DHCP 状态码

| 值 | 含义 |
|---|---|
| 1 | DISCOVER |
| 2 | OFFER |
| 3 | REQUEST |
| 5 | **ACK**（最终分配） |
| 6 | NAK |

**坑**：DISCOVER/OFFER 阶段的 IP 是候选，最终以 ACK 为准。

## 五、TCP 会话重建

### 5.1 跟随流

```powershell
tshark -r x.pcapng -q -z follow,tcp,ascii,<stream_index>
```

先用 `-T fields -e tcp.stream` 找流号。

### 5.2 统计会话

```
tcp.flags.syn == 1 && tcp.flags.ack == 0      # SYN 包数 = 连接尝试数
```

## 六、加密流量

### 6.1 TLS 基本信息

```
tls.handshake.extensions_server_name     # SNI
tls.handshake.type == 1                  # ClientHello
```

### 6.2 解密（有密钥时）

```powershell
$env:SSLKEYLOGFILE = "keys.log"
# 或 tshark 指定
tshark -r x.pcapng -o tls.keylog_file:keys.log
```

RSA 私钥：
```powershell
tshark -r x.pcapng -o "tls.keys_list:1.2.3.4,443,http,server.key"
```

### 6.3 判断是否为加密流量

- 端口 443 + TLS 握手 → HTTPS
- 端口 53 + 明文 → DNS
- 端口 2020 或随机高端口 + 二进制 → 常见远控

## 七、常见协议端口

| 端口 | 协议 |
|---|---|
| 53 | DNS |
| 67/68 | DHCP |
| 80 | HTTP |
| 443 | HTTPS |
| 2020 | TeamViewer |
| 3389 | RDP |
| 445 | SMB |
| 5353 | mDNS |
| 5938 | TeamViewer（备用） |
| 7070 | RealServer |
| 3000 | 常见 Node.js 应用 |

## 八、Docker/容器网络

pcap 里若出现：
- `172.18.0.1` → Docker 网桥网关（宿主机侧）
- `172.18.0.x` → 容器 IP
- `192.168.x.x` → 物理内网

**判别**：同一段 `172.1x.0.0/16` 通常是 Docker 默认网段。

## 九、pcapng 多文件处理

```powershell
# 合并
& 'C:\Program Files\Wireshark\mergecap.exe' -w merged.pcapng a.pcapng b.pcapng c.pcapng

# 按时间切分
& 'C:\Program Files\Wireshark\editcap.exe' -A "2026-08-06 11:00:00" -B "2026-08-06 12:00:00" in.pcapng out.pcapng
```

## 十、tshark 输出格式化

### 10.1 字段导出 CSV

```powershell
tshark -r x.pcapng -Y "<filter>" -T fields `
  -e frame.number -e frame.time -e ip.src -e ip.dst -e http.request.uri `
  -E header=y -E separator=, -E quote=d > out.csv
```

### 10.2 与 Python 配合

```python
import subprocess, csv, io
cmd = ['tshark','-r','x.pcapng','-Y','http.request','-T','fields',
       '-e','frame.number','-e','ip.src','-e','http.request.uri']
out = subprocess.run(cmd, capture_output=True, text=True).stdout
for line in out.splitlines():
    parts = line.split('\t')
```

## 十一、自定义 / 私有协议（含蜜罐）

出题人爱用自定义 ASCII 前缀协议，还会**故意混入干扰协议**。龙信杯 360 MB pcapng 里同时存在 `TLM4`（11835 条，纯干扰）、`HBG6`（194552 条，纯噪声）、`IN7`/`UI7`/`PMU7`（真正要答的）。

### 11.1 第一步：不要全量解析，先做前缀分布

```python
import subprocess, re, collections
cmd = ['tshark','-r',pcap,'-T','fields','-e','frame.number','-e','frame.interface_name',
       '-e','ip.src','-e','ip.dst','-e','data.data','-E','separator=|']
rows = []
for ln in subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines():
    p = ln.split('|')
    if len(p) < 5 or not p[4]: continue
    try: b = bytes.fromhex(p[4])
    except Exception: continue
    rows.append((int(p[0]), p[1], p[2], p[3], b))

c = collections.Counter()
for num, iface, src, dst, b in rows:
    m = re.match(rb'([A-Za-z][A-Za-z0-9_\-]{1,14})', b)
    if m and m.group(1).isascii():
        s = m.group(1).decode()
        if sum(ch.isupper() or ch.isdigit() for ch in s) >= 2:
            c[s] += 1
for k, v in c.most_common(50):
    print('%-18s %d' % (k, v))
```

**判据**：前缀数量**最多**的那几个通常是背景噪声/干扰；前缀数量**少但成对出现**的才是题目要的（一问一答）。

### 11.2 第二步：按题面关键词定位

题面写「控制会话」「nonce」「规范输入」「主机见证」「事务」「回绕」，就直接在这些行里 grep：

```python
KEY = [b'nonce', b'canon', b'digest', b'witness', b'SCHEMA', b'RULE',
       b'cumulative', b'TSN', b'wrap', b'TX']
for num, iface, src, dst, b in rows:
    if any(k in b[:200] for k in KEY):
        print(num, iface, src, '->', dst, b.decode('latin1')[:200])
```

在这批行里会出现**规则声明帧**，例如：

```
PMUSCHEMA7 min_us=200 max_us=25000 rule=sha256(input_digest|"pmu7"|retired)[:24]
SIDSCHEMA4 data=4 shard_bytes=4 p4=d0^d1^d2^d3 p5=d0^rol1(d1)^rol2(d2)^rol3(d3)
```

**这些规则帧就是判分口径**，一定要先找到并抄下来。

### 11.3 第三步：按 nonce / 会话聚合

```python
by_nonce = collections.defaultdict(list)
for x in IN_FRAMES:
    by_nonce[x['nonce']].append(x)
for nonce, v in by_nonce.items():
    print(nonce, len(v), sorted(set(x['src'] for x in v)),
          v[0]['t'], '..', v[-1]['t'])
```

### 11.4 判"真实会话"的四种手段

| 题面线索 | 判据 |
|---|---|
| "真实控制终端" | **只有它出现在核心接口（如 `tap-core`）**；其他只在边缘接口（如 `tap-remote`）→ 影子会话 |
| "摘要正确" | 按规则帧的公式复算，`sha256(input_digest\|"pmu7"\|retired)[:24]` 与 PMU7.digest 相等 |
| "见证早于最后一条输入" | `UI7.timestamp - last(IN7).timestamp < 0` |
| "见证超出允许上界" | `UI7.timestamp - last(IN7).timestamp > 上界`，上界在规则帧或 schema 里 |

**实测（龙信杯）**：

| 会话源 IP | nonce | UI7摘要 vs PMU | 见证-末输入 | 在 tap-core |
|---|---|---|---|---|
| 198.51.100.201 | 672823595ed5c1eb | 无 UI7 | — | **是（唯一）** |
| 198.51.100.202 | e2b79b5c2bfd1b61 | OK | −182.7 ms | 否 |
| 198.51.100.203 | b2e353286e2bba68 | MISMATCH | −162.9 ms | 否 |
| 198.51.100.204 | 5acda53cd2afcb64 | **OK** | **−168.1 ms** | 否 |
| 198.51.100.205 | b2b3364801b84d0a | MISMATCH | +60.9 ms | 否 |
| 198.51.100.206 | d14eeb6a492de491 | **OK** | **+196.1 ms** | 否 |
| 198.51.100.207 | 4304c3d9a80f3d32 | MISMATCH | +61.2 ms | 否 |
| 198.51.100.208 | d0c2fe10c5258f92 | MISMATCH | +61.4 ms | 否 |

→ 真实控制端 = `.201`；"摘要正确且见证早于末输入" = `.204`；"超出上界" = `.206`。

### 11.5 摘要链的正确复算

摘要规则常是**两段**：

```
input_digest = sha256(规范输入原文)      ← 由 UI7 帧宣告
pmu_digest   = sha256(input_digest|"pmu7"|retired)[:24]
```

**只用第二段就能验证"PMU 与规范输入是否一致"**——把 UI7 的 digest 当 `input_digest` 代入即可，**不需要复现规范输入的逐字节排版**。龙信杯就是靠这一步锁定 3 个"摘要一致"的会话。

```python
import hashlib
got = hashlib.sha256((ui7_digest + '|pmu7|' + retired).encode()).hexdigest()[:24]
ok = (got == pmu7_digest)
```

### 11.6 时钟阶跃（多 tap 时钟域）

同一份 pcapng 里多个接口可能来自**不同时钟域**，`CLK7` 这类帧用于校准：

```
CLK7 tap=1 seg=0 host_ns=2550000000 seq=2550
CLK7 tap=1 seg=1 host_ns=3050000000 seq=3050
```

计算某个 tap 在某个 seg 的**捕获偏移**：

```python
offset = frame.time_epoch - host_ns / 1e9
```

阶跃 = `mean(seg1.offset) - mean(seg0.offset)`，单位秒，题面要微秒就 ×1e6：

```
seg0 offsets: 1788576300.181311 / .181815 / .182151  → mean 1788576300.181759
seg1 offsets: 1788576299.958256 / .957824 / .957419  → mean 1788576299.957833
差 = -0.223926 s = -223926 us
单点算（末条seg0 → 首条seg1）= -223895 us
```

**坑**：两种算法差几十微秒。题面没说用哪种时，**优先单点**（跨越切换点的那一对帧），并在备注里写另一种。

### 11.7 蜜罐 flag

大流量题常见 `flag{...}` 明文，**几乎全是诱导**。判据：

- flag 出现在与题面无关的协议载荷里 → 干扰
- flag 内容是对某个错误结论的陈述（`flag{latest_version_always_wins}`）→ 反向提示
- 同一处载荷里连着出现 6–8 个 flag → 整组都是干扰

**真答案要从数据算出来，不是搜出来的。**

### 11.8 时序/回绕类题目

题面出现 "cumulative TSN"、"回绕"、"I-DATA"、"未进入 core"，**先确认是不是真的 SCTP**。

```powershell
# 1) 协议分布（SCTP 是 IP proto 132）
tshark -r x.pcapng -T fields -e ip.proto | Group-Object | Select Count,Name
#   6=TCP  17=UDP  132=SCTP

# 2) 拉 SCTP 帧
tshark -r x.pcapng -Y sctp -T fields -e frame.number -e sctp.chunk_type -e sctp.data_tsn_raw
```

**chunk_type 对照**

| 值 | 类型 | 关键字段 |
|---|---|---|
| 1 | INIT | `sctp.init_initial_tsn` |
| 2 | INIT-ACK | `sctp.initack_initial_tsn` |
| 3 | SACK | `sctp.sack_cumulative_tsn_ack_raw` |
| **64** | **I-DATA** | `sctp.data_tsn_raw` / `sctp.data_mid` / `sctp.data_sid` |
| 194 | I-FORWARD-TSN | **`sctp.i_forward_tsn_tsn`** |

**Q64「放弃回绕后首个消息的新 cumulative TSN」** → 找 `chunk_type=194` 的 `i_forward_tsn_tsn`。

**Q65「未进入 tap-core、处于回绕前夜」的 I-DATA 标识**，判据三条同时满足：
1. MID 从 `0xFFFFFFFF` 跳到 `0`（或从大值跳小值）
2. 该段全部帧的 `frame.interface_name` **不含 core**
3. `sctp.data_mid` 就是题面要的"消息标识"

龙信杯实测（sid=0x0003 一条流）：
```
MID=0xFFFFFFFE  tsn 900000..900213  214片  全 tap-core
MID=0xFFFFFFFF  tsn 900214..900427  214片  全 tap-office   ← Q65 答案 4294967295
MID=0            tsn 900428..900641 214片  全 tap-core
```

**致命坑：`tshark -T fields` 里只要有一个字段名无效，整条命令静默返回 0 行**——返回码 0、stdout 空、stderr 空，看起来像"过滤器没命中"。

```powershell
# 排查：一次只测一个字段
foreach($f in 'sctp.data_sid','sctp.data_mid','sctp.i_forward_tsn_mid'){
  $o = & tshark -r x.pcapng -Y sctp -T fields -e frame.number -e $f 2>&1
  "{0,-32} {1}" -f $f, $(if($o.Count -gt 0 -and $o[0] -notmatch 'valid'){"OK"}else{"INVALID"})
}
```

龙信杯实测 `sctp.i_forward_tsn_mid` **不存在**（Wireshark 4.x），导致我浪费了三轮。正确做法是先查字段表：

```powershell
& tshark -G fields 2>&1 | Select-String 'sctp\.' | Select-String 'tsn|mid|ppid|cum'
```

若搜不到关键字，说明该协议用了非标准字段名，**回到 11.2 用题面的中文概念去反推英文缩写**（cumulative → `cum`/`cumtsn`/`cts`；I-DATA → `idata`/`idat`/`IM`）。

## 十二、常见失分点

1. **笔数与金额强关联**：笔数错 → 金额必错。先确认笔数。
2. **多份 pcap 漏统计**：题目说"该批侧录封包"，通常是**全部** pcapng。
3. **把失败请求算进去**：4xx/5xx 响应不算"成功提交"。
4. **SRV 端口取错位**：是第 3 个数字，不是第 1 个。
5. **DHCP 取 OFFER 而非 ACK**。
6. **UA 误判**：iPhone Chrome 有 `CriOS/`，别当成 Safari。

## 十三、协议伪装识别（龙信杯实测）

**核心陷阱**：`tshark -z io,phs` 会按**端口**猜测协议。端口 53 的流量被标成 `dns`，
但实际载荷根本不是 DNS。

### 13.1 症状

```
Protocol Hierarchy Statistics
  udp   frames:288889
    dns frames:27101 bytes:18348829
      _ws.malformed   frames:27101      ← 100% malformed
    mdns frames:6021
      _ws.malformed   frames:6021       ← 100% malformed
```

**`_ws.malformed` 占比 100% = 这不是该协议**，只是端口撞上了。

### 13.2 三步确认真伪

```powershell
# 1) 按协议过滤，看关键字段是否为空
tshark -r x.pcapng -Y 'dns' -c 6 -T fields -e frame.number -e dns.qry.name -e data.data
```

龙信杯实测输出：

```
1    <空>   <空>
2    <空>   <空>
3    <空>   <空>
```

**`dns.qry.name` 空 + `data.data` 也空** → 载荷被上层解析器吃掉了，但没解析出真 DNS 结构。

```powershell
# 2) 用 -V 看完整结构
tshark -r x.pcapng -Y 'dns' -c 3 -V | Select-String 'UDP|Length|DNS'
```

实测：

```
User Datagram Protocol, Src Port: 27398, Dst Port: 53
    Length: 221
```

**UDP 长度 221，但没有任何 DNS 字段** → 伪装确认。

```powershell
# 3) 导出子集，用 raw 看载荷
tshark -r x.pcapng -Y 'dns' -c 30 -w subset.pcapng
tshark -r subset.pcapng -T fields -e data.data
```

### 13.3 判据表

| 现象 | 结论 |
|---|---|
| `io,phs` 显示协议 X，但 100% `_ws.malformed` | 端口伪装，不是协议 X |
| `-Y x` 能选出帧，但 `x.*` 字段全空 | 同上 |
| `-T fields -e data.data` 也空 | 载荷被协议解析器"消耗"了 |
| UDP 长度正常但无结构字段 | 自定义二进制协议 |

**正确做法**：把 `data.data` 换成 `udp.payload` 或直接读原始帧：

```powershell
# udp.payload 不会被上层解析器吃掉
tshark -r x.pcapng -Y 'udp.dstport eq 53' -T fields -e udp.payload
```

### 13.4 tshark 的输出开关坑

**`-Y` 里的 `==` 在 PowerShell 下会被吞**：

```powershell
# ❌ 返回 0 行
tshark ... -Y "udp.dstport==53" -T fields ...

# ✅ 用 eq，或单引号包住
tshark ... -Y 'udp.dstport eq 53' -T fields ...
```

**`-T fields` 里任一字段名无效 → 整条静默返回 0 行**（见 traps 陷阱 33）：

```powershell
# 排查：逐字段测
foreach($f in 'dns.qry.name','dns.flags.response','sctp.data_mid'){
  $o = & tshark -r x.pcapng -Y 'frame' -c 1 -T fields -e $f 2>&1
  "{0,-30} {1}" -f $f, $(if($o[0] -notmatch 'valid'){'OK'}else{'INVALID'})
}
```

**Python `subprocess` 读 tshark stdout 会丢数据**（龙信杯实测）：

```python
# ❌ 同一命令，PowerShell 里有 4 行，Python 里 0 行
r = subprocess.run([T, '-r', P, '-Y', 'dns', '-T', 'fields', '-e', 'frame.number'],
                   capture_output=True, text=True)
print(len(r.stdout.splitlines()))    # 0

# ✅ 先落文件再读
subprocess.run(f'{T} -r {P} -Y dns -T fields -e frame.number > out.txt', shell=True)
lines = open('out.txt').read().splitlines()
```

或者显式指定编码：

```python
r = subprocess.run(cmd, capture_output=True)
text = r.stdout.decode('utf-8', 'replace')
```

## 十四、流量分析的通用套路（按题面措辞索引）

题面的每个词都指向一个固定动作。**先看措辞，再选工具**。

| 题面措辞 | 动作 | 命令 |
|---|---|---|
| 「明文」「未加密」 | 过滤纯文本协议 | `-Y 'http or ftp or telnet'` |
| 「几个」「合计」「最多」 | 全量统计，不能抽检 | `-T fields -e xxx \| Group-Object` |
| 「第一次」「最后」 | 按时间排序取首尾 | `-T fields -e frame.time_epoch` |
| 「哪个主机」「IP」 | IP 会话对统计 | `-T fields -e ip.src -e ip.dst` |
| 「用了什么软件」 | User-Agent | `-e http.user_agent` |
| 「密码」「凭据」 | POST 表单 / Basic Auth | `-e http.authorization` `-e http.file_data` |
| 「下载了什么」 | 响应体 + Content-Type | `-e http.content_type` `-e http.request.uri` |
| 「是否存在」 | 帧计数 | `-Y 'xxx' \| Measure-Object` |
| 「跳数」「延迟」 | 时间差 | 相邻帧 `frame.time_delta` |
| 「真实」「伪装」 | 看 `_ws.malformed` 比例 | `-z io,phs` |

### 14.1 快速体检（每条流量检材第一步）

```powershell
$T = 'C:\Program Files\Wireshark\tshark.exe'
$P = 'x.pcapng'

# 1) 规模
& $T -r $P -q -z io,stat,0

# 2) 协议层级（看 malformed 比例）
& $T -r $P -q -z io,phs

# 3) 端点
& $T -r $P -q -z endpoints,ip

# 4) 会话
& $T -r $P -q -z conv,tcp
```

**判据**：先看 `io,phs` 里有没有 100% malformed 的分支——有就是伪装或自定义协议。

### 14.2 批量字段导出模板

```powershell
& $T -r $P -T fields `
  -e frame.number -e frame.time_epoch -e ip.src -e ip.dst `
  -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport `
  -e _ws.col.Protocol -e frame.len -e data.data > all.tsv
```

**字段数不要超过 15 个**，否则容易撞上无效字段名导致全空。

### 14.3 时间相关题的标准算法

```python
import datetime
# pcapng EPB 时间戳单位是微秒
ts_us = (ts_hi << 32) | ts_lo
dt = datetime.datetime.fromtimestamp(ts_us / 1e6, datetime.timezone.utc)

# pcap（老格式）也是微秒，但要注意有些工具写的是纳秒
# 判据：时间落在 1970 附近 → 单位错了
```

**判据**：算出来的时间若是 1970 年，说明把微秒当纳秒（或反过来）了。

### 14.4 流重组与文件提取

```powershell
# 列出所有 HTTP 对象
& $T -r $P --export-objects http,out/

# 列出所有 SMB 对象
& $T -r $P --export-objects smb,out/

# 单个流的内容
& $T -r $P -q -z follow,tcp,ascii,0
```

**判据**：`--export-objects` 会自动还原文件名，比手工拼流快得多。

### 14.5 大文件处理

```powershell
# 先切分再分析（比直接读全量快）
& 'C:\Program Files\Wireshark\editcap.exe' -c 100000 big.pcapng part.pcapng

# 只看某时间窗口
& 'C:\Program Files\Wireshark\editcap.exe' -A '2026-09-01 00:00:00' -B '2026-09-02 00:00:00' in.pcapng out.pcapng

# 合并多个
& 'C:\Program Files\Wireshark\mergecap.exe' -w merged.pcapng a.pcapng b.pcapng
```

**判据**：超过 500 MB 的 pcap 先 `editcap` 切分，或用 `-Y` 导子集，不要硬跑。

### 14.6 常见失分点补充

| 失分点 | 正确做法 |
|---|---|
| 用端口判断协议 | 看 `io,phs` 的 malformed 比例 |
| `-Y` 用 `==` | PowerShell 下用 `eq` |
| `-T fields` 一次堆 20 个字段 | 分批或先验字段名 |
| Python 直接读 stdout | 先落文件 |
| 时间戳单位靠猜 | 算出来看年份对不对 |
| 统计题抽检 | 全量 `Group-Object` |
| 忘记 IP 是 v4 还是 v6 | 先 `-e ip.version` 看 |


## 相关章节

- `linux.md` —— Docker 网络 / 服务端口配置
- `windows.md` —— 事件日志里的连接记录
- `mobile.md` —— 手机 App 的流量特征
- `iot.md` —— 门锁/网关的总线抓包
- `traps.md` —— tshark 字段名陷阱（陷阱 33）
