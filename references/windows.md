# Windows 取证手册

## 一、镜像结构识别

```python
from forensic import Evidence
ev = Evidence(r"镜像路径")
print(ev.summary())
```

三种常见形态：

1. **整盘**（含分区表）→ `partitions` 有多项，选对卷
2. **裸 NTFS 卷**（`eb 52 90 4e 54 46 53`）→ `volumes["raw"]`
3. **裸 ext4**（`53 ef` 在 0x438）→ `volumes["raw"]`

## 二、注册表

### 2.1 提取 hive

```python
fs = ev.fs()
for hive in ["SYSTEM","SOFTWARE","SAM","SECURITY","DEFAULT","COMPONENTS"]:
    data = fs.open(f"/Windows/System32/config/{hive}").read_random(0, size)
    open(f"out/{hive}","wb").write(data)
```

各用户 NTUSER：
```python
for user in ["Tronic_Office","Tronic_Guest","WONGKH","Wah"]:
    fs.open(f"/Users/{user}/NTUSER.DAT")
```

### 2.2 高频题对应的键

| 题目问什么 | 键路径 | 值名 |
|---|---|---|
| 系统版本号 | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` | `CurrentBuild` / `CurrentBuildNumber` |
| 显示版本 | 同上 | `DisplayVersion` |
| 安装日期 | 同上 | `InstallDate`（epoch 秒） |
| 计算机名 | `SYSTEM\ControlSet001\Control\ComputerName\ComputerName` | `ComputerName` |
| 时区 | `SYSTEM\ControlSet001\Control\TimeZoneInformation` | `TimeZoneKeyName`、`Bias` |
| 最后关机 | `SYSTEM\ControlSet001\Control\Windows` | `ShutdownTime`（REG_BINARY FILETIME） |
| 用户配置文件列表 | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` | 子键名=SID，`ProfileImagePath` |
| .mp4 默认程序 | `NTUSER\...\Explorer\FileExts\.mp4\UserChoiceLatest\ProgId` | 注：新版 Win 没有 UserChoice，只有 UserChoiceLatest |
| Win+R 历史 | `NTUSER\...\Explorer\RunMRU` | `a`/`b`/`c`… + `MRUList` |
| 自启动项 | `NTUSER\...\CurrentVersion\Run` | 各值名 |
| 密码提示 | `SAM\SAM\Domains\Account\Users\<RID>\UserPasswordHint` | REG_BINARY，UTF-16LE |
| 网卡伪造 MAC | `SYSTEM\...\Control\Class\{4d36e972-...}\<NNNN>\NetworkAddress` | |
| 网卡真实 MAC | `SYSTEM\...\Control\NetworkSetup2\Interfaces\<GUID>\Kernel\PermanentAddress` | |
| WLAN 配置 | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\<GUID>` | `ProfileName`、`DateLastConnected` |
| 蓝牙设备 | `SYSTEM\ControlSet001\Services\BTHPORT\Parameters\Devices\<MAC>` | `LastConnected`、`Name` |
| 空密码限制 | `SYSTEM\ControlSet001\Control\Lsa` | `LimitBlankPasswordUse` |

### 2.3 regipy 用法与坑

```python
from regipy.registry import RegistryHive
h = RegistryHive(path)
k = h.get_key(r"\Path\To\Key")
k.get_value("Name")
[v.name for v in k.iter_values()]
[s.name for s in k.iter_subkeys()]
k.get_class_name()      # JD/Skew1/GBG/Data 用这个算 bootkey
k.header.last_modified  # 键写入时间 FILETIME
```

**坑**：
- 值可能是 `bytes` 或 **hex 字符串**，统一用 `tb()` 转换
- 遍历全 hive 递归非常慢（分钟级），先定位再读
- `get_key` 失败抛异常，用 try 包住

### 2.4 SAM 解析

见 `scripts/registry.py` 的 `sam_users()`。要点：

- bootkey = `JD+Skew1+GBG+Data` 类名拼接 → 置换表 `[8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7]`
- F 结构时间偏移：`0x08` 最后登录、`0x18` 改密、`0x20` 登录失败、`0x28` 账号过期、`0x38` 密码重置
- **密码提示不在 F+0x48**，是独立值 `UserPasswordHint`

## 三、事件日志

### 3.1 用 EzTools 批量转 CSV

```powershell
D:\ForensicTools\eztools\EvtxECmd\EvtxeCmd\EvtxECmd.exe `
  -f Security.evtx --csv out_dir --csvf security.csv
```

CSV 列：`RecordNumber, TimeCreated, EventId, Level, Provider, Channel, UserName, RemoteHost, PayloadData1..6, Payload`

`Payload` 是完整 JSON，解析：
```python
import json
j = json.loads(row['Payload'])
d = {x['@Name']: x.get('#text') for x in j['EventData']['Data']}
```

### 3.2 关键 EventId

| ID | 含义 | 常考题 |
|---|---|---|
| **4624** | 登录成功 | 来源 IP、登录类型（2=交互,3=网络,5=服务,10=RDP） |
| **4625** | 登录失败 | 计数、Status 码 |
| **4648** | 显式凭据登录 | 横向移动 |
| **4672** | 特殊权限分配 | 提权 |
| **4720** | **创建账号** | 账号创建顺序（不是目录 crtime） |
| **4726** | 删除账号 | |
| **4738** | 账号变更 | |
| **104** | **某日志文件被清除** | PayloadData1 是日志名 |
| **1102** | Security 日志被清除 | |
| **1074** | 关机/重启请求 | param5 区分 power off / sleep |
| **6006** | 事件日志服务停止 | 真关机三件套之一 |
| **6008** | 意外关机 | |
| **41** | 内核未正常关机 | |
| **42** | 进入睡眠 | **不是关机** |
| **13** | 系统时间同步到硬件 | 真关机三件套之一 |
| **109** | 内核发起关机 | 真关机三件套之一 |
| **7045** | 服务安装 | PSEXESVC 远程执行 |
| **1116/1117** | Defender 检测到威胁/采取动作 | 木马名、路径 |
| **11000-11010** | WLAN 连接 | `LocalMac`、SSID |

### 3.3 Status 码

| 码 | 含义 |
|---|---|
| `0xC000006D` | 用户名或密码错 |
| `0xC000006A` | 密码错（用户名对） |
| `0xC000015B` | **STATUS_LOGON_TYPE_NOT_GRANTED** 未授予该登录类型 |
| `0xC0000193` | 账号已过期 |
| `0xC0000072` | 账号被禁用 |

### 3.4 关机 vs 睡眠判别

```
真关机：6006 + 109 + 13 三件套齐全
睡眠：  只有 1074（param5 可能写 power off）+ 42（Reason="Sleep initiated"）
```

唤醒时会写 1（系统从睡眠恢复），且 Kernel-Power 的 `OldTime` 保持睡眠前的时刻（计时连续）。

## 四、文件痕迹

### 4.1 回收站

路径：`/$Recycle.Bin/<SID>/`

- `$I<6字符><扩展名>`：元数据（删除时间 + 原路径）
- `$R<6字符><扩展名>`：实际文件内容

`$I` 结构（v2）：
```
0x00 version(8)     = 2
0x08 filesize(8)
0x10 deleted_time(8) FILETIME
0x18 name_len(4)   （字符数）
0x1C name(name_len*2) UTF-16LE
     path_len(4)
     path(path_len*2) UTF-16LE
```

**注意**：v1 没有 path 字段，且 name 固定 520 字节。

### 4.2 Recent / LNK

`/Users/<u>/AppData/Roaming/Microsoft/Windows/Recent/*.lnk`

用 LECmd 解析（`D:\ForensicTools\eztools\LECmd\LECmd.exe -d <dir> --csv out --csvf lecmd.csv`），关键列：

- **`TargetAccessed`** ← 目标文件的**真实访问时间**（$SI 被篡改时用这个）
- `TargetModified`、`TargetCreated`
- `LocalPath` 目标路径
- `SourceModified` lnk 自身时间

### 4.3 Notepad 未保存内容

路径：`/Users/<u>/AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState/*.bin`

格式：`NP` 魔数 + 二进制头 + **UTF-16LE 正文**。

用 `sqlite_tools.py notepad <目录>` 直接抽文本。

### 4.4 Prefetch

`/Windows/Prefetch/*.pf`

用 `PECmd.exe -f <file> --csv out` 解析。关键字段：`LastRun`（程序真实启动时间）、`RunCount`。

### 4.5 UserAssist

`NTUSER\...\Explorer\UserAssist\{GUID}\Count`

- 值名是 **ROT13 编码**的程序路径
- 值内容是二进制：`0x04` 运行次数(4)、`0x3C` 最后执行时间(FILETIME)

用 `registry.py ua <NTUSER>` 解码。

### 4.6 浏览器数据

| 文件 | 内容 |
|---|---|
| `History` | `urls` 表（访问记录）、`visits` 表（含 `visit_time`，Chrome epoch 1601） |
| `Web Data` | `autofill` 表（表单自动填充，含 `card_no`）、`credit_cards` 表 |
| `Login Data` | `logins` 表（保存的账号密码） |
| `Bookmarks` | JSON |

Chrome/Edge 路径：`/Users/<u>/AppData/Local/Google/Chrome/User Data/Default/`
（Edge 换 `Microsoft/Edge`）

**坑**：题目若指定某用户，**必须只查该用户**的库。查错用户是最常见的失分。

### 4.7 ADS（备用数据流）

```python
for attr in fs.open(path):
    if attr.info.name == b'Zone.Identifier':
        data = fs.open(path).read_random(0, attr.info.size, 128, attr.info.id)
```

`Zone.Identifier` 内容：
```
[ZoneTransfer]
ZoneId=3                              # 3=Internet, 2=Intranet, 1=Local
ReferrerUrl=https://...               # 来源页面
HostUrl=https://...                   # 直链
```

`ZoneId=3` 才代表"来自 Internet 下载"。

## 五、时间戳篡改检测

```python
from forensic import detect_tamper
r = detect_tamper(fs, "/path/to/file")
print(r["tampered"], r["real_crtime"], r["si_crtime"], r["fn_crtime"])
```

判别信号：

1. `$SI` 与 `$FN` 的 crtime 差 > 1 天 → 篡改
2. 一批文件的 atime 落在同一秒 → 批量改写
3. `$SI` 时间精确到秒（无小数），`$FN` 有 100ns 小数 → 前者是 GUI 工具写的

**常见工具**：TimeStamp Changer、SetFileTime、PowerShell `(Get-Item).CreationTime=`

## 六、内存镜像

```powershell
vol -f memory.raw windows.info.Info
vol -f memory.raw windows.registry.hashdump.Hashdump      # 用户 NTLM
vol -f memory.raw windows.pslist.PsList
vol -f memory.raw windows.netscan.NetScan
vol -f memory.raw windows.cmdline.CmdLine
vol -f memory.raw windows.filescan.FileScan
```

**优势**：hashdump 直接出明文哈希，不需要解析 SAM+bootkey，也不受 PEK 定位问题影响。COM-01 的 Q32/Q33 就是靠这个一次拿下。

## 七、Shellcode / 反向木马分析（2026 龙信杯增补）

题目常问「回传地址」「生成框架」。两个字段都在 shellcode 的 `mov` 立即数里，**但端口极易读错**。

### 7.1 定位 shellcode 载体

```python
import struct
d = open('sample.exe', 'rb').read()
e = struct.unpack('<I', d[0x3c:0x40])[0]          # e_lfanew
nsec = struct.unpack('<H', d[e+6:e+8])[0]
ohs  = struct.unpack('<H', d[e+20:e+22])[0]
st   = e + 24 + ohs
for i in range(nsec):
    s = d[st+i*40:st+(i+1)*40]
    name = s[:8].rstrip(b'\x00').decode('latin1')
    vs, va, rs, ra = struct.unpack('<IIII', s[8:24])
    print('%-10s va=0x%05x vs=0x%05x raw=0x%05x rs=0x%05x' % (name, va, vs, ra, rs))
```

**判据**：出现怪节名（龙信杯是 `.fuqy`，`va=0x4000 vs=0x258 raw=0x1800`）就是 shellcode 载体。

### 7.2 反连地址的正确读法（关键坑）

msfvenom 反连 stub：

```
49 bc  02 00 03 8f c0 a8 02 6f       mov r12, 0x6f02a8c0038f0002
       ^^^^^ ^^^^^ ^^^^^^^^^^^
       pad2   port   ip(4B)
```

**8 字节立即数布局 = `[pad 2B][port 2B 大端][ip 4B]`**

```python
seg = d[0x1800:0x1800+0x400]
i = seg.find(bytes([0xc0, 0xa8, 0x02, 0x6f]))   # 先按 IP 定位
imm = seg[i-4:i+8]
port = int.from_bytes(imm[2:4], 'big')           # ← 这里
ip   = '.'.join(str(x) for x in imm[4:8])
print('%s:%d' % (ip, port))                      # 192.0.2.111:911
```

**易错对照**

| 做法 | 结果 |
|---|---|
| 取 `imm[0:2]` 当端口 | `0x0200`=512（那是 pad） |
| 取 `imm[2:4]` 按小端 | `0x8f03`=36611 |
| **取 `imm[2:4]` 大端** | **`0x038f`=911** ✅ |
| 拿相邻 `push 0x101` 当端口 | 257 ❌（`68 01 01 00 00` 是**另一条**指令） |

### 7.3 判框架：Metasploit vs Cobalt Strike

**别靠单个字符串**。`AQAPRQVH1` 常被误当 CS 标记，其实它只是 `push r9/r8/rdx/rcx` 的指令字节
（`51 50 52 51 56 48`），**任何 shellcode 都有**。

| 特征 | Metasploit | Cobalt Strike |
|---|---|---|
| prologue | `fc4883e4f0e8c0000000415141505251564831d265488b5260...` | 无固定 prologue |
| PEB 遍历 | `65488b5260 488b5218 488b5220 488b7250 0fb74a4a 4d31c9` | 类似 |
| API 哈希 | `ac3c617c022c20`（lodsb/cmp 'a'/加 0x20 归一化）<br>`41c1c90d4101c1e2ed`（ror13/add/loop = **djb2 `block_api`**） | 循环结构不同 |
| 配置块 | 无 | beacon 配置（XOR 编码的 sleep/port） |
| 字符串 | `ws2_32`、`VirtualAlloc`、`ExitProcess` | `beacon`、`Sleep`、`ReflectiveLoader` |

```python
msf = bytes.fromhex('fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c9')
print('Metasploit'     if seg.find(msf) >= 0 else '-')
print('CobaltStrike'   if any(k in seg for k in (b'beacon', b'ReflectiveLoader')) else '-')
```

**龙信杯实测**：`.fuqy+0x10` 起完整命中 msf prologue（48 字节），后续是 djb2 `block_api`
→ **Metasploit**；无 `beacon`/`ReflectiveLoader`/配置块，排除 CS。

### 7.4 核对清单

```
□ 节表看过，找异常节名
□ IP 用 4 字节点分搜索（c0 a8 / 0a 00 / ac 10 开头）
□ 端口取 mov reg,imm64 的 imm[2:4]，【大端】
□ 端口不是相邻 push 指令的立即数
□ prologue 比对 msfvenom 标准 48 字节
□ 哈希循环 ac3c617c022c20 + 41c1c90d4101c1e2ed = djb2 block_api
□ CS 特征 beacon / ReflectiveLoader / 配置块 都没有才能排除 CS
```

## 八、PyInstaller / Nuitka 打包识别

题面问「用什么模块打包的」。

| 打包器 | 判据 |
|---|---|
| **PyInstaller** | 文件尾有 `MEI\014\013\012\013\016` cookie；有 `PYINSTALLER_*` / `pyi-*` 串；用 `pyinstxtractor-ng` 能解出 `*.pyc` |
| **Nuitka** | 解不出 `.pyc`；有 `nuitka` / `__compiled__` 串；产物是编译后的 C 扩展 + `nuitka-*.dll` |
| **py2exe** | 有 `PYTHONSCRIPT` 资源 |

```powershell
# 快速判
& strings.exe -n 6 app.exe | Select-String -Pattern 'PYINSTALLER|MEI|nuitka|__compiled__|_MEIPASS'
# 解包
python -m pyinstxtractor_ng app.exe
```

**判据**：解出 `app.pyc` 且头部是 Python magic → PyInstaller。龙信杯 `快递e栈客户端_v2.19.exe`
解出 `express_client.pyc`（Python 3.13），答案 `PyInstaller`。

**坑**：题面 `[标准格式：Nuitka]` 是**格式示例**，不是答案。别照抄格式示例里的词。

## 九、注册表深度用法（易漏的高频键）

### 9.1 真实 Hive 位置与大小判据

龙信杯驿站 PC 实测：

```
/Windows/System32/config/SOFTWARE      71,565,312 B   ← 软件安装、系统配置
/Windows/System32/config/SYSTEM        12,058,624 B   ← 服务、驱动、USB、时区
/Windows/System32/config/SAM              65,536 B   ← 账号与哈希
/Windows/System32/config/SECURITY         32,768 B   ← LSA 密钥
/Users/<u>/NTUSER.DAT                  1,310,720 B   ← 用户级（UserAssist/RunMRU/RecentDocs）
/Users/<u>/AppData/Local/Microsoft/Windows/UsrClass.dat  3,407,872 B  ← ShellBags
```

**判据**：`SAM` 只有 64 KB，若明显更大说明账号多；`NTUSER.DAT` 超过 10 MB 说明用户活动频繁。

### 9.2 regipy 的致命坑：`iter_values()` 会漏值

**现象**：读 UserAssist 时 `iter_values()` 只返回 `Version` 一个值，看起来像"没有数据"。

```python
# ❌ 会漏
for v in sk.iter_values():
    print(v.name)          # 只出 Version

# ✅ 正确做法
try:
    vals = sk.get_values()          # 返回 dict
except Exception:
    vals = {}
names = list(vals.keys())
for nm in names:
    v = sk.get_value(nm)
    print(nm, v.value)
```

**根因**：regipy 的 `iter_values()` 在部分 hive 结构下只遍历到第一个值。
**判据**：若 `iter_values()` 返回数量 ≤ 2 但子键明显有数据，改用 `get_values()`。

### 9.3 UserAssist 的正确解析（含"真空"判据）

| 项 | 值 |
|---|---|
| 路径 | `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<GUID>\Count` |
| 值名 | **ROT13 编码**的程序路径 |
| 记录大小 | **72 字节/条**（Win7+） |
| 偏移 4:8 | 运行次数（u32） |
| 偏移 60:68 | 最后执行时间（**FILETIME**） |

```python
import struct, datetime, codecs

for sk in reg.get_key(r'\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist').iter_subkeys():
    try:
        cv = sk.get_value('Count')
    except Exception:
        continue          # 该 GUID 下没有 Count，跳过
    data = cv.value
    for off in range(0, len(data) - 71, 72):
        rec = data[off:off + 72]
        run = struct.unpack('<I', rec[4:8])[0]
        ft = struct.unpack('<Q', rec[60:68])[0]
        if not ft:
            continue
        dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
        print(codecs.decode(sk.name, 'rot13'), run, dt)
```

**"UserAssist 为空"的判据**：9 个 GUID 全部只有 `Version` 无 `Count` → 这个用户从未通过 GUI 启动过程序
（或被清理工具清过）。**这时是真空，不是解析错。**

### 9.4 RunMRU：Win+R 历史（明文，无需解码）

```
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

值名是 `a` `b` `c`…（字母序），值是**明文字符串 + `\1` 结尾**。

龙信杯实测：
```
a        shell:Common Startup\1
MRUList  a
```

### 9.5 RecentDocs：最近文档（UTF-16LE，需切分）

```
NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

值是**二进制**：`UTF-16LE 文件名 + \x00\x00 + 6 字节附加数据`。

```python
val = v.value
name = val.split(b'\x00\x00')[0].decode('utf-16-le', 'replace').strip('\x00')
```

**坑**：`MRUListEx` 值是索引序列（`0xFFFFFFFF` 结尾），不是文件名，要跳过。

### 9.6 BAM / DAM：后台活动（无 GUI 也记录）

```
SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>
SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\<SID>
```

**只在 SYSTEM hive 里，不在 NTUSER**。值是二进制：`8 字节 FILETIME + 路径（UTF-16LE）`。

**判据**：题问「某程序最后运行时间」而 UserAssist 没有 → 查 BAM。服务类程序（无界面）只在 BAM。

### 9.7 其他高频键速查

| 题问什么 | 键 | 关键值 |
|---|---|---|
| 计算机名 | `SYSTEM\ControlSet00X\Control\ComputerName\ComputerName` | `ComputerName` |
| 时区 | `SYSTEM\ControlSet00X\Control\TimeZoneInformation` | `TimeZoneKeyName` `Bias` |
| 安装时间 | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` | `InstallDate`(epoch) `InstallTime` |
| 产品 ID | 同上 | `ProductId` |
| 系统版本 | 同上 | `ProductName` `CurrentBuild` `DisplayVersion` |
| 最后关机时间 | `SYSTEM\ControlSet00X\Control\Windows` | `ShutdownTime`(FILETIME) |
| 网络接口 | `SYSTEM\...\Services\Tcpip\Parameters\Interfaces\{GUID}` | `DhcpIPAddress` `NameServer` |
| 无线 SSID | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` | `ProfileName` `DateLastConnected` |
| 已装软件 | `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` | `DisplayName` `InstallDate` `Publisher` |
| 启动项 | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | 值名=名称，值=路径 |
| 服务 | `SYSTEM\ControlSet00X\Services\*` | `ImagePath` `Start` `ObjectName` |
| USB 历史 | `SYSTEM\ControlSet00X\Enum\USBSTOR` | 设备型号 + 序列号 |
| 外置 SSD | `SYSTEM\ControlSet00X\Enum\SCSI` | **不落 USBSTOR** |
| 用户 SID | `SAM\SAM\Domains\Account\Users\Names` | 名字→SID 映射 |

**`ControlSet00X` 的 X 怎么定**：查 `SYSTEM\Select` 的 `Current` 值，通常是 1 或 2。
若 `Current=1`，就用 `ControlSet001`。

## 十、事件日志深度用法

### 10.1 同名 EventId 不同 Provider 的坑（重要）

**现象**：查"关机事件 41"，抓到一堆 `Microsoft-Windows-TerminalServices-LocalSessionManager`
的 41 —— 那是**远程桌面会话**，不是内核电源。

龙信杯实测：
```
EventId=41  Provider=Microsoft-Windows-TerminalServices-LocalSessionManager   ← RDP 会话
             PayloadData1 = Target: DESKTOP-L8LJ3U8\de...
EventId=41  Provider=Microsoft-Windows-Kernel-Power                            ← 内核电源（异常关机）
```

**判据：必须先看 Provider，不能只看 EventId。**

| EventId | 常见 Provider | 含义 |
|---|---|---|
| 41 | `Kernel-Power` | **异常关机**（断电/蓝屏） |
| 41 | `TerminalServices-LocalSessionManager` | **RDP 会话开始** |
| 42 | `Kernel-Power` | 进入睡眠 |
| 42 | `TerminalServices-LocalSessionManager` | RDP 会话结束 |
| 6005 | `EventLog` | **开机**（日志服务启动） |
| 6006 | `EventLog` | **正常关机**（日志服务停止） |
| 6013 | `EventLog` | 系统运行时长 |
| 1074 | `User32` | **主动关机/重启**（含发起进程） |
| 6008 | `EventLog` | 上次意外关机 |

**关机判定三件套**：`6006`（日志停） + `1074`（主动发起） + `6013`（时长）。
只有 `1074` + `Kernel-Power 42` 且 `Reason` 是 `Sleep` → 是睡眠不是关机。

### 10.2 登录事件详解（4624 / 4625 / 4634 / 4647 / 4672）

| EventId | 含义 | 关键字段 |
|---|---|---|
| **4624** | 登录成功 | `LogonType` `TargetUserName` `IpAddress` `WorkstationName` |
| **4625** | 登录失败 | `LogonType` `TargetUserName` `Status` `SubStatus` |
| 4634 | 登出 | |
| 4647 | 用户主动注销 | |
| 4672 | 授予特殊权限（**管理员登录必出**） | `SubjectUserName` |
| 4776 | NTLM 凭据验证 | `TargetUserName` |
| 4648 | 用显式凭据登录 | |
| 4798/4799 | 枚举用户/组 | |

**LogonType 对照（题常问）**：

| 值 | 含义 |
|---|---|
| 2 | 交互式（本地键盘） |
| 3 | 网络（共享访问） |
| 4 | 批处理 |
| 5 | 服务 |
| 7 | 解锁 |
| 8 | 网络明文 |
| 9 | NewCredentials（`runas /netonly`） |
| **10** | **远程桌面（RDP）** |
| 11 | 缓存凭据 |

**判据**：题问"是否远程登录"→ `LogonType=10`；问"本地登录"→ `LogonType=2`。
`4672` 出现说明该账号是管理员（UAC 提权）。

### 10.3 攻击痕迹事件

| EventId | 含义 | 为什么重要 |
|---|---|---|
| **1102** | 审计日志被清空 | 明确的反取证 |
| **104** | 某日志被清除（System） | **带日志名，比 1102 更具体** |
| 4688 | 进程创建（需开审核） | 命令行全文 |
| 4697 | 服务安装 | 后门常走这里 |
| 7045 | 服务安装（System） | 同上，**更常见** |
| 5140/5145 | 网络共享访问 | 横向移动 |
| 4720 | **账号创建** | 后门账号 |
| 4722 | 账号启用 | |
| 4726 | 账号删除 | |
| 4738 | 账号属性修改 | |
| 4756 | 加入通用组 | 提权 |

**判据**：`1102` 和 `104` 是日志清除的两条路。`104` 在 `System.evtx`，带 `channel` 名，
**比 1102 更能定位"哪个日志被清"**。

### 10.4 PowerShell 日志

| 路径 | 内容 |
|---|---|
| `Microsoft-Windows-PowerShell%4Operational.evtx` | EventId **4104** = 脚本块内容（**明文命令**） |
| `Windows PowerShell.evtx` | EventId 400/403 = 引擎启停 |

**判据**：4104 里能看到完整 PowerShell 代码，是查无文件攻击的最佳位置。

### 10.5 EvtxECmd 实战

```powershell
$ez = 'D:\ForensicTools\eztools\EvtxECmd\EvtxeCmd\EvtxECmd.exe'
& $ez -d 'G:\case\evtx' --csv 'G:\case\csv' --csvf all.csv
```

**输出 24 列**（龙信杯实测）：

```
RecordNumber  EventRecordId  TimeCreated  EventId  Level  Provider  Channel
ProcessId  ThreadId  Computer  ChunkNumber  UserId  MapDescription  UserName
RemoteHost  PayloadData1  PayloadData2  PayloadData3  ...  ExecutableInfo  ExtraData
```

**其后用 PowerShell 直接统计**：

```powershell
# EventId 分布
Import-Csv all.csv | Group-Object EventId | Sort Count -Desc | Select -First 20 Count,Name

# 关机事件（注意带 Provider 过滤）
Import-Csv all.csv | Where-Object { $_.EventId -eq '1074' } |
  Select TimeCreated,PayloadData1,PayloadData2

# 登录来源
Import-Csv all.csv | Where-Object { $_.EventId -eq '4624' } |
  Group-Object RemoteHost | Sort Count -Desc | Select Count,Name
```

龙信杯实测：5 个日志 → **3773 条记录**，1.2 秒跑完。EventId 分布：

```
5379(609) 4624(400) 4672(375) 4799(340) 44(232) 16(166)
4798(99)  4627(70)  225(68)  1034(60) 4735(49) 4688(45)
```

`44` 是 `Microsoft-Windows-Kernel-Boot` 的启动前事件（ShutdownAction），
`16` 是 NTFS 卷挂载。**不是所有高分 EventId 都是攻击痕迹，要按 Provider 判。**

## 十一、文件系统痕迹

### 11.1 $UsnJrnl:$J 的正确读法（易踩）

```python
# ❌ 这样读出来大小是 0
f.open('/$Extend/$UsnJrnl:$J')

# ✅ 必须带 ADS 名称和类型
node = f.open('/$Extend/$UsnJrnl:$J', attr_type=None)  # 或用 MFTECmd
```

**最省事的办法：用 MFTECmd**

```powershell
& 'D:\ForensicTools\eztools\MFTECmd\MFTECmd.exe' -f '$J' --csv out --csvf usn.csv
# 或直接从镜像提
& MFTECmd.exe -f 'E:\$Extend\$UsnJrnl' --csv out --csvf usn.csv
```

**$J 记录格式**：`长度(4) | 主版本(2) | 次版本(2) | 文件引用(8) | 父引用(8) | USN(8) |
时间戳(8) | 原因(4) | 源信息(4) | 安全ID(4) | 文件属性(4) | 文件名长度(2) | 文件名(opt)`

**Reason 标志**（题常问"这个文件被做了什么"）：

| 值 | 含义 |
|---|---|
| `0x1` | FILE_CREATE |
| `0x2` | FILE_DELETE |
| `0x4` | EA_CHANGE |
| `0x100` | SECURITY_CHANGE |
| `0x200` | RENAME_OLD_NAME |
| `0x400` | RENAME_NEW_NAME |
| `0x800` | **FILE_DELETE**（真删除） |
| `0x1000` | DATA_OVERWRITE |
| `0x8000` | **CLOSE** |
| `0x80000000` | CLOSE |

**判据**：`0x1000 | 0x80000000` = 数据被覆写并关闭；`0x80000000 | 0x200` = 重命名。

### 11.2 三道时间戳（$SI / $FN / $SDS）

| 来源 | 可信度 | 说明 |
|---|---|---|
| **$SI**（Standard Information） | **低** | 可被用户态 API 修改（SetFileTime） |
| **$FN**（File Name） | **高** | 只有内核能写，篡改难度极大 |
| **$SDS**（Security Descriptor Stream） | 高 | 权限变更时间 |

```python
node = f.open('/path')
si = node.info.meta              # $SI
for attr in node:
    if attr.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_FNAME:
        fn = attr.info.meta       # $FN
        print('FN crtime:', fn.crtime, 'mtime:', fn.mtime)
```

**判据**：`|$SI.crtime - $FN.crtime| > 1 天` → 篡改。
**批量篡改信号**：一批文件的 `$SI.atime` 落在**同一秒**。

**程序启动/访问用哪个**：
- 程序最后启动 → Prefetch 的 `LastRun`
- 文件最后被访问 → **LNK 的 `TargetAccessed`**（不用 `$SI.atime`）

### 11.3 Prefetch 实测

```
/Windows/Prefetch/*.pf
```

```powershell
& 'D:\ForensicTools\eztools\PECmd\PECmd.exe' -d 'G:\case\Prefetch' --csv out
```

关键字段：`LastRun`（真实启动时间，FILETIME）、`RunCount`、`FilesLoaded`（加载的 DLL，可判是否加载了恶意模块）。

**判据**：
- 有 `.pf` = 程序**至少运行过一次**
- `.pf` 的 crtime 是**首次运行**时间
- 文件被删了但 `.pf` 还在 → 说明运行过，这是关键证据

### 11.4 Amcache / ShimCache / SRUM 三件套

| 工具 | 文件 | 回答什么问题 |
|---|---|---|
| AmcacheParser | `Amcache.hve` | **程序是否安装过**、安装时间、SHA1 |
| AppCompatCacheParser | `SYSTEM` 的 `AppCompatCache` | **程序是否存在过**（含已删除的） |
| SrumECmd | `SRUDB.dat` | **网络流量归属哪个程序**、执行时长 |

```powershell
& AmcacheParser.exe -f Amcache.hve --csv out
& AppCompatCacheParser.exe -f SYSTEM --csv out
& SrumECmd.exe -f SRUDB.dat -r SOFTWARE --csv out
```

**判据**：
- 问「某恶意程序是否存在过」→ ShimCache（**包含未执行的**）
- 问「是否运行过」→ Prefetch
- 问「是否安装过」→ Amcache
- 问「哪个程序用了多少流量」→ SRUM

### 11.5 回收站

```
/$Recycle.Bin/<SID>/$I<随机>   ← 元数据（原路径 + 删除时间）
/$Recycle.Bin/<SID>/$R<随机>   ← 实际内容
```

```powershell
& RBCmd.exe -d '$Recycle.Bin' --csv out
```

**$I 文件结构**：
```
Win10: 8B 头部 | 8B 原文件大小 | 8B 删除时间(FILETIME) | 4B 路径长度 | UTF-16LE 路径
Win7 : 8B 头部 | 8B 原文件大小 | 8B 删除时间        | UTF-16LE 路径（520 固定）
```

`$I` 和 `$R` 的文件名后缀相同，靠后缀配对。

### 11.6 ShellBags（UsrClass.dat）

记录用户在资源管理器里**浏览过的文件夹**（含已删除的、U 盘里的）。

```powershell
& 'D:\ForensicTools\eztools\SBECmd\SBECmd.exe' -d NTUSER.DAT --csv out
& 'D:\ForensicTools\eztools\SBECmd\SBECmd.exe' -d UsrClass.dat --csv out
```

**判据**：题问「嫌疑人浏览过哪些目录」→ ShellBags；问「打开过哪些文件」→ LNK/JumpList。

### 11.7 JumpList

```
/Users/<u>/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/*.automaticDestinations-ms
/Users/<u>/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/*.customDestinations-ms
```

```powershell
& 'D:\ForensicTools\eztools\JLECmd\JLECmd.exe' -d <dir> --csv out
```

**文件名是 AppID 的 base64 编码**，可反查程序（如 `1b4dd67f29cb1962` = 记事本）。

### 11.8 浏览器数据实测路径

```
/Users/<u>/AppData/Local/Google/Chrome/User Data/Default/
  History            访问记录（urls + visits）
  Web Data           表单自动填充、信用卡
  Login Data         保存的密码（需 DPAPI 解密）
  Cookies            含加密值
  Bookmarks          JSON
  Top Sites / Shortcuts
/Users/<u>/AppData/Local/Microsoft/Edge/User Data/Default/   同上
/Users/<u>/AppData/Roaming/Mozilla/Firefox/Profiles/<x>/places.sqlite
```

**Chrome 时间戳**：`WebKit/Chrome epoch` = 1601-01-01，单位**微秒**
```python
dt = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=visit_time)
```

**判据**：`visit_time` 若当 Unix epoch 读会得到 17 世纪的时间，一眼能看出错。

## 十二、DPAPI（加密数据解不开的常见原因）

**问题**：Chrome 密码、RDP 凭据、WiFi 密码、Credential Manager 都是 DPAPI 加密，
直接读是密文。

### 12.1 三层结构

```
用户主密钥（MasterKey）    ← 存在 /Users/<u>/AppData/Roaming/Microsoft/Protect/<SID>/
    ↑ 由用户密码派生（SHA1(password) + SID）
用户密码哈希               ← SAM + SYSTEM（需 bootkey）
```

### 12.2 解密路径

| 情况 | 需要什么 |
|---|---|
| 已登录的活系统 | `mimikatz sekurlsa::dpapi` 直接出 |
| 离线镜像 + 已知用户密码 | `dpapi.py masterkey` + `dpapi.py blob` |
| 离线镜像 + 域环境 | 域备份密钥（`ntds.dit` 的 DPAPI_SYSTEM） |
| 无密码 | 只能爆破用户密码（hashcat `-m 1000` NTLM） |

```powershell
# impacket
dpapi.py masterkey -file <MasterKey文件> -sid <SID> -password <明文密码>
dpapi.py blob -file <加密blob> -mkfile <解密后的MasterKey>
```

**判据**：题问「Chrome 保存的密码」→ 必须 DPAPI 解密，不是读 SQLite 就有。

## 十三、Windows 反取证识别

| 手法 | 痕迹 |
|---|---|
| 日志清除 | EventId **1102**（Security）+ **104**（System，带日志名） |
| 时间戳篡改 | `$SI` vs `$FN` 差异；批量 atime 同秒 |
| 安全删除 | `$J` 的 Reason 含 `0x800`（FILE_DELETE）；`$MFT` 记录变 `0x0` |
| 禁用审计 | `auditpol /clear`；`Security.evtx` 突然停止 |
| 删除 Prefetch | 目录为空但程序明明运行过 |
| 清 UserAssist | 9 个 GUID 只有 Version |
| 清 RunMRU | 只剩 `MRUList` 无 `a`/`b` |
| 卸载痕迹工具 | Amcache 有记录但程序目录不存在 |

**判据**：「没有记录」和「记录被删」是两回事。要能区分：

```
程序目录在 + Prefetch 无        → Prefetch 被清（反取证）
程序目录不在 + Prefetch 有      → 程序被删但运行过
程序目录在 + Prefetch 有        → 正常运行
三者都无                        → 从未运行
```

## 十四、Windows 取证检查清单

```
□ 计算机名/时区/安装时间（SYSTEM + SOFTWARE）
□ 账号列表 + RID + 最后登录（SAM + 4624）
□ 登录来源 IP + LogonType（4624，注意 10=RDP）
□ 关机三件套 6006/1074/6013 + Provider 核对
□ 账号创建 4720（不是用户目录 crtime）
□ 程序启动 Prefetch 的 LastRun（不是日志首行）
□ 程序存在过 ShimCache / 安装过 Amcache / 流量 SRUM
□ 外置存储 USBSTOR + SCSI + Portable Devices 三通道
□ 时间戳 $SI vs $FN 交叉校验
□ 回收站 $I 配对 $R
□ ShellBags 浏览目录 / LNK 打开文件 / JumpList 最近文档
□ 浏览器 History（Chrome 是 1601 微秒）
□ DPAPI 加密的要看是否解得开
□ 日志清除 1102 + 104
```

## 十五、注册表 hive 损坏/截断的诊断与绕过

**这是 Windows 取证最容易被误判为"工具坏了"的问题。**

### 15.1 症状

```
regipy: RegistryParsingException: Bad subkey at offset 69955884:
        stream read less than specified amount, expected 2, found 0
dissect.regf: struct.error / StreamError 在同一偏移附近
RECmd: 静默输出空
```

三个独立解析器都在**同一偏移**失败 → 不是工具问题，是 **hive 本身的问题**。

### 15.2 诊断脚本（30 秒定性）

```python
import struct

d = open('SOFTWARE', 'rb').read()
print('文件大小   :', len(d))
print('magic      :', d[:4])                       # 应为 b'regf'
print('主/次版本  :', struct.unpack('<I', d[0x14:0x18])[0],
                       struct.unpack('<I', d[0x18:0x1c])[0])
print('root cell  : 0x%X' % struct.unpack('<I', d[0x24:0x28])[0])
hbs = struct.unpack('<I', d[0x28:0x2c])[0]
print('hive_bins_size (头部声称) :', hbs, '(0x%X)' % hbs)

# hbin 链扫描
pos, bins = 0x1000, []
while pos < len(d) - 32:
    if d[pos:pos+4] != b'hbin':
        nxt = d.find(b'hbin', pos)
        if nxt < 0:
            break
        pos = nxt
        continue
    sz = struct.unpack('<I', d[pos+8:pos+12])[0]
    if not sz or pos + sz > len(d):
        break
    bins.append((pos, sz))
    pos += sz
print('hbin 块数  :', len(bins))
print('hbin 覆盖到: 0x%X' % pos)
print('文件实际到 : 0x%X' % len(d))
print()
if hbs > len(d):
    print('★ 判定：头部声称 %d 字节，实际只有 %d 字节' % (hbs, len(d)))
    print('  → 缺口 %d 字节（%.1f MB），这是【镜像采集截断】，不是文件损坏' % (
        hbs - len(d), (hbs - len(d)) / 1e6))
```

**龙信杯实测输出**：

```
文件大小   : 67108864
hive_bins_size (头部声称) : 71315456 (0x4400000)
hbin 块数  : 14922
hbin 覆盖到: 0x4000000
文件实际到 : 0x4000000
★ 判定：头部声称 71315456 字节，实际只有 67108864 字节
  → 缺口 4196,592 字节（4.2 MB），这是【镜像采集截断】，不是文件损坏
```

### 15.3 两种情况要分清

| 现象 | 原因 | 能否恢复 |
|---|---|---|
| `hive_bins_size` > 文件大小 | **采集截断**（镜像没采全） | 缺失部分不可恢复，但**已采集的部分可用** |
| `hbin` 链中间断裂（`size=0` 或 magic 错） | 文件损坏/写入中断 | 断点后的数据不可用 |
| `hbin` 覆盖 == 文件大小，但子键解析失败 | 真正的 cell 损坏 | 用事务日志 `.LOG1/.LOG2` 重放 |

**判据**：先比 `hive_bins_size` 与文件实际大小。**不相等 = 采集问题，与方法无关。**

### 15.4 截断 hive 的正确用法

**核心认知**：截断只影响**尾部**（通常是最大的子键，如 `Classes`），
**前面的键（`Microsoft\Windows NT\CurrentVersion`）通常在覆盖范围内**。

```python
# 1) 先确认损坏偏移
BAD = 69955884
COVERED = 0x4000000     # hbin 实际覆盖到

# 2) 只要目标键的 cell 偏移 < COVERED，就能读
# regipy 的问题是 iter_subkeys 会遍历所有兄弟键，撞到坏的就抛异常
# 解决办法：用 dissect.regf 直接按 cell 偏移访问，或接受失败换个键
```

**实测结论**：龙信杯的 `SOFTWARE` 里，`\Microsoft\Windows NT\CurrentVersion`
**恰好落在损坏区之后**，所以读不到。此时：

| 要的信息 | 替代来源 |
|---|---|
| 系统版本 | `C:\Windows\System32\ntoskrnl.exe` 的版本资源（用 ExifTool / pefile） |
| 安装时间 | `SYSTEM` hive 的 `\Setup` 或 `C:\Windows\Panther\setupact.log` |
| 产品 ID | `C:\Windows\System32\config\SYSTEM` 的 `\Control\ProductOptions` |
| 已装软件 | `C:\Program Files` 目录列表 + `Amcache.hve` |
| 计算机名 | **`SYSTEM` hive 就有**（`\Control\ComputerName\ComputerName`），不用 SOFTWARE |

**关键**：`SYSTEM` hive 往往完好（12 MB），**优先从 SYSTEM 拿信息**。

### 15.5 事务日志重放（真正的修复手段）

Windows 10/11 的 hive 旁边有 `.LOG1` / `.LOG2`：

```
/Windows/System32/config/SOFTWARE
/Windows/System32/config/SOFTWARE.LOG1
/Windows/System32/config/SOFTWARE.LOG2
```

```powershell
# RECmd 带 --nl（no log）或让它自动重放
& RECmd.exe -f SOFTWARE --nl --sk "" --csv out
```

**判据**：有 `.LOG1/.LOG2` 说明 hive 处于 **dirty** 状态（未正常卸载），
重放日志能恢复到一致状态。**没有 log 文件 = 正常关闭的 hive。**

### 15.6 regipy 6.x 的 API 变化（必知）

```python
# get_value() 直接返回值，不带 .value
v = key.get_value('ComputerName')
print(v)                    # ✅ 'DESKTOP-L8LJ3U8'
print(v.value)              # ❌ AttributeError: 'str' object has no attribute 'value'
```

**类型映射**：

| REG 类型 | Python 类型 |
|---|---|
| REG_SZ / REG_EXPAND_SZ | `str` |
| REG_DWORD | `int` |
| REG_QWORD | `int` |
| REG_BINARY | `bytes` |
| REG_MULTI_SZ | `list` |

**坑**：网上大量教程写 `v.value`，那是 regipy 3.x 的写法。6.x 变了。

### 15.7 `iter_values()` 会漏值的坑

```python
# ❌ 只出 Version，看不到 Count
for v in sk.iter_values():
    print(v.name)

# ✅ 用 get_values() 拿 dict
vals = sk.get_values()
for name in vals:
    print(name, sk.get_value(name))
```

**判据**：`iter_values()` 返回数量 ≤ 2 但子键明显有数据 → 换 `get_values()`。

### 15.8 损坏 hive 处理流程

```
1. 读头部：hive_bins_size vs 文件实际大小
   ├─ 不相等 → 采集截断，记录缺口，继续用可读部分
   └─ 相等   → 进第 2 步

2. hbin 链扫描（上面的脚本）
   ├─ 中间断裂 → 断点后不可用，记录偏移
   └─ 完整     → 进第 3 步

3. 有 .LOG1/.LOG2 吗？
   ├─ 有 → RECmd --nl 重放，或手工解析日志
   └─ 无 → 用可读部分，缺失字段换替代来源

4. 记录到交付物：
   - 哪个 hive、缺多少字节、损坏偏移
   - 哪些题受影响
   - 替代来源拿到了什么
```


## 相关章节

- `containers.md` —— BitLocker / 加密容器
- `network.md` —— 事件日志里的网络连接 / pcap 关联
- `traps.md` —— 时间戳与证据源陷阱
- `iot.md` —— 固件里的 Windows PE 组件
- `quickwin.md` —— 三档分类与源×题矩阵
