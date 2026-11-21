# 加密容器 / 分层卷 / 特殊文件系统

覆盖：VeraCrypt、TrueCrypt、LUKS1/2、LVM2、BitLocker、以及"看起来像坏卷"的情况。

**铁律**：拿到密码就**挂载**，不解密整卷。只有在容器不支持随机读、或下游工具必须吃 raw 时才整卷解。

---

## 一、先判断是什么容器

```python
# 读前 512 字节 + 尾部，对照魔数
SIGS = {
    b'VERA': 'VeraCrypt/TrueCrypt 明文头（已解密）',
    b'TRUE': 'TrueCrypt 明文头（已解密）',
    b'LUKS\xba\xbe': 'LUKS1',
    b'LUKS\x00\x00\x18\x00': 'LUKS2',
    b'-FVE-FS-': 'BitLocker',
    b'CONECTIX': 'VHD 尾标（在文件末尾 512B）',
    b'KDMV': 'VMDK',
    b'QFI\xfb': 'qcow2',
    b'LABELONE': 'LVM2 PV（在 512 偏移）',
    b'\x53\xef': 'ext2/3/4 超级块（在 1024 偏移）',
    b'XFSB': 'XFS',
    b'_BHRfS_M': 'btrfs',
}
```

**判据**：
- 熵 > 7.99 **且** 无明显魔数 → 加密容器（VeraCrypt/LUKS/BitLocker/第三方 FDE）
- 熵 > 7.99 **且** 有 `-FVE-FS-` → BitLocker
- 熵 > 7.99 **且** 是 GPT 分区无标识 → 第三方 FDE（如某些国产加密软件），常规手段打不开
- 前 512 字节是 `eb52904e54465320` → NTFS，直接 pytsk3
- 前 512 全 0 但 GPT 头在 512 → 分区表正常，去读各分区起始扇区

---

## 二、VeraCrypt / TrueCrypt

### 2.1 密码候选（铁律 1）

```python
PWDS = [
    raw_string.encode('utf-8'),            # 原样，最常见
    base64.b64decode(raw_string),          # Base64 解码值
    raw_string.encode('utf-8') + b'\n',    # 多了个换行
    raw_string.rstrip().encode('utf-8'),   # 尾部空格
]
```

**全角/半角别自己统一**：`！` `￥` `＠` 和 `!` `¥` `@` 是不同字节。用户给的原样保留。

### 2.2 头部参数（默认值）

| 项 | 默认 | 备注 |
|---|---|---|
| 加密算法 | AES-256-XTS | 也可能是 Serpent/Twofish/Camellia 或其级联 |
| PRF（KDF） | **PBKDF2-HMAC-SHA512**，**500,000** 轮 | VeraCrypt 1.x 默认；TrueCrypt 是 RIPEMD160 / 2000 轮 |
| 盐 | 前 64 字节 | |
| 头部位置 | 偏移 0（主）+ 卷尾 131072 前（备） | |
| 头部占用 | 前 512 字节（加密主体是 `hdr[64:512]`） | `hdr[:64]` 是盐，明文 |
| 数据区起始 | 131072 | |
| XTS data unit | **扇区号（文件绝对偏移 / 512）** | 见 2.4 |

### 2.3 解头部取主密钥

```python
import hashlib, struct, zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def xts_dec(key, data, unit):
    tw = struct.pack('<Q', unit) + b'\x00' * 8
    c = Cipher(algorithms.AES(key), modes.XTS(tw)).decryptor()
    return c.update(data) + c.finalize()

fs = open(IMG, 'rb'); fs.seek(0); hdr = fs.read(512)
salt, body = hdr[:64], hdr[64:512]
for pwd in PWDS:
    for prf, it in [('sha512', 500000), ('ripemd160', 655331), ('sha256', 500000)]:
        dk = hashlib.pbkdf2_hmac(prf, pwd, salt, it, 64)
        h = xts_dec(dk, body, 0)
        if h[:4] in (b'VERA', b'TRUE'):
            print('HIT', pwd, prf, it, h[:4])
```

解出的 512 字节头字段：

| 偏移 | 字段 |
|---|---|
| 4:6 | 版本（大端 u16） |
| 8:12 | `crc32(h[192:512])` 的期望值 |
| 28:36 | hidden volume size |
| 36:44 | 卷大小（u64 BE） |
| 44:52 | 加密区起始 |
| 52:60 | 加密区长度 |
| 64:68 | 扇区大小（512） |
| **192:256** | **主密钥 1**（XTS key part 1，32B） |
| **256:320** | **主密钥 2**（XTS key part 2，32B） |
| 188:192 | `crc32(h[0:188])` |

**校验**：`crc32(h[0:188])` 与偏移 188 相等，`crc32(h[192:512])` 与偏移 8 相等 → 头有效。
> 龙信杯实战：这两个 CRC 都通过，但央视 `MD5.txt` 记录的哈希对不上，说明**映像本身完好、只是哈希清单与发放件不配套**。别因为哈希不符就判定镜像损坏。

### 2.4 数据区解密（最容易错的一步）

**XTS data unit 用的是文件绝对扇区号，不是相对数据区的偏移。**

```python
ENC_START = 131072
SECTOR = 512
BASE_UNIT = ENC_START // SECTOR        # = 256

def read_dec(off, length):             # off 相对数据区
    unit0 = BASE_UNIT + off // SECTOR
    ...  # 每 SECTOR 一个 XTS 单元
```

**验证方法**：解出来第一扇区应该是文件系统引导扇区。
- NTFS：`eb 52 90 4e 54 46 53 20 20 20`（`\xebR\x90NTFS    `）
- ext4：偏移 1024+56 处是 `53 ef`
- 解出来是随机字节 → data unit 基址错了，试 `unit = off/512`（基址 0）

### 2.5 挂载（首选，秒级）

```powershell
$pw = '<BASE64_PASSWORD>'   # 原样，不解码
$p = Start-Process -FilePath 'D:\ForensicTools\VeraCrypt.exe' `
   -ArgumentList @('/volume',$img,'/letter','Z','/password',$pw,
                   '/quit','/silent','/history','n','/cache','n') `
   -PassThru -Wait
"exit=$($p.ExitCode)"          # 0 = 成功
Test-Path 'Z:\'
```

- 需要 `veracrypt` 驱动在运行（`sc query veracrypt` → RUNNING）。首次挂载会自动加载。
- `/history n` 别写历史、`/cache n` 别缓存口令——取证现场不留痕。
- 挂载成功后是**普通盘符**，直接 `Get-ChildItem`、Python `open`、tsk 读都行。
- 卸载：`'/dismount','Z','/quit','/silent'`。

**独立复算时的独占锁坑**：容器一旦挂载，`veracrypt.sys` 会对镜像文件加**独占锁**，此时 Python `open(IMG,'rb')` 报 `PermissionError: [Errno 13]`。

```
要做独立复算（自己解头验证主密钥 / 算镜像哈希）→ 先 dismount
要读里面的数据 → 挂载，别去碰镜像文件本身
两者不能同时
```

```powershell
& 'D:\ForensicTools\VeraCrypt.exe' /dismount Z /quit /silent
Start-Sleep -Seconds 3      # 等驱动释放句柄
# 此时才可以 open(IMG,'rb')
```

### 2.7 完整验证脚本（卸载后跑）

```python
import hashlib, struct, zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

IMG = r'...\container'
PWD = b'<BASE64_PASSWORD>'      # 原样

def xts(key, data, unit):
    tw = struct.pack('<Q', unit) + b'\x00' * 8
    c = Cipher(algorithms.AES(key), modes.XTS(tw)).decryptor()
    return c.update(data) + c.finalize()

hdr = open(IMG, 'rb').read(512)
salt, body = hdr[:64], hdr[64:512]
dk = hashlib.pbkdf2_hmac('sha512', PWD, salt, 500000, 64)
h = xts(dk, body, 0)
assert h[:4] in (b'VERA', b'TRUE')
assert struct.unpack('>I', h[8:12])[0]   == (zlib.crc32(h[192:512]) & 0xffffffff)   # crcKey
assert struct.unpack('>I', h[188:192])[0] == (zlib.crc32(h[0:188]) & 0xffffffff)   # crcHdr
MK = h[192:256]

f = open(IMG, 'rb'); f.seek(131072); blk = f.read(512); f.close()
unit = 131072 // 512
print(xts(MK, blk, unit)[:11])     # 应为 b'\xebR\x90NTFS    '
```

三条断言全过 = 密码对、KDF 对、XTS 基址对、主密钥可用。**先跑这个再动手取数据**，比事后发现解错了省时间。

### 2.6 全量解密的速算

如果确实要 raw（下游工具不支持盘符）：

| 环节 | 实测（龙信杯，105 GiB / G 盘） |
|---|---|
| 单线程 AES-XTS | 44 MB/s |
| 10 线程 | 76 MB/s（瓶颈在磁盘读） |
| 全卷预计 | 约 25 分钟 |

用分段 + 断点续传：每 32–64 MiB 一个 seg，`progress.json` 记录已完成 seg 索引，中断可续。

---

## 三、LUKS

```bash
# WSL / Linux
cryptsetup luksDump /dev/sdX          # 看版本、cipher、PBKDF
cryptsetup luksOpen /dev/sdX name     # 输入密码
mount /dev/mapper/name /mnt
```

LUKS1 头在偏移 0；LUKS2 有 JSON 元数据。若 WSL 里没 `cryptsetup`：

```bash
wsl -d docker-desktop -- sh -c "which cryptsetup"   # 常见没有
# 备选：Windows 上跑 VeraCrypt 也能开 LUKS（"Linux" 选项）
```

LUKS 的 PBKDF 可能是 `argon2id`（LUKS2 默认）或 `pbkdf2`。手工解要读 `luksDump` 的 `Iterations`/`Memory`/`Threads`。

---

## 四、LVM2（分层卷）

Linux 服务器镜像常是 **GPT → PV(LVM2) → VG → LV(ext4)**，直接对着分区偏移开 ext4 会失败。

### 4.1 定位 PV 与 LV 起始

```python
P3_LBA = 4198400              # 从 GPT 表读到的物理卷分区起始扇区
f.seek(P3_LBA * 512 + 512)    # LABELONE 标签在 PV 起点 +512
lab = f.read(512)
assert lab[:8] == b'LABELONE'
```

元数据文本里找：

```
extent_size = 8192            # sectors
physical_volumes { pv0 { pe_start = 2048
                          pe_count = 63487 } }
```

**LV 起始扇区 = PV 起始 LBA + pe_start**

```
LV_LBA = 4198400 + 2048 = 4200448
```

### 4.2 验证

```python
f.seek(LV_LBA * 512 + 1024 + 56)
assert f.read(2) == b'\x53\xef'    # ext4 magic
```

然后 `pytsk3.FS_Info(img, offset=LV_LBA*512)` 就能开。

### 4.3 常见坑

| 现象 | 原因 | 处理 |
|---|---|---|
| `Cannot determine file system type` | 对着 PV 分区起点开，没跳 pe_start | 加 pe_start |
| ext4 开了但只有 `lost+found`、`boot` | 开的是 `/boot` 分区（通常 p2） | 找 LV 分区（通常 p3） |
| 元数据里 `pe_count=0` | 读到的是旧副本或被覆盖 | 扫前 4 MB 找所有 `contents = "Text Format Volume Group"`，取 `seqno` 最大的 |
| 两台机器镜像布局完全一致 | 同母版克隆 | 分别验证 `/opt`、`/etc` 内容区分角色 |

### 4.4 区分多台服务器的角色

龙信杯两台的布局、LVM UUID、VG 名完全相同（同母版）。靠**业务内容**区分：

```python
for n in ('srv1','srv2'):
    print(n, ls(fs(n), '/opt'))         # 看服务目录
    print(n, ls(fs(n), '/etc/systemd/system'))   # 看 service 名
```

- 出现 `delivery-query` + `dq-bootstrap.service` → 网站/查询服务器
- 出现 `query-crypto` + `crypto-bootstrap.service` + `meridian-core` → 解密服务器

---

## 五、BitLocker

有恢复密钥时：

```powershell
manage-bde -unlock E: -RecoveryPassword 111111-222222-333333-444444-555555-666666-777777-888888
# 或
manage-bde -unlock E: -Password
```

密钥可能在：
- AD / Azure AD（比赛里通常给文本）
- `MicrosoftAccount\*.json` 备份文件
- 内存镜像里的 `BitLocker` 密钥结构（Volatility3 `windows.bitlocker`）

恢复密钥文件格式：`BitLocker 恢复密钥：xxxxxx-xxxxxx-...`

---

## 六、"打不开"的判别树

```
镜像熵 7.99+？
├─ 有 -FVE-FS- → BitLocker，找恢复密钥
├─ 有 LUKS 头 → LUKS，找密码跑 cryptsetup
├─ 有 VERA/TRUE（解密后） → VeraCrypt，密码已对
├─ 有 GPT 但分区高熵、无标识 → 第三方 FDE
│    ├─ 先查同一检材里有没有密钥文件（.key / 密码文本 / 配置文件）
│    └─ 都没有 → 标 ⬜「第三方全盘加密，无密钥」，不要硬啃
└─ 无任何标识 → 可能是 VeraCrypt（头本身加密，看不出魔数）
     └─ 直接盲试 VeraCrypt 解头（2.3 的脚本），密码对就有 VERA 魔数

镜像熵 < 7.99 但 FS 打不开？
├─ 分区表是 GPT，分区类型是 Linux → 大概率 LVM，走第四节
├─ 分区类型 0x83 但 tsk 报错 → 试指定 offset / 试 dissect.target
└─ 是 /boot 分区 → 真正的根在别的分区或 LV
```

---

## 七、检查清单

```
□ 密码按「原样 / 解码后 / 加换行」全试过（各 1 秒）
□ 容器是挂载的，不是整卷解密的
□ XTS data unit 基址验证过（解出头扇区魔数）
□ 头部双 CRC 校验过
□ 哈希不符时先判断是"映像坏"还是"清单不配套"
□ LVM 加了 pe_start 偏移
□ 多服务器用业务内容区分角色，不靠分区布局
□ 确实打不开的标 ⬜ 并写明缺什么密钥/文件
```


## 八、密钥链断了的处理（情况1 实证）

**场景**：多层派生密钥（root → seed → field_key → 明文），某一层的 KDF 参数不在配置文件里。

### 8.1 先找算法，别猜参数

龙信杯的错误做法：拿 `service-root.key` 当 IKM，用 20 种 info × 20 种 salt 硬试
**400 次全灭**。正确做法是找常量字符串。

算法的 `info` 标签（如 `dq/sqlcipher/v2`、`dq/field/v2`）**一定以明文形式出现在**：

| 位置 | 说明 |
|---|---|
| 客户端二进制 | Rust/Go 的 `.rodata`，`strings` 直接出 |
| 容器镜像 | 服务端算法在容器内的 `.py`/二进制里 |
| 部署脚本 | `install.sh`、`deploy.sh`、`docker-compose.yml` 的 env |
| compose 配置 | `environment:` 段 |

```powershell
& strings.exe -n 4 app.bin | Select-String '^dq/|^/v1/|kek|seed|salt|hkdf|derive'
```

**龙信杯实测**（`crypto-agent.core`，Rust）：

```
dq/sqlcipher/v2    ← 数据库密钥 info
dq/index/v1        ← 索引密钥
/v1/lease/acquire  ← 协议路径
struct Config with 12 elements  node_id challenge_id dataset_id schema_rev
  generation db_generation manifest_hash runtime_epoch crypto_endpoint
  renew_interval grace_deadline server_cert_pin
struct AcquireResp with 8 elements  expires_at server_ephemeral_pub seal_nonce
  sealed_key_bundle server_nonce timestamp ...
```

**关键**：客户端二进制里只有客户端用的 info（`dq/sqlcipher/v2`、`dq/index/v1`）。
服务端才有的（`dq/field/v2`、`dq/link/v2`、`dq/forensic-kek/v1`）在 `cryptod` 里。
→ **两端都要找**，只找到一半解不开全链。

### 8.2 服务端算法被删了怎么办

龙信杯真实现状：

```
/opt/query-crypto/v3-chaxun/   目录已删（含 crypto_service_v31.py）
/home/goyasha/                 被 shred -n 0 -z -u 擦两遍
/var/lib/docker/overlay2/      空（镜像层已清）
```

**四条抢救路线，按成功率排序**：

| 路线 | 成功率 | 做法 |
|---|---|---|
| **1. 备份目录** | 高 | 找 `.xxx-backup-<ts>`、`*.before`、`*.bak` |
| **2. ext4 journal** | 中 | `debugfs` 或读 inode 8 |
| **3. 日志还原命令** | 中 | `auth.log` 的 sudo、`dpkg.log` 的装包 |
| **4. 二进制字符串** | 视情况 | 服务端二进制若在，`strings` 出常量 |

**路线 1 实测**：srv1 有三个备份目录，但只含 `docker-compose.yml` 和旧二进制，
**没有 v31 源码**。→ 备份不一定管用，所有服务器都要找。

**路线 2 实测**（ext4 journal）：

```python
import pytsk3
f = fs('srv2')
node = pytsk3.FS_Info.open_meta(f, inode=8)   # inode 8 = journal
print(node.info.meta.size)                     # 536870912 = 512 MB

with open('journal.bin','wb') as o:
    off = 0
    while off < node.info.meta.size:
        buf = node.read_random(off, 8<<20)
        if not buf: break
        o.write(buf); off += len(buf)
```

然后搜文件名：

```python
for k in (b'crypto_service_v31.py', b'v3-chaxun', b'dq/field/v2', b'AESGCM'):
    print(k, len([m.start() for m in re.finditer(re.escape(k), d)]))
```

**龙信杯结果**：

```
crypto_service_v31.py   2 处   ← 只有目录项（文件名），没有正文
crypto_service.py       4 处
v3-chaxun               3 处
dq/field/v2             0 处   ← 算法常量完全没有
dq/link/v2              0 处
FORENSIC_SEED           0 处
AESGCM                  0 处
```

**关键判据**：journal 里只有**元数据块**（目录项、inode），没有**数据块**。
正文若已被覆盖，从 journal 恢复不出来。

从目录项拿 inode：

```
60 00 5e 00 | 20 | 15 | 01 | "crypto_service_v31.py"
^^^^^^^^^^^  ^^   ^^   ^^
inode=0x005e0060  reclen  namelen  type
```

```python
node = pytsk3.FS_Info.open_meta(f, inode=0x005e0060)
print(node.info.meta.size)   # 0  —— extent 树已清空
print(node.info.meta.nlink)  # 0
```

**路线 3 实测**（`auth.log` 还原操作序列）：

```
2026-09-01T09:57:53  find /home/goyasha -type f -exec shred -n 0 -z -u -- {} +
2026-09-01T09:57:53  find /home/goyasha -mindepth 1 -delete
2026-09-02T02:17:51  bash /tmp/tmp.OBIireWqOX/crypto_server/deploy.sh
2026-09-02T07:26:57  /home/goyasha/query-crypto-docker-simple-v4/install.sh
2026-09-02T07:32:33  /usr/local/bin/qdec /home/goyasha/pckey.qenc
2026-09-02T07:35:29  install python3-pycryptodome 3.20.0   ← dpkg.log
2026-09-02T07:41:27  /home/goyasha/query-crypto-docker-simple-v4.1/install.sh
2026-09-02T07:42:20  find /home/goyasha -type f -exec shred -n 0 -z -u -- {} +
2026-09-02T07:42:29  /usr/local/bin/qdec /home/goyasha/pckey.qenc
```

时间线说明：**07:35 临时装 pycryptodome 写解密脚本，07:42 立刻 shred**。
这就是为什么源码和常量都没了——反取证做得很彻底。

### 8.3 剩下的文件里能直接答的题

密钥链断了不代表这块全废。先扫一遍「不需要密钥的题」。

| 文件 | 能答什么 |
|---|---|
| `/usr/local/bin/qdec` | 镜像标签（脚本里 `docker run ... qc-runtime:1 decrypt`） |
| `/home/goyasha/pckey.qenc` | 文件 SHA256（45 B，`QCD2` 魔数） |
| `/etc/qc-runtime/server.key` | 65 B ASCII 十六进制 = 32 B 密钥 |
| `BUILD_ATTESTATION.txt` | 各二进制 sha256，可做完整性核验 |
| `docker/containers/*/config.v2.json` | 容器名、镜像、env、挂载点 |
| `config/challenge.json` | challenge_id、dataset_id、generation、manifest_hash |
| `/var/log/auth.log` | 完整操作时间线 |

龙信杯服务器 20 题里，**7 题属于这类**（不需要密钥）。

### 8.4 结论模板

密钥链断掉时，交付物必须写清这三条：

```
1. 断了哪一层：root → seed 的 HKDF info 未知
2. 已穷举什么：20 info × 20 salt = 400 组合，全灭
3. 为什么不可恢复：
   - 源码在 /home/goyasha，被 shred -n 0 -z -u 擦两遍（auth.log 07:42:20）
   - ext4 journal 只剩目录项元数据，无数据块（dq/field/v2 搜索 0 命中）
   - docker 镜像层已清（overlay2 空）
   → 该层密钥不可恢复，题目标 ⬜
```

**不许把"试了 400 次没中"写成"解密失败"** —— 要写清试了什么、为什么不可恢复。


## 相关章节

- `linux.md` —— Docker 配置 / systemd 联动
- `windows.md` —— BitLocker / EFS
- `case2.md` —— 密钥链断了怎么办
- `traps.md` —— 密码与字节序陷阱
- `quickwin.md` —— 三档分类与源×题矩阵
