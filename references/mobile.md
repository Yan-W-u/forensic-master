# 手机取证手册（iOS / WhatsApp）

## 一、检材形态识别

| 形态 | 特征 | 处理 |
|---|---|---|
| **iOS 备份** | 根目录有 `Manifest.db`、`Manifest.plist`、`Status.plist`、`Info.plist` | 按 fileID 索引 |
| **逻辑提取** | 目录结构是 `/var/mobile/...` 原生路径 | 直接按路径读 |
| **物理镜像** | 有分区表 + HFS+/APFS | pytsk3 + APFS 支持有限 |
| **Android** | `/data/data/`、`/data/media/` | 类似逻辑提取 |

**重要区分**：本次 FC-01 是**逻辑提取**，路径是 `/var/mobile/Applications/...`，但根目录**也有** `Manifest.db`。两者都要会查：

- 问"备份文件标识符 fileID"→ 查 Manifest.db
- 问"数据库里的具体字段"→ 按实际路径读文件

## 二、iOS 备份索引（Manifest.db）

### 2.1 表结构

```sql
Files(fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)
Properties(key TEXT, value BLOB)
```

`flags`：1=普通文件，2=目录，4=符号链接

### 2.2 fileID 与实际路径的映射

**标准 iTunes 备份**：`<前2字符>/<完整fileID>`

```python
def fileid_to_path(fid):
    return f"/{fid[:2]}/{fid}"
```

**但逻辑提取的镜像不一定有这些哈希目录**——本次 FC-01 就没有，只能按 Manifest 记录作答。

### 2.3 常用 domain

| domain | 内容 |
|---|---|
| `AppDomainGroup-group.net.whatsapp.WhatsApp.shared` | **WhatsApp 全部数据** |
| `AppDomain-net.whatsapp.WhatsApp` | WhatsApp 主程序 |
| `CameraRollDomain` | 相册 |
| `HomeDomain` | 系统偏好 |
| `AppDomain-com.apple.mobilesafari` | Safari |
| `WirelessDomain` | 网络配置 |

### 2.4 查询示例

```python
from sqlite_tools import connect_ro
con = connect_ro("Manifest.db")
# 找 WhatsApp 头像
for r in con.execute("""select fileID, domain, relativePath from Files
    where relativePath like 'Media/Profile/%' and relativePath not like '%.thumb'"""):
    print(r)
```

## 三、WhatsApp 数据

### 3.1 核心数据库

路径：`/var/mobile/Applications/group.net.whatsapp.WhatsApp.shared/`

| 文件 | 内容 |
|---|---|
| **ChatStorage.sqlite** | 消息、群组、会话（最重要） |
| ContactsV2.sqlite | 通讯录 |
| CallHistory.sqlite | 通话记录 |
| LID.sqlite | LID ↔ 电话号码映射 |
| statusDB/Status.sqlite | 状态 |
| Media/Profile/ | 头像 |
| Message/Media/ | 附件 |

### 3.2 ChatStorage 关键表

**ZWACHATSESSION**（会话）
```sql
Z_PK, ZPARTNERNAME, ZCONTACTJID, ZCONTACTIDENTIFIER, ZMESSAGECOUNTER
```
- `ZPARTNERNAME` 显示名
- `ZCONTACTJID` 当前 JID（可能是 `@lid`）
- `ZCONTACTIDENTIFIER` 电话号码 JID（`@s.whatsapp.net`）

**ZWAMESSAGE**（消息）
```sql
Z_PK, ZCHATSESSION, ZMESSAGEDATE, ZISFROMME, ZFROMJID, ZTOJID,
ZTEXT, ZMESSAGETYPE, ZGROUPMEMBER, ZMESSAGEINFO
```

**ZWAGROUPINFO**（群组）
```sql
Z_PK, ZCHATSESSION, ZCREATORJID, ZOWNERJID, ZSOURCEJID, ZCREATIONDATE
```
- **`ZCREATORJID` 就是题目问的"Creator JID"**

**ZWAGROUPMEMBER**（群成员）
```sql
Z_PK, ZCHATSESSION, ZMEMBERJID, ZISADMIN, ZISACTIVE
```

**ZWAMESSAGEINFO**（回执）
```sql
Z_PK, ZMESSAGE, ZRECEIPTINFO
```
**关键坑**：`ZRECEIPTINFO` **只对本机发出的消息（`ZISFROMME=1`）有值**。别人发的消息回执为空，此时"最早阅读者"在个人赛检材上**不可解**。

**ZWAMEDIAITEM**（媒体）
```sql
ZFILESIZE, ZMEDIALOCALPATH, ZMEDIAURL, ZTITLE
```

### 3.3 LID 映射

`LID.sqlite` 的 `ZWAZACCOUNT`：
```sql
ZIDENTIFIER    -- xxx@lid
ZPHONENUMBER   -- 85246292519（无 +）
ZDISPLAYNAME
```

**用途**：判断某手机号是否真正注册了 WhatsApp。只在通讯录（ContactsV2）里出现但 LID 表没有 → **未注册**。

### 3.4 时间戳

WhatsApp 用 **Apple epoch（2001-01-01 起秒数）**：

```python
def apple_ts(v, tz=8):
    import datetime
    dt = datetime.datetime(2001,1,1) + datetime.timedelta(seconds=float(v))
    return (dt + datetime.timedelta(hours=tz)).strftime("%Y-%m-%d %H:%M:%S")
```

### 3.5 常见题型

| 题目 | 求法 |
|---|---|
| 群主 JID | `ZWAGROUPINFO.ZCREATORJID` |
| 群消息总数 | `select count(*) from ZWAMESSAGE where ZCHATSESSION=<pk>` |
| 通话时长/时间 | CallHistory 的 `ZWACDCALLEVENT.ZDURATION` / `ZDATE` |
| 某人是哪个群成员 | `ZWAGROUPMEMBER.ZMEMBERJID` |
| 头像 fileID | Manifest.db 里 `Media/Profile/<号码>-<数字>.jpg` |

### 3.6 已接通 vs 未接通的通话

`ZWACDCALLEVENT`：
- `ZOUTCOME` 为空 → **成功接通**
- `ZOUTCOME=1` → 未接通/被拒
- `ZDURATION` 有值才说明通了

## 四、iOS 照片数据库

### 4.1 Photos.sqlite

路径：`/var/mobile/Media/PhotoData/Photos.sqlite`

核心表 **ZASSET**（135 列），关键字段：

| 字段 | 含义 |
|---|---|
| `Z_PK` | 主键（**注意连续性，缺号说明有删除**） |
| `ZFILENAME` | 文件名 |
| `ZUUID` | 全局唯一标识符 |
| `ZDATECREATED` | 拍摄时间（Apple epoch） |
| `ZTRASHEDDATE` | 移入回收站时间 |
| `ZTRASHEDSTATE` | 1 = 已删除 |
| `ZDIRECTORY` | 目录，如 `DCIM/100APPLE` |
| `ZISDETECTEDSCREENSHOT` | 1 = 截图 |
| `ZCLOUDASSETGUID` | iCloud 资产 GUID |
| `ZMASTER` | 外键 → ZCLOUDMASTER |

**ZADDITIONALASSETATTRIBUTES**：`ZORIGINALFILESIZE`（原始字节数）、`ZORIGINALFILENAME`

**ZCLOUDMASTER**：`ZCLOUDMASTERGUID`（**题目问的"云端主唯一标识符"**）、`ZIMPORTEDBYBUNDLEIDENTIFIER`、`ZIMPORTEDBYDISPLAYNAME`

### 4.2 "截图共几张"

```sql
select count(*) from ZASSET a join ZCLOUDMASTER c on c.Z_PK = a.ZMASTER
where c.ZIMPORTEDBYBUNDLEIDENTIFIER = 'com.apple.springboard'
  and a.ZISDETECTEDSCREENSHOT = 1
```

**坑**：`ZISDETECTEDSCREENSHOT=1` 的照片里，大部分是相机拍的"看起来像截图"，真正的截图是 **SpringBoard 导入**的。两者要一起筛。

### 4.3 WAL 恢复已删记录

**这是本次最核心的技术点**。

`Photos.sqlite` 被删除的记录还在 `Photos.sqlite-wal` 里（如果没被 checkpoint）。

流程：
1. 把 `Photos.sqlite` + `-wal` + `-shm` **三个文件一起**复制到独立目录
2. **不要**用 `sqlite3.connect()` 直接打开（会 checkpoint 删掉 WAL）
3. 用 `sqlite_tools.py wal <wal文件> <关键词>` 做帧级解析

WAL 结构：
```
32B 文件头 (magic 0x377f0682, page_size, salt1, salt2)
然后 N 个帧：
  24B 帧头 (page_no, commit_size, salt1, salt2, cksum1, cksum2)
  page_size 字节的页数据
```

每页是 b-tree 节点，type `0x0D` = table leaf，含 cell 数组。

**判别删除**：主库 `ZASSET` 的 `Z_PK` 从 2 开始（缺 1）→ PK=1 被删，去 WAL 里找。

### 4.4 文件大小

`ZORIGINALFILESIZE`（ZADDITIONALASSETATTRIBUTES）或 `ZDATALENGTH`（ZINTERNALRESOURCE）

## 五、iOS 其他数据

### 5.1 短信

`/var/mobile/Library/SMS/sms.db`

```sql
select m.ROWID, h.id, m.date, m.is_from_me, m.text
from message m left join handle h on h.ROWID = m.handle_id
```

**坑**：`date` 单位是**纳秒**（不是秒）：
```python
dt = datetime.datetime(2001,1,1) + datetime.timedelta(seconds=ns/1e9)
```

### 5.2 通讯录

`/var/mobile/Library/AddressBook/AddressBook.sqlitedb`

```sql
select ROWID, First, Last from ABPerson
select record_id, value from ABMultiValue where property=3   -- 3=电话
```

### 5.3 浏览器

Safari：`/var/mobile/Library/Safari/History.db`

```sql
select url, visit_time from history_items join history_visits ...
```

`visit_time` 也是 Apple epoch。

## 六、Android 补充

### 6.1 WhatsApp

`/data/data/com.whatsapp/databases/msgstore.db`

表：`message`、`chat`、`jid`、`group_participants`

时间戳单位：**毫秒** epoch。

### 6.2 微信

`/data/data/com.tencent.mm/MicroMsg/<hash>/EnMicroMsg.db`

需要 IMEI + uin 算 SQLCipher 密钥（MD5(IMEI+uin) 前 7 位）。

**判据**：文件头不是 `SQLite format 3\x00` 而是随机字节 → 已加密。此时**先找 IMEI 和 uin**：

| 需要 | 位置 |
|---|---|
| uin | `r/MicroMsg/<hash>/systemInfo.cfg`（Java 序列化的 HashMap） |
| IMEI | 手机备份通常**不含**（小米备份会脱敏）；在 PC 端握手过的设备记录、或 `account.bin`（同样加密） |
| 现成密钥 | `sp/` 下有时存有 `login_weixin_username`，但密钥本身不落盘 |

**如果 IMEI 不可得（例如 PC 镜像被全盘加密）→ 这题直接标 ⬜，不要硬啃。**

### 6.3 应用数据

`/data/data/<包名>/`、`/data/media/0/`（内部存储）

---

## 六A、MIUI 备份（.bak）

小米的「本地备份」产物，一个 `.bak` 一个应用。

### 6A.1 封装格式

```
MIUI BACKUP\n
2\n
<包名>\n
-1\n
0\n
ANDROID BACKUP\n
5\n          ← 版本
0\n          ← 压缩（0=不压缩）
none\n       ← 加密（none=明文）
<tar 流开始>
```

**判据**：搜 `ANDROID BACKUP\n` 定位 tar 起点（不要硬算偏移，不同版本前导行数不同）。

```python
def find_ab_start(path):
    head = open(path, 'rb').read(1 << 16)
    i = head.find(b'ANDROID BACKUP\n')
    if i < 0: return None, None
    pos = i; lines = []
    for _ in range(4):                      # 只读 4 行：magic/ver/compress/encrypt
        j = head.find(b'\n', pos)
        lines.append(head[pos:j]); pos = j + 1
    return pos, dict(version=lines[1], compress=lines[2], encrypt=lines[3])
```

**坑**：`lines` 只能读 4 行。多读一行会把 tar 第一个 header 块吃掉，`tarfile` 报 `bad checksum`。我第一次就是读 5 行踩了这个坑。

### 6A.2 目录结构

```
apps/<包名>/
  _manifest              ← 文件清单（protobuf）
  a/base.apk             ← 安装包
  r/                     ← 运行时数据（≈ /data/data，**业务库在这里**）
  f/                     ← 外部存储（≈ /sdcard/Android/data）
  db/                    ← 数据库副本（部分 app 有）
  sp/                    ← SharedPreferences
  d_sp/                  ← 设备级 SharedPreferences
```

### 6A.3 列表与提取（流式，不落盘全解）

```python
import tarfile
f = open(bak, 'rb'); f.seek(start)
tf = tarfile.open(fileobj=f, mode='r|')     # 流式：大文件（1 GB+）也不爆内存
for m in tf:
    if m.isdir(): continue
    if 关键词 in m.name:
        data = tf.extractfile(m).read()
```

**判据**：微信备份 4970 个文件 / 抖音 18874 个文件，**绝不要全解**。先按名字过滤。

### 6A.4 必查的 sp 文件（一文件多答案）

| 文件 | 含什么 |
|---|---|
| `sp/login_user_info.xml` | 登录用户全部信息（userId/token/昵称/手机号/头像/VIP） |
| `sp/authStatus_<pkg>.xml` | 是否已登录、绑定手机号 |
| `sp/com.android.browser_preferences.xml` | 浏览器主页、UA |
| `WLAN设置(com.android.settings).bak` | WiFi SSID / 密码 |
| `sp/msgzpfc.xml` | 消息推送配置 |

**龙信杯实例**：`apps/com.app.siyu/sp/login_user_info.xml` 里的 `initActModel` JSON 直接给出「晋江」「支付宝开关」等全部业务开关——但**用户身份在数据库里，不在 sp 里**。

### 6A.5 必查的数据库表（国产 IM 通用）

| 表名 | 内容 |
|---|---|
| `AUTH_INFO` | `USER_ID` / `TOKEN` / `LAST_LOGIN_USER` |
| `CHAT_USER` | 本人 `NICK_NAME` / `MOBILE` / `AVATAR` / `GENDER` |
| `CONTACT` | 全部联系人（`USER_ID` / `NICK_NAME` / `REMARK` / `MOBILE`） |
| `CHAT_MESSAGE` | 消息：`CONTENT`（可能是明文）/ `ORIGIN_CONTENT`（base64）/ `TYPE` / `MSG_TIME_STAMP` |
| `CONVERSATION` | 会话名 + `UPDATE_TIME_STAMP`（**按此排序找最近的会话**） |
| `GROUP` | 群信息（`GROUP_NAME` / `GROUP_INTRODUCTION`） |
| `COMMAND_MESSAGE` | 系统消息（入群、好友申请） |

**最强判据**：`CHAT_MESSAGE.CONTENT` 是明文中文、`ORIGIN_CONTENT` 是 base64 → **CONTENT 就是答案，不用解密**。

龙信杯 6 道题全靠这条：
```
_2  "请查看字段核验清单，文件不应转发到其他会话。\n[附件：字段核验清单.xlsx]"
_3  "清单中共有4列，分别是收派状态、区域、日期、物流编码。"
_4  "请确认配送页面四项信息的第一项为"收派状态"。"
_5  "需要保全的三项电子数据是：文件名、版本号、权限提示时间。"
_6  "客户明细不通过聊天发送；这里只核对字段名称，不讨论具体客户信息。"
```

### 6A.6 会话排序找"核心"

```sql
select SESSION_ID, NAME, UN_READ_NUM, UPDATE_TIME_STAMP
from CONVERSATION order by UPDATE_TIME_STAMP;
```

题面说「**核心**聊天记录」→ 找名字异常（如「合规核验组」「从字段核验清单导入的聊天记录」）或时间异常的那个会话，不是消息最多的。

---

## 六B、protobuf 类数据（联系人 / 短信 / 通话）

小米备份里联系人、短信、通话记录是 **protobuf 二进制**，不是 SQLite。表结构未知时手工解析：

```python
def varint(buf, i):
    v = s = 0
    while True:
        c = buf[i]; v |= (c & 0x7f) << s; i += 1
        if not c & 0x80: return v, i
        s += 7

def walk(buf, depth=0, out=None):
    """通用 protobuf 遍历：wt=0 varint, wt=2 length-delimited, wt=5 fixed32, wt=1 fixed64"""
    if out is None: out = []
    i = 0
    while i < len(buf):
        try: key, i = varint(buf, i)
        except Exception: break
        f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(buf, i); out.append((depth, f, 'varint', v))
        elif wt == 2:
            ln, i = varint(buf, i); data = buf[i:i+ln]; i += ln
            try:
                s = data.decode('utf-8')
                if s.isprintable() and s.strip():
                    out.append((depth, f, 'str', s)); continue
            except Exception: pass
            out.append((depth, f, 'msg', None)); walk(data, depth+1, out)
        elif wt == 5: i += 4
        elif wt == 1: i += 8
        else: break
    return out
```

**反推字段含义的判据**：

| 观察 | 结论 |
|---|---|
| 11 位数字（可能带空格分组如 `189 9965 5661`） | 手机号 |
| 2–4 个汉字，且与另一个汉字串同行 | 姓名（全名/昵称/姓氏各占一字段） |
| `f2 = varint 2` | 类型枚举（2 = 手机号） |
| 单字符 `f4` | 姓氏首字（用于拼音排序） |

**短信实例**：
```
f2='1'                                        ← 记录序号
f4='<SMSC_NUMBER>'                        ← 发送方号码（106 开头 = 服务号）
f6='【腾讯科技】你正在登录微信，验证码445123…'   ← 正文
f12='+460030934775200'                        ← SMSC 中心号
```

**判据**：短信正文里的验证码就是题面问的「动态验证码」，`f4` 是服务号。若题面问「获取动态验证码的**应用**」，看服务号含义（`<SMSC_NUMBER>` → 腾讯 → 微信）。

---

## 六C、加密数据库但密钥不在检材（情况2 实证）

**问题**：拿到 `EnMicroMsg.db` 却是密文，密钥要从 IMEI+uin 算，而 IMEI 在另一份被全盘加密的镜像里 → 死锁。

### 6C.1 微信密钥规则演进（先判版本，别盲试）

| 版本 | 密钥来源 | 长度 | 可枚举性 |
|---|---|---|---|
| WeChat 3.x / 6.x | `MD5(IMEI + uin)[:7]` | 7 位十六进制 | **可枚举**（IMEI 15 位数字，实际常是空串或全 0） |
| WeChat 4.x（2024 后） | `androidId + uin` 派生，存于 `EnMicroMsg.db.sm` 或 mmkv | 32 字节 raw | **不可枚举** |

**判据**：看 `.sm` 文件存不存在。有 `.sm` → 4.x。

龙信杯实测（WeChat 4.1.13）：
```
apps/com.tencent.mm/r/MicroMsg/<hash>/
  EnMicroMsg.db        1081344 B   头 = 69b17799...（非 SQLite 明文）
  EnMicroMsg.db.sm       19963 B   ← 4.x 才有
```

### 6C.2 已知线索的提取位置（一个都不能少）

| 线索 | 位置 | 龙信杯实际值 |
|---|---|---|
| **uin** | `sp/auth_info_key_prefs.xml` 的 `_auth_uin` | `-598263202` |
| | `sp/com.tencent.mm_preferences.xml` 的 `last_login_uin` | `3696704094` |
| 微信号 | `com.tencent.mm_preferences.xml` 的 `login_weixin_username` | `wxid_7xmmiqfl9dwb22` |
| 绑定手机 | 同文件 `login_user_name` | `13900139000` |
| **androidId** | ❌ **MIUI 备份不含** | 无法获取 |

### 6C.3 纯 Python SQLCipher 解密器（Python 3.13 装不上 sqlcipher3 时用这个）

`sqlcipher3-binary` 在 Python 3.13 上**没有预编译轮子**，pip 装不上。自己实现：

```python
import hmac, hashlib, struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def decrypt_page1(dbpath, password: bytes, kdf_iter=256000, algo='sha512',
                  page_size=4096, hmac_size=64, reserve=80):
    """SQLCipher 4 页结构：salt(16) | IV(16) | ciphertext | HMAC(64) | padding"""
    with open(dbpath, 'rb') as f:
        page1 = f.read(page_size)
    salt = page1[:16]
    key = hashlib.pbkdf2_hmac(algo, password, salt, kdf_iter, 32)
    body = page1[16:]                      # 跳过 salt
    iv, ct = body[:16], body[16:page_size - reserve - 16 + 16]
    usable = page_size - 16 - 16 - hmac_size
    ct = body[16:16 + usable - 16]
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = d.update(ct) + d.finalize()
    return b'SQLite format 3' in pt[:32], pt[:16]
```

**先验证页结构对不对**（这一步能区分"密码错"和"代码错"）：

```python
d = open(DB, 'rb').read(4096)
assert os.path.getsize(DB) % 4096 == 0        # 页对齐
print('salt:', d[:16].hex())                  # 16B
print('IV  :', d[16:32].hex())                # 16B
print('HMAC:', d[-64:].hex())                 # 64B
```

三条都对 → 代码没问题，是密码不对。

### 6C.4 决策树：密钥找不到时的 7 条路

```
1. 应用自己的配置        sp/*.xml、files/、databases/
2. 系统唯一标识          androidId / IMEI / serial / build.prop
3. 备份文件明文           MIUI .bak 的 sp/、iTunes 的 Info.plist
4. 内存镜像              vol3 + strings 搜库路径
5. 另一份检材            PC 端 adb/MTP 握手日志
6. 暴力                  仅 3.x 的 7 位十六进制有意义
7. 降级目标 ← 最后这条最实用
```

**第 7 条是正解**：拿不到库就取别的。龙信杯 6 道题全靠这条——明文库 `sy_chat_imPROD_SY.db` 里有一切，微信/抖音/高德全是加密的。

### 6C.5 什么时候该停

出现这两条的任意一条，立刻标 ⬜ 并转去降级目标：

1. 密钥是 4.x 的 32 字节 raw，且 `androidId` 不在任何检材里
2. 密钥依赖的文件所在镜像本身被全盘加密（FDE），且没有恢复密钥

**龙信杯结论**：微信库 6C.3 的 13 个候选密码（含 3.x 的 `MD5(imei+uin)[:7]` 9 种）全灭，
因为 4.x 需要 `androidId`，而 MIUI 备份不备份它。**这题本来就无解**，出题人的意图就是让你拿明文库。

### 6C.6 已安装的能力

```python
# 纯 Python，无需 sqlcipher3
from sqlcipher_py import decrypt_page1
# 或者用官方的（Python ≤3.11）
# pip install sqlcipher3-binary
```

---

## 七、图片/视频取证

### 7.1 扩展名伪造

按文件头 magic 判断真实类型：

| 类型 | 魔数 |
|---|---|
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| JPEG | `FF D8 FF` |
| GIF | `47 49 46 38` |
| BMP | `42 4D` |
| HEIC/MP4 | `00 00 00 xx 66 74 79 70`（`ftyp`）后跟 brand |
| ZIP/DOCX | `50 4B 03 04` |
| PDF | `25 50 44 46` |

```python
def sniff_magic(d):
    if d[:8] == b'\x89PNG\r\n\x1a\n': return 'png'
    if d[:3] == b'\xff\xd8\xff': return 'jpg'
    if d[4:8] == b'ftyp':
        return 'heic' if d[8:12] in (b'heic', b'mif1', b'msf1') else 'mp4'
    if d[:4] == b'PK\x03\x04': return 'zip'
    ...
```

### 7.2 EXIF

```python
import exifread
with open(path,'rb') as f:
    tags = exifread.process_file(f)
```

关注：`EXIF DateTimeOriginal`、`Image Make/Model`、`GPS` 字段。

### 7.3 视频帧 OCR

```bash
ffmpeg -i video.mp4 -vf "fps=1/2" frame%03d.png
tesseract frame001.png stdout -l eng --psm 6
```

截图类检材常用：放大 3x + `--psm 6` 或 `--psm 11` 效果最好。

## 八、OCR 技巧

### 8.1 首选：rapidocr（中文准，无需语言包）

```python
from rapidocr_onnxruntime import RapidOCR
ocr = RapidOCR()
res, _ = ocr(path)                 # res = [[box4pts, text, score], ...]
for box, txt, score in (res or []):
    print('%.3f  %s' % (float(score), txt))
```

- 中文识别质量远高于 tesseract（面单里的「苏州市工业园区星湖街328号创意产业园6幢6楼」一次就对）
- 速度约 **0.56 s/张**（1281 张 ≈ 38 分钟），**挂后台跑**
- 输出带坐标，可按 `box[0][1]`（y 坐标）分行、按 `box[0][0]`（x 坐标）分列
- 断点续传：结果每 50 张存一次 JSON，重跑时跳过已完成的

### 8.2 tesseract（备选，需注意语言包）

```powershell
& 'C:\Program Files\Tesseract-OCR\tesseract.exe' img.jpg stdout `
  --tessdata-dir G:\tessdata -l chi_sim+eng --psm 6
```

| 场景 | 参数 |
|---|---|
| 手机截图 | `--psm 6` |
| 小字 | 3× 双三次放大后 |
| 单行标题 | `--psm 7` |
| 稀疏文本 | `--psm 11` |
| 多列排版（面单） | `--psm 4` 或 `--psm 11`，`--psm 6` 会串行 |

**坑**：默认安装只有 `eng` + `osd`，没有 `chi_sim`。且 `C:\Program Files\Tesseract-OCR\tessdata` 是**受保护目录，写不进去**——要下到 `G:\...\tessdata` 再用 `--tessdata-dir` 指过去。

```powershell
Invoke-WebRequest -Uri 'https://ghfast.top/https://github.com/tesseract-ocr/tessdata_fast/raw/main/chi_sim.traineddata' -OutFile "$env:TEMP\tessdata\chi_sim.traineddata"
```

即便装上，中文识别仍明显不如 rapidocr（面单地址常错成「市匡区旦清28二人」）。**能用 rapidocr 就别折腾 tesseract。**

### 8.3 批量统计类题目

OCR 全量跑完后，用关键词统计，不要抽检：

```python
import re, collections
recs = {name: ' '.join(l[0] for l in lines) for name, lines in ocr_json.items()}

# 某姓名出现几张
print(sum(1 for t in recs.values() if '周平' in t))

# 手机号后四位分布
c = collections.Counter()
for t in recs.values():
    m = re.findall(r'1[3-9]\d{9}', t)
    if m: c[m[-1][-4:]] += 1
print(c.most_common(10))
```

**判据**：题面问「有几个 / 最多 / 合计」→ 必须全量统计。抽检 5 张就给答案是失分点。

## 九、明文库普查（手机取证的第一步，别跳过）

**核心认知**：主流 app 的库**不全是加密的**。龙信杯实测推翻了我的错误判断：

| app | 数据库数 | 明文 | 加密 |
|---|---|---|---|
| 思语 `com.app.siyu` | 13 | **13** | 0 |
| 抖音 `com.ss.android.ugc.aweme` | 45 | **32** | 13 |
| 高德 `com.autonavi.minimap` | 34 | **22** | 12 |
| 微信 `com.tencent.mm` | — | 少 | `EnMicroMsg.db` |

我之前以为"抖音全是 `encrypted_*`"——错。45 个库里 32 个是明文。

### 9.1 普查脚本（5 分钟摸清全部检材）

```python
import tarfile, os, sys
sys.path.insert(0, r'<CASE_DIR>')
from miui_bak import find_ab_start

def survey(bak_path):
    st, meta = find_ab_start(bak_path)
    if st is None:
        return []
    f = open(bak_path, 'rb'); f.seek(st)
    tf = tarfile.open(fileobj=f, mode='r|')
    out = []
    for m in tf:
        if not m.isfile() or not m.name.endswith(('.db', '.sqlite')):
            continue
        try:
            head = tf.extractfile(m).read(16)
        except Exception:
            continue
        out.append((m.name, m.size, head == b'SQLite format 3\x00'))
    f.close()
    return out

for bak in glob.glob(r'<备份目录>\*.bak'):
    rows = survey(bak)
    plain = [r for r in rows if r[2]]
    print('%-46s 库%-3d 明文%-3d 加密%-3d' % (
        os.path.basename(bak), len(rows), len(plain), len(rows) - len(plain)))
    for nm, sz, _ in sorted(plain, key=lambda x: -x[1])[:5]:
        print('    PLAIN %9d  %s' % (sz, nm))
```

**判据**：先跑这个，把**明文库挑出来**。龙信杯 6 道题的答案全在
`apps/com.app.siyu/db/sy_chat_imPROD_SY.db` 一个文件里。

### 9.2 一个库答多题：思语实例

`sy_chat_imPROD_SY.db`（233 KB，16 张表）：

| 表 | 行数 | 能答什么 |
|---|---|---|
| `AUTH_INFO` | 1 | 登录用户 USER_ID / TOKEN |
| `CHAT_USER` | 1 | **本人**昵称/手机/头像/性别 |
| `CONTACT` | 13 | 全部联系人 |
| `CONVERSATION` | 13 | 会话名 + `UPDATE_TIME_STAMP`（按此排序找最近） |
| `CHAT_MESSAGE` | **52** | 消息正文（`CONTENT` 明文） |
| `COMMAND_MESSAGE` | 7 | 系统消息（入群、好友申请） |
| `GROUP` | 3 | 群名 / 群公告 / 群简介 |

配套两个库：

| 库 | 表 | 用途 |
|---|---|---|
| `siyu_x.db` | `sy_friendlist`(9) / `sy_label`(2) | 好友列表、标签分组 |
| `userEvent.db` | `EVENT`(117) | **埋点事件**（含时间、会话名，可还原操作序列） |

**判据**：`CHAT_MESSAGE.CONTENT` 是明文中文 → 直接读，不用解密。
`ORIGIN_CONTENT` 是 base64，`CONTENT` 已经解好了。

### 9.3 `EVENT` 表：先看类型分布，再决定要不要用

`userEvent.db` 的 `EVENT` 表字段：
```
_id  EVTID  EVTTYPE  CONTENT  EVTTIME  SERVICETAG  SESSIONID  SESSIONNAME
```

**龙信杯实测**（117 行）——全是噪声：

```
$ExitScreen     58
$EnterScreen    55
$LaunchApp       3
$AppFirstOpen    1
```

**118 条里 113 条是屏幕进出**，没有业务价值。

**正确做法**：先统计 `EVTID` 分布，不要直接全量列出来。

```sql
SELECT EVTID, COUNT(*) FROM EVENT GROUP BY EVTID ORDER BY 2 DESC;
```

**判据**：
- 全是 `$EnterScreen`/`$ExitScreen` → 埋点库无效，转去 `CHAT_MESSAGE`
- 有业务事件（`$Click`/`$Pay`/`$Search` + 具体页面名）→ 能还原操作序列

**别把时间浪费在埋点库上**。龙信杯我在 117 行噪声里翻了半天，实际答案全在 52 行 `CHAT_MESSAGE` 里。

## 十、Android 特有数据源

### 10.1 应用私有目录布局

```
/data/data/<pkg>/
  databases/*.db          ← 业务库（首选）
  shared_prefs/*.xml      ← 登录态、配置（明文 XML）
  files/                  ← 缓存、下载
  cache/
  lib/                    ← so 库（判加密方式）
  no_backup/              ← 不参与备份的（有时有密钥）
/data/media/0/            ← 内部存储（SD 卡）
  Android/data/<pkg>/
  DCIM/  Download/  Pictures/  Movies/
  tencent/  ← 微信/QQ 的媒体
```

MIUI 备份对应：

| Android | MIUI .bak |
|---|---|
| `/data/data/<pkg>/` | `apps/<pkg>/r/` |
| `/sdcard/Android/data/<pkg>/` | `apps/<pkg>/f/` |
| `shared_prefs/` | `apps/<pkg>/sp/` |
| `databases/` | `apps/<pkg>/db/` 或 `r/` 里的 `*.db` |

### 10.2 短信（MMS/SMS）

```
/data/data/com.android.providers.telephony/databases/mmssms.db
  sms      短信（address/body/date/type/read）
  threads  会话
  pdu      彩信
```

**date 是毫秒 epoch**。`type` 1=收 2=发。

MIUI 备份里是 **protobuf**（`短信(com.android.mms).bak`），不是 SQLite。
见第六章 B 的 protobuf 解析。

### 10.3 通话记录

```
/data/data/com.android.providers.contacts/databases/calllog.db
  calls    number/date/duration/type
```

`type`：1=来电 2=去电 3=未接 4=语音信箱 5=拒接 6=拉黑

**判据**：题问「打了多久」→ `duration` 秒；「几个未接」→ `type=3` 计数。

### 10.4 通讯录

```
/data/data/com.android.providers.contacts/databases/contacts2.db
  raw_contacts   原始联系人
  data           所有字段（电话/邮箱/地址），靠 mimetype_id 区分
  mimetypes
```

`data.mimetype_id` 对照：

| id | 内容 |
|---|---|
| 1 | 邮箱 |
| 4 | 即时通讯 |
| 5 | **电话** |
| 7 | 昵称 |
| 10 | 备注 |

### 10.5 位置与轨迹

| 来源 | 路径 |
|---|---|
| 系统位置历史 | `/data/data/com.google.android.gms/databases/` |
| 高德 | `.../com.autonavi.minimap/db/aMap.db` |
| 百度地图 | `.../com.baidu.BaiduMap/db/` |
| 照片 EXIF GPS | `DCIM/Camera/*.jpg` |
| WiFi 扫描记录 | `/data/misc/wifi/WifiConfigStore.xml` |

### 10.6 通知记录（安卓 11+）

```
/data/data/<pkg>/databases/notification_log.db
```

**能答**：「收到过什么通知」「几点推的」。比聊天库多一层佐证。

### 10.7 剪贴板与输入法

| 内容 | 路径 |
|---|---|
| 剪贴板历史 | `com.android.clipboard` 相关库 |
| 百度输入法 | `com.baidu.input_mi/db/` 的**输入历史**（可能含密码） |
| 搜狗输入法 | `com.sohu.inputmethod.sogou/db/` |

**判据**：题问「输入过什么」→ 输入法库是唯一来源。

## 十一、Android 反取证识别

| 手法 | 痕迹 |
|---|---|
| 删除聊天记录 | 库变小 + `CHAT_MESSAGE` 行数少；查 `-wal` 恢复 |
| 清应用数据 | `shared_prefs` 空 / 目录 mtime 新但不是首次 |
| 卸载重装 | 包目录 crtime 很新，但 `userEvent.db` 有旧记录 |
| 双开/分身 | `com.tencent.mm` 与 `com.tencent.mm:xxx`、小米「手机分身」用户空间 |
| 隐藏相册 | `.nomedia` 文件、`Android/media/<pkg>` 深目录 |
| 改系统时间 | 照片 EXIF 与文件 mtime 不一致 |

### 11.1 双开/分身的识别

```python
# 包名带后缀
pkgs = [n for n in os.listdir('/data/data') if ':' in n or '_' in n]
# 小米分身：多用户空间
/users/  或  /data/user/10/  /data/user/999/
```

**判据**：`/data/user/` 下若有多于 `0` 个数字目录 → 开了分身，要分别查。

### 11.2 WAL 恢复已删记录

```python
# 必须三件套一起复制，否则 WAL 会被 checkpoint 掉
shutil.copy(db); shutil.copy(db + '-wal'); shutil.copy(db + '-shm')
# 主库用 immutable 打开
con = sqlite3.connect('file:%s?mode=ro&immutable=1' % db, uri=True)
```

或用 `sqlite_tools.py wal <wal文件>`。

**判据**：`-wal` 文件存在且非空 → 有未 checkpoint 的数据，可能含已删记录。


## 相关章节

- `case2.md` —— 加密库密钥找不到时的 7 条路
- `network.md` —— 手机流量与 pcap 关联
- `windows.md` —— 手机备份存在 PC 镜像里时
- `traps.md` —— OCR 与批量统计陷阱
- `quickwin.md` —— 三档分类与源×题矩阵
