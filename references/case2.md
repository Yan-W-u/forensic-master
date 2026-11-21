# 情况2：加密数据库但密钥不在检材

**典型死锁**：拿到 `EnMicroMsg.db` 是密文，密钥要 IMEI+uin，而 IMEI 在另一份被全盘加密的镜像里。

---

## 一、微信密钥规则演进（先判版本，别盲试）

| 版本 | 密钥来源 | 长度 | 可枚举性 |
|---|---|---|---|
| WeChat 3.x / 6.x | `MD5(IMEI + uin)[:7]` | 7 位十六进制 | **可枚举**（IMEI 常是空串或全 0） |
| WeChat 4.x（2024 后） | `androidId + uin` 派生 | 32 字节 raw | **不可枚举** |

**判据**：看 `.sm` 文件存不存在。有 `.sm` → 4.x。

龙信杯实测（WeChat 4.1.13）：
```
apps/com.tencent.mm/r/MicroMsg/<hash>/
  EnMicroMsg.db        1081344 B   头 = 69b17799...（非 SQLite 明文）
  EnMicroMsg.db.sm       19963 B   ← 4.x 才有
```

---

## 二、已知线索的提取位置（一个都不能少）

| 线索 | 位置 | 龙信杯实际值 |
|---|---|---|
| **uin** | `sp/auth_info_key_prefs.xml` → `_auth_uin` | `-598263202` |
| | `sp/com.tencent.mm_preferences.xml` → `last_login_uin` | `3696704094` |
| 微信号 | `com.tencent.mm_preferences.xml` → `login_weixin_username` | `wxid_7xmmiqfl9dwb22` |
| 绑定手机 | 同文件 → `login_user_name` | `13900139000` |
| **androidId** | ❌ **MIUI 备份不含** | 无法获取 |

---

## 三、纯 Python SQLCipher 解密器

`sqlcipher3-binary` 在 **Python 3.13 上没有预编译轮子**，pip 装不上。自己实现：

```python
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def decrypt_page1(dbpath, password: bytes, kdf_iter=256000, algo='sha512',
                  page_size=4096, hmac_size=64, reserve=80):
    """SQLCipher 4 页结构：salt(16) | IV(16) | ciphertext | HMAC(64) | padding"""
    with open(dbpath, 'rb') as f:
        page1 = f.read(page_size)
    salt = page1[:16]
    key = hashlib.pbkdf2_hmac(algo, password, salt, kdf_iter, 32)
    body = page1[16:]                                  # 跳过 salt
    iv = body[:16]
    usable = page_size - 16 - 16 - hmac_size
    ct = body[16:16 + usable - 16]
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = d.update(ct) + d.finalize()
    return b'SQLite format 3' in pt[:32], pt[:16]
```

**先验证页结构对不对**（区分"密码错"和"代码错"）：

```python
d = open(DB, 'rb').read(4096)
assert os.path.getsize(DB) % 4096 == 0     # 页对齐
print('salt:', d[:16].hex())               # 16B
print('IV  :', d[16:32].hex())             # 16B
print('HMAC:', d[-64:].hex())              # 64B
```

三条都对 → 代码没问题，是密码不对。

龙信杯实测页结构确认：
```
salt : 69b17799f03a6917a944b724c703e54a
IV   : 36f108a8aa9195bfb8dd6f838eeebf1a
HMAC : af060b6bf6acdbb37e726a497a61afeb...  (64B)
文件大小 1081344 = 4096 × 264 页 ✅
```

---

## 四、决策树：密钥找不到时的 7 条路

```
1. 应用自己的配置     sp/*.xml  files/  databases/
2. 系统唯一标识       androidId / IMEI / serial / build.prop
3. 备份文件明文       MIUI .bak 的 sp/  iTunes 的 Info.plist
4. 内存镜像           vol3 + strings 搜库路径
5. 另一份检材         PC 端 adb/MTP 握手日志
6. 暴力               仅 3.x 的 7 位十六进制有意义
7. 降级目标 ← 最实用
```

### 4.1 第 1 条：应用配置

```python
import tarfile, os
tf = tarfile.open(fileobj=f, mode='r|')
for m in tf:
    if m.name.endswith('.xml') and 'shared_prefs' in m.name:
        d = tf.extractfile(m).read()
        hits = [l for l in d.decode('utf-8','replace').splitlines()
                if any(k in l.lower() for k in ('key','uin','token','user','imei'))]
```

### 4.2 第 2 条：系统标识

```python
PAT = re.compile(rb'(android_?[Ii]d|imei|meid|serialno|ro\.serial|device_?id)', re.I)
# 在设置/手机管家/系统桌面等 .bak 里找
```

**MIUI 备份不备份 androidId**（实测：搜遍 5 个系统 .bak 全部无命中）。

### 4.3 第 3 条：备份明文

MIUI `.bak` 的 `sp/` 目录常常直接有密钥类配置。这是命中率最高的一条。

### 4.4 第 4 条：内存镜像

```powershell
vol -f mem.raw windows.memmap.Memmap --pid <PID> --dump
# 然后在 dump 里 strings 搜库路径附件
```

### 4.5 第 5 条：跨检材

手机备份没 IMEI → 看 PC 镜像里的 `adb` 记录、MTP 握手日志、`AppData\Local\Temp\adb*`。

### 4.6 第 6 条：暴力

只在 3.x 有意义（7 位十六进制，IMEI 空间 15 位数字但实际常为空/全 0）：

```python
for imei in ('', '0', '000000000000000'):
    for uin in uins:
        k = hashlib.md5((imei + uin).encode()).hexdigest()[:7]
```

### 4.7 第 7 条：降级目标（最实用）

拿不到库就取别的。**龙信杯 6 道题全靠这条。**

| 降级目标 | 位置 |
|---|---|
| 明文聊天库 | 小众 IM 的库常常不加密（龙信杯 `sy_chat_imPROD_SY.db`） |
| 聊天中的附件 | `/sdcard/tencent/MicroMsg/<hash>/image2/` |
| 通讯录 | `/data/data/com.android.providers.contacts/` |
| 朋友圈缓存 | `sns/` |
| 备份里的 db 副本 | `.bak` 的 `db/` 目录 |

---

## 五、什么时候该停

出现这两条的任意一条，立刻标 ⬜ 转降级目标：

1. 密钥是 4.x 的 32 字节 raw，且 `androidId` 不在任何检材里
2. 密钥依赖的文件所在镜像本身被全盘加密（FDE），且没有恢复密钥

**龙信杯结论**：13 个候选密码（含 3.x 的 `MD5(imei+uin)[:7]` 9 种）全灭。
4.x 需要 `androidId`，MIUI 备份不备份它 → **这题本来就无解**，
出题人意图就是让你拿明文库 `sy_chat_imPROD_SY.db`。

---

## 六、抖音 / 其他 app 的加密库

| app | 库 | 加密方式 | 出路 |
|---|---|---|---|
| 抖音 | `encrypted_*` | 自定义（native 层） | 找 `sp/` 里的明文配置；或放弃 |
| 高德 | 大量 `.dat` | 部分加密 | 找 `Documents/` 的 GPS 轨迹明文 |
| 支付宝 | `*.db` | 部分明文 | 先试 `PRAGMA integrity_check` |
| 淘宝 | `*.db` | 明文常见 | 直接开 |

**通用判据**：文件头是不是 `SQLite format 3\x00`。

```python
heads = {}
for p in glob.glob('**/*.db', recursive=True):
    h = open(p, 'rb').read(16)
    heads[p] = 'PLAIN' if h == b'SQLite format 3\x00' else 'ENCRYPTED'
```

**先跑这个，把明文库挑出来** —— 龙信杯就是靠它 5 分钟定位到 `sy_chat_imPROD_SY.db`。


## 相关章节

- `mobile.md` —— Android 数据源清单
- `containers.md` —— 密钥链派生
- `traps.md` —— 密码相关陷阱
- `quickwin.md` —— 降级目标优先
