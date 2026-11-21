# 速赢法：源 × 题 矩阵

**解决什么问题**：题目多（50–150 题）、检材杂、时间有限时，怎么在头 30 分钟内把"一个文件能答 6 题"的格子全清掉，而不是随机挑一个应用开始挖。

**龙信杯教训**：手机 15 题，我先啃微信/抖音/高德（全加密，零产出，30 分钟），真正的答案在一个明文 SQLite 里，一个文件答了 6 题。这 6 题本可以在第 15 分钟拿到。

---

## 一、三步走

### 第 0 步（新增，最重要）：给每题分档

在做矩阵之前，先把题分成三档。**这决定了你的时间花在哪。**

| 档 | 判据 | 单题成本 | 成功率 | 龙信杯占比 |
|---|---|---|---|---|
| **A 不用密钥** | 明文配置/日志/字符串/文件名/时间戳/哈希 | 1–5 min | >80% | 约 40% |
| **B 解一薄层** | 解压缩/XOR/TLV/protobuf/pcap，不需密钥 | 5–15 min | ~70% | 约 30% |
| **C 密钥链** | HKDF/AES/密码派生，密钥可能不在检材 | 30 min+ | <50% | 约 30% |

**执行顺序 A → B → C，不许颠倒。**

**A 档的典型位置**（龙信杯实测，1 分钟出答案）：

| 题类型 | 去哪找 | 实测 |
|---|---|---|
| systemd 服务名 | `/etc/systemd/system/*.service` | `dq-bootstrap.service` |
| 容器名/镜像标签 | `docker/containers/*/config.v2.json` | `dqmain-gate-1` |
| 挂载/源码目录 | 同上 `MountPoints` | `/run/dq-runtime/app` |
| 数据库路径 | `docker-compose.yml` 的 env | `/data/challenge.db` |
| **文件时间新旧** | `stat` 对比 mtime | `crypto-agent.core` 早 1 小时 → 原始核心 |
| 清理顺序 | cleanup 脚本的 `stop_service` 调用序 | gate → app → port80 → runtime |
| 业务端口 | nginx `listen` | 不是 `.env` 的 `PORT` |
| 文件哈希 | 直接 sha256 | `2bb1a463...` |

**判据**：看到题目先问「这个值会不会以明文躺在某个配置文件里」。
会 → A 档，立刻去读。不会 → 再往下判。

### 第 0.5 步：A 档也要验证，别拿第一个匹配

A 档快，但**快不等于可以随便取第一个**。龙信杯实测两个坑：

**坑 1：同名多服务，`-guard` 是假的**

```
/etc/systemd/system/
  dq-bootstrap.service          351 B  Description=DQ Main Bootstrap
                                      ExecStart=/opt/delivery-query/bin/crypto-agent
                                      ExecStopPost=/usr/local/libexec/dq-cleanup
  dq-bootstrap-guard.service    348 B  Description=DQ Main Fail-Closed Guard V3.4.7
                                      ExecStart=/opt/delivery-query/bin/dq-bootstrap-guard
```

`for f in *dq*.service` 拿到的第一个是 **`-guard`**——那是故障保护，
不是题目问的「负责完整启动查询系统的服务」。**必须读 `Description` 和 `ExecStart` 才能区分。**

**判据**：
- `Description` 含 `Guard` / `Fail-Closed` / `Watchdog` → 防护服务，不是主服务
- `ExecStart` 指向 `*-guard`、`*-watchdog`、`*-monitor` → 同上
- 主服务通常带 `ExecStopPost`（清理钩子）和 `WantsBy=multi-user.target`

**坑 2：同名多个二进制，看 mtime**

```
/opt/delivery-query/bin/
  crypto-agent.core        3461560  02:53:52   ← 最早，原始核心
  dq-failclosed-cleanup       2973  03:50:04
  crypto-agent                1215  03:50:05   ← wrapper
  dq-bootstrap-guard           947  03:50:05
```

题面问「系统后期调整前使用的原始核心启动程序」→ 按 mtime 取最早的。
但问「当前实际执行的程序」→ 取 `ExecStart` 指的那个（wrapper）。

**两个问法答案不同，读题时必须分清「原始」和「当前」。**

### 第 0.6 步：A 档的验证成本很低

既然 A 档每项只要 0.5–1 秒，就没有理由不验证：

```python
# 拿全部候选，而不是第一个
cands = [n for n in ls('/etc/systemd/system') if 'dq' in n and n.endswith('.service')]
for c in cands:
    body = read('/etc/systemd/system/' + c)
    desc = grep('Description', body)
    exe = grep('ExecStart', body)
    print('%-40s %-40s %s' % (c, desc, exe))   # 一眼看出哪个是主服务
```

**判据**：候选 ≤ 5 个时全部打印对比；> 5 个时按 `Description` 关键词过滤。

### 第 1 步：源 × 题矩阵

分档之后做矩阵，把「一个文件答多题」的格子先清掉。

### 第 1 步：从题面抽实体关键词（5 分钟）

不做技术分析，纯文本处理。每题抽三类词：

| 类型 | 例（龙信杯原题） |
|---|---|
| **具名实体** | 小区名、账号昵称、手机号尾号、姓名、文件名 |
| **结构特征** | "几列""四类信息""第三项""多少个""最多" |
| **格式提示** | `[标准格式：xxx]` 里的样例——**这是出题人的答案模板，不是答案** |

关键判据：**题面里出现"核心""最"「明确」这类词，说明答案在少数几个关键记录里，不在海量数据里。**

> 原题「对手机检材中的**核心**聊天记录进行分析，嫌疑人使用的聊天软件是？」——"核心"两个字直接指向「有组织性对话的那个会话」，不是主流的微信。答案「思语」。

### 第 2 步：列候选数据源（10 分钟）

**不要只列主流的**。把检材里所有可读的数据源按"覆盖题数估计"排序：

```
Android 手机备份：
  □ 每个 app 的数据库清单（.db / .sqlite）
  □ 每个 app 的 shared_prefs（登录态、昵称、手机号）
  □ 联系人 / 短信 / 通话（常是 protobuf，不是 SQLite）
  □ 浏览器 History / Cookies
  □ 系统设置、WLAN、应用锁

Windows 磁盘：
  □ 注册表（SOFTWARE/SYSTEM/SAM/NTUSER）
  □ 事件日志 evtx
  □ Prefetch / Amcache / ShimCache / SRUM / BAM
  □ 应用配置目录（AppData\Roaming\<app>）
  □ 用户文档 / 桌面 / 下载

Linux 服务器：
  □ /etc/systemd/system/*.service
  □ /opt/*/docker-compose*.yml
  □ /var/lib/docker/containers/*/config.v2.json
  □ /var/log/auth.log（sudo 记录）
  □ 各服务的 config/*.json

流量：
  □ 接口清单（pcapng 的 if_name）
  □ 协议前缀分布（正则提取每条 data.data 的前 4–8 字符）
```

### 第 3 步：填矩阵，从高分格开始

| 数据源 | 能答的题 | 题数 | 读完耗时 | 优先级 |
|---|---|---|---|---|
| `sy_chat_imPROD_SY.db` | 6,7,8,9,10,11 | 6 | 3 min | **P0** |
| 注册表 SOFTWARE | 16 | 1 | 2 min | P1 |
| 客户端 exe 解包 | 18,19 | 2 | 8 min | P1 |
| 面单目录 + OCR | 24,25,27,28,48 | 5 | 40 min | P2（先跑后台） |
| 微信 EnMicroMsg.db | 需 IMEI+uin | ? | 依赖加密盘 | P3 |

**规则**：P0 全清完才动 P1。P2 类（OCR、批量解析）**先挂后台跑**，不占前台时间。

---

## 二、常见"一源多题"的位置

按经验排序，这些地方最常一次命中 3 题以上：

| 位置 | 典型命中 |
|---|---|
| **聊天软件的会话+联系人表** | 软件名、昵称、手机号、群名、讨论内容、附件名 |
| **docker-compose.yml + config.v2.json** | 服务名、镜像标签、端口、挂载路径、容器名 |
| **systemd service 文件** | 服务名、ExecStart 路径、依赖顺序、重启策略 |
| **注册表 SOFTWARE\...\Uninstall** | 安装的软件数量、版本、安装路径 |
| **Prefetch 目录** | 程序是否运行、运行次数、最后运行时间 |
| **浏览器 History** | 访问的网址、搜索词、次数 |
| **面单/票据图片的 OCR 结果** | 单号、姓名、电话、地址、重量、件数 |

---

## 三、判据：什么时候该放弃一个源

出现以下任一情况，**立刻换源**，不要继续：

1. 文件头是 `SQLite format 3` 但打开后表全空 → 记录在 `-wal`，先复制三件套；若 `-wal` 也空，是数据没落库
2. 文件熵 > 7.99 且无已知容器魔数 → 加密；**先找密码/密钥，别硬啃**
3. 文件名带 `encrypted_` / `.enc` / `.bin` 且无结构 → 同上
4. 翻了 3 层目录还是只有 `.so` / `.apk` / 图片资源 → 业务数据不在这个 app

**"换源"不是放弃这道题，是把这道题标 🟡 挂起，去做能做的题。** 最后统一回填。

---

## 四、手机备份的候选源清单（MIUI / Android）

`.bak`（MIUI BACKUP）解开后的典型结构：

```
apps/<包名>/
  a/base.apk            ← 安装包（可解包看是不是 PyInstaller/H5）
  r/                    ← 运行时数据（≈ /data/data，**业务库在这里**）
  f/                    ← 外部存储（≈ /sdcard/Android/data）
  db/                   ← 部分 app 的数据库副本
  sp/                   ← SharedPreferences（登录态、昵称、手机号）
```

**必查的 sp 文件**（一文件多答案）：

| 文件 | 含什么 |
|---|---|
| `sp/login_user_info.xml` | 登录用户全部信息（userId/token/昵称/手机号/头像） |
| `sp/authStatus_*.xml` | 是否已登录、绑定的手机号 |
| `sp/com.android.browser_preferences.xml` | 浏览器主页、UA |
| `WLAN设置(com.android.settings).bak` | WiFi SSID/密码 |

**必查的 db 表**：

| 表名模式 | 软件 | 内容 |
|---|---|---|
| `AUTH_INFO` | 多数国产 IM | USER_ID / TOKEN / LAST_LOGIN_USER |
| `CHAT_USER` | 同上 | 本人昵称 / MOBILE / AVATAR |
| `CONTACT` | 同上 | 全部联系人 |
| `CHAT_MESSAGE` | 同上 | 消息正文（可能明文，也可能 `ORIGIN_CONTENT` 加密） |
| `CONVERSATION` | 同上 | 会话名与排序（**按 UPDATE_TIME 排序找最近的**） |

**判据**：如果 `CHAT_MESSAGE.CONTENT` 是明文中文，`ORIGIN_CONTENT` 是 base64 → **CONTENT 就是明文答案，不用解密**。龙信杯 6 题全靠这一条。

---

## 五、protobuf 类数据（联系人、短信、通话）

小米备份里联系人/短信是 **protobuf 二进制**，不是 SQLite。用 `dumpsys` 风格的手工解析：

```python
def varint(buf, i):
    v = s = 0
    while True:
        c = buf[i]; v |= (c & 0x7f) << s; i += 1
        if not c & 0x80: return v, i
        s += 7

def walk(buf, depth=0, out=None):
    if out is None: out = []
    i = 0
    while i < len(buf):
        try: key, i = varint(buf, i)
        except Exception: break
        f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(buf, i); out.append((depth, f, 'v', v))
        elif wt == 2:
            ln, i = varint(buf, i); data = buf[i:i+ln]; i += ln
            try:
                s = data.decode('utf-8')
                if s.isprintable() and s.strip():
                    out.append((depth, f, 's', s)); continue
            except Exception: pass
            walk(data, depth+1, out)
        elif wt == 5: i += 4
        elif wt == 1: i += 8
        else: break
    return out
```

**判据**：字段号固定但含义未知时，用「已知值反推」——看到一串 11 位数字就是手机号，看到 2–4 个汉字就是姓名，`f2=varint 2` 通常是类型枚举（2=手机）。

---

## 六、时间预算参考

| 检材规模 | 读题+分组+矩阵 | 单源深挖 | 全部作答 |
|---|---|---|---|
| 30–50 题，1–2 份检材 | 10 min | 5–15 min/源 | 2–3 h |
| 70–100 题，4–6 份检材 | 20 min | 5–20 min/源 | 4–6 h |
| 100+ 题，含加密容器/固件 | 30 min | 单源可能 1 h | 8–12 h |

**超时信号**：单个数据源超过 20 分钟没有产出任何可填进 `progress.md` 的值 → 换源，标 🟡。


## 相关章节

- `traps.md` —— 失分陷阱清单
- `howto.md` —— 解析作者的实操路径
- `parallel.md` —— 子智能体调度判据
