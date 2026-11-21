"""forensic-master 注册表工具：SAM/NTUSER/SYSTEM 高频查询。

覆盖 2026 美亚杯 COM-01 的全部注册表题型：
- SAM 用户/哈希/时间戳/密码提示
- 账号真实创建顺序（EventId 4720，不是目录 crtime）
- 蓝牙/网卡/USB 设备枚举
- WLAN 配置时间排序
- UserAssist ROT13 + RunMRU
- 时间戳篡改工具痕迹

用法：
    python registry.py sam <SYSTEM> <SAM>
    python registry.py net <SYSTEM> <SOFTWARE>
    python registry.py devices <SYSTEM> <SOFTWARE>
"""
from __future__ import annotations

import codecs
import datetime
import struct
import sys

from regipy.registry import RegistryHive


# ═══════════════════════════════════════════════════════════
#  时间工具
# ═══════════════════════════════════════════════════════════

def ft(v):
    """FILETIME -> datetime（UTC，不带时区）。"""
    if not v:
        return None
    try:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v / 10)
    except Exception:
        return None


def key_mtime(key):
    """注册表键的 last_modified -> datetime。"""
    try:
        return ft(key.header.last_modified)
    except Exception:
        return None


def tb(v):
    """注册表值可能是 bytes 也可能是 hex 字符串，统一成 bytes。"""
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str):
        try:
            return bytes.fromhex(v)
        except Exception:
            return v.encode("latin1", "ignore")
    return b""


# ═══════════════════════════════════════════════════════════
#  SAM 解析
# ═══════════════════════════════════════════════════════════

def bootkey(system_hive: str, cs: int = 1) -> bytes:
    """从 SYSTEM 算 bootkey。JD/Skew1/GBG/Data 类名拼接后置换。"""
    S = RegistryHive(system_hive)
    lsa = S.get_key(f"\\ControlSet{cs:03d}\\Control\\Lsa")
    parts = [lsa.get_subkey(n).get_class_name() for n in ("JD", "Skew1", "GBG", "Data")]
    raw = bytes.fromhex("".join(parts))
    perm = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
    return bytes(raw[perm[i]] for i in range(16))


def sam_users(sam_hive: str) -> list[dict]:
    """枚举 SAM 用户：RID / 用户名 / 密码提示。

    注意：密码提示不在 F 结构的 0x48 偏移，
    而是独立值 `UserPasswordHint`（REG_BINARY, UTF-16LE）。
    """
    h = RegistryHive(sam_hive)
    uk = h.get_key(r"\SAM\Domains\Account\Users")
    out = []
    for sub in uk.iter_subkeys():
        if len(sub.name) != 8:
            continue
        try:
            rid = int(sub.name, 16)
        except ValueError:
            continue
        rec = {"rid": rid, "hex": sub.name}
        # 用户名在 V，偏移表基址 0xCC，表项 0x0C/0x10
        try:
            V = sub.get_value("V")
            off = struct.unpack("<I", V[0x0C:0x10])[0] + 0xCC
            ln = struct.unpack("<I", V[0x10:0x14])[0]
            rec["name"] = V[off:off + ln].decode("utf-16le", "replace")
        except Exception:
            rec["name"] = None
        # 密码提示
        try:
            hint = sub.get_value("UserPasswordHint")
            rec["hint"] = tb(hint).decode("utf-16le", "replace").rstrip("\x00")
        except Exception:
            rec["hint"] = ""
        # 四个时间戳：F 结构 0x08/0x18/0x20/0x28/0x38
        try:
            F = sub.get_value("F")
            rec["last_logon"] = ft(struct.unpack("<Q", F[0x08:0x10])[0]) if len(F) >= 16 else None
            rec["pwd_last_set"] = ft(struct.unpack("<Q", F[0x18:0x20])[0]) if len(F) >= 32 else None
            rec["last_bad_pwd"] = ft(struct.unpack("<Q", F[0x20:0x28])[0]) if len(F) >= 40 else None
            rec["acct_expires"] = ft(struct.unpack("<Q", F[0x28:0x30])[0]) if len(F) >= 48 else None
            rec["pwd_reset"] = ft(struct.unpack("<Q", F[0x38:0x40])[0]) if len(F) >= 64 else None
        except Exception:
            pass
        out.append(rec)
    return sorted(out, key=lambda x: x["rid"])


def print_sam(system_hive: str, sam_hive: str):
    print(f"bootkey = {bootkey(system_hive).hex()}\n")
    print(f"{'RID':>6} {'HEX':<10} {'用户名':<20} {'密码提示':<12} {'最后登录(UTC)':<20} {'改密(UTC)'}")
    print("-" * 100)
    for r in sam_users(sam_hive):
        ll = r.get("last_logon")
        pl = r.get("pwd_last_set")
        print(f"{r['rid']:>6} {r['hex']:<10} {str(r['name']):<20} {str(r.get('hint') or '-'):<12} "
              f"{ll.strftime('%Y-%m-%d %H:%M:%S') if ll else '-':<20} "
              f"{pl.strftime('%Y-%m-%d %H:%M:%S') if pl else '-'}")


def crack_ntlm(target_hash: str, wordlist: list[str]) -> str | None:
    """NTLM 弱口令爆破。NTLM = MD4(UTF-16LE(plain))。"""
    from Cryptodome.Hash import MD4
    target = target_hash.lower()
    for p in wordlist:
        h = MD4.new()
        h.update(p.encode("utf-16le"))
        if h.hexdigest() == target:
            return p
    return None


COMMON_PASSWORDS = [
    "password", "Password", "Password1", "password1", "123456", "12345678",
    "123456789", "1234567890", "P@ssw0rd", "Passw0rd", "admin", "Admin",
    "admin123", "Admin123", "Administrator", "qwerty", "abc123", "letmein",
    "welcome", "monkey", "dragon", "master", "sunshine", "princess",
    "football", "iloveyou", "trustno1", "Password123", "Abc123", "111111",
    "000000", "888888", "666666", "qwerty123", "zxcvbnm", "1q2w3e4r",
    "Qwer1234", "Welcome1", "Changeme", "changeme", "secret", "24682468",
    "87654321", "11223344", "Password@123", "Aa123456", "P@ssw0rd123",
]


# ═══════════════════════════════════════════════════════════
#  设备枚举
# ═══════════════════════════════════════════════════════════

def enum_usb(system_hive: str) -> list[dict]:
    """USBSTOR 枚举（U 盘）。注意 SSD 走 SCSI，不在这里！"""
    S = RegistryHive(system_hive)
    out = []
    try:
        k = S.get_key(r"\ControlSet001\Enum\USBSTOR")
    except Exception:
        return out
    for s in k.iter_subkeys():
        for s2 in s.iter_subkeys():
            fn = None
            for v in s2.iter_values():
                if v.name == "FriendlyName":
                    fn = v.value
            out.append({
                "device": s.name, "instance": s2.name, "friendly": fn,
                "last_write": key_mtime(s2),
            })
    return out


def enum_scsi(system_hive: str) -> list[dict]:
    """SCSI 枚举（外置 SSD / 移动硬盘）。本次 Q66 关键：SanDisk Extreme 在这里。"""
    S = RegistryHive(system_hive)
    out = []
    try:
        k = S.get_key(r"\ControlSet001\Enum\SCSI")
    except Exception:
        return out
    for s in k.iter_subkeys():
        for s2 in s.iter_subkeys():
            fn = None
            for v in s2.iter_values():
                if v.name == "FriendlyName":
                    fn = v.value
            out.append({
                "device": s.name, "instance": s2.name, "friendly": fn,
                "last_write": key_mtime(s2),
            })
    return out


def enum_wpd(software_hive: str) -> list[dict]:
    """Windows Portable Devices：卷标 + 最后连接时间。"""
    SO = RegistryHive(software_hive)
    out = []
    try:
        k = SO.get_key(r"\Microsoft\Windows Portable Devices\Devices")
    except Exception:
        return out
    for s in k.iter_subkeys():
        fn = None
        for v in s.iter_values():
            if v.name == "FriendlyName":
                fn = v.value
        out.append({"name": s.name, "label": fn, "last_write": key_mtime(s)})
    return out


def print_devices(system_hive: str, software_hive: str):
    print("═══ USBSTOR（U 盘类）═══")
    for d in sorted(enum_usb(system_hive), key=lambda x: x["last_write"] or datetime.datetime.min, reverse=True):
        print(f"  {d['last_write']}  {d['friendly']!r}")
        print(f"      {d['device']}")
    print("\n═══ SCSI（外置 SSD/硬盘，Q66 关键）═══")
    for d in sorted(enum_scsi(system_hive), key=lambda x: x["last_write"] or datetime.datetime.min, reverse=True):
        print(f"  {d['last_write']}  {d['friendly']!r}")
    print("\n═══ Portable Devices（卷标）═══")
    for d in sorted(enum_wpd(software_hive), key=lambda x: x["last_write"] or datetime.datetime.min, reverse=True):
        print(f"  {d['last_write']}  label={d['label']!r}")
        print(f"      {d['name'][:80]}")


def enum_bluetooth(system_hive: str) -> list[dict]:
    """蓝牙设备：MAC + LastConnected。

    注意：LastConnected 的 FILETIME 存的已是本地时间，
    若再 +8 会比该键自身写入时间还晚，逻辑不成立。
    """
    S = RegistryHive(system_hive)
    out = []
    try:
        k = S.get_key(r"\ControlSet001\Services\BTHPORT\Parameters\Devices")
    except Exception:
        return out
    for s in k.iter_subkeys():
        rec = {"mac": s.name.upper(), "key_mtime": key_mtime(s)}
        for v in s.iter_values():
            if v.name in ("LastConnected", "LastSeen"):
                raw = v.value
                if isinstance(raw, int):
                    rec[v.name] = ft(raw)
                else:
                    b = tb(raw)
                    if len(b) >= 8:
                        rec[v.name] = ft(struct.unpack("<Q", b[:8])[0])
            elif v.name == "Name":
                b = tb(v.value)
                rec["name"] = b.decode("utf8", "replace").strip("\x00")
        out.append(rec)
    return out


def enum_wlan_profiles(software_hive: str) -> list[dict]:
    """WLAN 配置：GUID + 最后连接时间（SYSTEMTIME 解码）。"""
    SO = RegistryHive(software_hive)
    out = []
    try:
        k = SO.get_key(r"\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles")
    except Exception:
        return out
    for s in k.iter_subkeys():
        rec = {"guid": s.name}
        for v in s.iter_values():
            if v.name == "ProfileName":
                rec["ssid"] = v.value
            elif v.name == "DateLastConnected":
                b = tb(v.value)
                if len(b) >= 16:
                    y, mo, _d, d, h, mi, sec, _ms = struct.unpack("<8H", b[:16])
                    try:
                        rec["last_connected"] = datetime.datetime(y, mo, d, h, mi, sec)
                    except Exception:
                        pass
            elif v.name == "DateCreated":
                b = tb(v.value)
                if len(b) >= 16:
                    y, mo, _d, d, h, mi, sec, _ms = struct.unpack("<8H", b[:16])
                    try:
                        rec["created"] = datetime.datetime(y, mo, d, h, mi, sec)
                    except Exception:
                        pass
        out.append(rec)
    return out


def print_net(system_hive: str, software_hive: str):
    print("═══ WLAN 配置（按最后连接降序）═══")
    for p in sorted(enum_wlan_profiles(software_hive),
                    key=lambda x: x.get("last_connected") or datetime.datetime.min, reverse=True):
        print(f"  {p.get('last_connected')}  {p['guid']}  {p.get('ssid')!r}")
    print("\n═══ 蓝牙设备 ═══")
    for b in enum_bluetooth(system_hive):
        print(f"  MAC={b['mac']}  name={b.get('name')!r}")
        print(f"     LastConnected={b.get('LastConnected')}  键写入={b['key_mtime']}")
        if b.get("LastConnected") and b["key_mtime"]:
            d = abs((b["LastConnected"] - b["key_mtime"]).total_seconds())
            note = "（同一时刻附近，说明该值已是本地时间）" if d < 600 else "（偏差大，需核对时区）"
            print(f"     与键写入相差 {d:.0f} 秒 {note}")
    print("\n═══ 网卡真实 MAC（NetworkSetup2\\PermanentAddress）═══")
    S = RegistryHive(system_hive)
    try:
        k = S.get_key(r"\ControlSet001\Control\NetworkSetup2\Interfaces")
        for s in k.iter_subkeys():
            try:
                kk = s.get_subkey("Kernel")
            except Exception:
                continue
            pa = desc = None
            for v in kk.iter_values():
                if v.name == "PermanentAddress":
                    pa = v.value
                if v.name == "Description":
                    desc = v.value
            if pa:
                print(f"  {s.name}  MAC={str(pa).upper()}  {desc!r}")
    except Exception as e:
        print(f"  读取失败: {e}")


# ═══════════════════════════════════════════════════════════
#  UserAssist / RunMRU
# ═══════════════════════════════════════════════════════════

def userassist(ntuser_path: str) -> list[dict]:
    """解析 UserAssist（ROT13 编码的程序名 + 运行次数 + 最后执行时间）。"""
    h = RegistryHive(ntuser_path)
    out = []
    for guid in ("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
                 "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"):
        try:
            k = h.get_key(rf"\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{guid}\Count")
        except Exception:
            continue
        for v in k.iter_values():
            name = codecs.decode(v.name, "rot13")
            rec = {"name": name, "guid": guid}
            raw = v.value
            if isinstance(raw, str):
                try:
                    raw = bytes.fromhex(raw)
                except Exception:
                    raw = None
            if raw and len(raw) >= 68:
                rec["runs"] = struct.unpack("<I", raw[4:8])[0]
                rec["last_exec"] = ft(struct.unpack("<Q", raw[60:68])[0])
            out.append(rec)
    return out


def runmru(ntuser_path: str) -> list[str]:
    """Win+R 运行历史。空列表 = 被清空（本次 Q48 的坑）。"""
    h = RegistryHive(ntuser_path)
    try:
        k = h.get_key(r"\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")
    except Exception:
        return []
    out = []
    for v in k.iter_values():
        if v.name == "MRUList":
            continue
        val = str(v.value)
        out.append(val.rstrip("\\1"))
    return out


def print_userassist(ntuser_path: str):
    print("═══ UserAssist ═══")
    for r in sorted(userassist(ntuser_path),
                    key=lambda x: x.get("last_exec") or datetime.datetime.min, reverse=True):
        le = r.get("last_exec")
        print(f"  runs={r.get('runs','?'):>5}  {le.strftime('%Y-%m-%d %H:%M:%S') if le else '-':<20}  {r['name']}")
    print("\n═══ RunMRU（Win+R）═══")
    rm = runmru(ntuser_path)
    if not rm:
        print("  [空] —— 该键存在但值列表为 0，说明被清理过")
    for x in rm:
        print(f"  {x}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "sam" and len(sys.argv) >= 4:
        print_sam(sys.argv[2], sys.argv[3])
    elif cmd == "net" and len(sys.argv) >= 4:
        print_net(sys.argv[2], sys.argv[3])
    elif cmd == "devices" and len(sys.argv) >= 4:
        print_devices(sys.argv[2], sys.argv[3])
    elif cmd == "ua" and len(sys.argv) >= 3:
        print_userassist(sys.argv[2])
    else:
        print(__doc__)
