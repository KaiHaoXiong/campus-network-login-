"""
srun_encrypt.py — 深澜（Srun）校园网认证系统加密模块

复现 Portal.js v2.00.20210607 中的 srun_bx1 加密算法：
  1. XXTEA 分组密码加密 JSON 用户信息
  2. 自定义 Base64 编码（字母表替换）
  3. HMAC-MD5/SHA1 哈希

关键 JS 源码（从 Portal.js 提取）：
  return '{SRBX1}' + base64.encode(encode(info, token));

其中 encode() 是 XXTEA 加密，l() 把 uint32 数组转字符串，
base64.encode() 用自定义字母表编码。
"""

import base64
import hashlib
import hmac
import json
import math
import struct


# ============================================================
# 自定义 Base64（字母表替换标准 Base64）
# ============================================================
_STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_SRUN = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
_TRANS = str.maketrans(_STANDARD, _SRUN)


def _srun_base64_encode(data: bytes) -> str:
    """自定义 Base64 编码：标准算法 + 深澜字母表"""
    return base64.b64encode(data).decode("ascii").translate(_TRANS)


def _string_to_uint32s(s: str, append_length: bool) -> list[int]:
    """
    字符串 → uint32 小端数组（对应 JS s() 函数）

    JS 中 charCodeAt 超出字符串长度会返回 NaN，NaN | 0 = 0，
    相当于自动用 0 补齐。这里手动补 0。
    """
    # JS charCodeAt 使用 UTF-16 码元，不能用 UTF-8 字节冒充。
    raw = s.encode("utf-16-le", errors="surrogatepass")
    units = [item[0] for item in struct.iter_unpack("<H", raw)]
    v = []
    for i in range(0, len(units), 4):
        word = 0
        for offset, unit in enumerate(units[i:i + 4]):
            word |= unit << (8 * offset)
        v.append(word & 0xFFFFFFFF)
    if append_length:
        v.append(len(units))
    return v


def _uint32s_to_string(v: list[int]) -> str:
    """
    uint32 数组 → 字符串（对应 JS l(v, false)）

    JS 中 String.fromCharCode(b0, b1, b2, b3) 把 4 个字节变成一个 4 字符的字符串。
    这里用 struct.pack 转字节串，再以 latin-1 解码（逐字节映射到字符）。
    """
    parts = []
    for val in v:
        parts.append(struct.pack("<I", val & 0xFFFFFFFF))
    return b"".join(parts).decode("latin-1")


# ============================================================
# XXTEA 加密
# ============================================================
def xxtea_encode(plaintext: str, key: str, mode: str = "legacy") -> str:
    """
    XXTEA 加密 + 自定义 Base64（对应 JS encode() 函数）

    JS: return l(v, false);  然后外层套 base64.encode()
    """
    if mode not in ("legacy", "portal_js"):
        raise ValueError("未知加密模式")
    if not plaintext:
        return ""

    v = _string_to_uint32s(plaintext, True)    # v[0..n-1]=数据, v[n]=原始长度
    k = _string_to_uint32s(key, False)          # 密钥，无长度标记
    while len(k) < 4:
        k.append(0)

    n = len(v) - 1           # 数据 uint32 个数（不含长度标记）
    if n < 1:
        return _srun_base64_encode(plaintext.encode("utf-8"))

    DELTA = 0x9E3779B9
    MASK = 0xFFFFFFFF

    z = v[n]                 # 初始 z = 长度标记
    rounds = math.floor(6 + 52 / (n + 1))
    d_sum = 0

    for _ in range(rounds):
        d_sum = (d_sum + DELTA) & MASK
        e = (d_sum >> 2) & 3

        # 处理 v[0] 到 v[n-1]
        # legacy 保留原 Python 的运算分组；portal_js 对应仓库原 JS 的另一种分组。
        # legacy:
        #   m = z>>>5 ^ y<<2
        #   m += y>>>3 ^ z<<4 ^ (d^y)
        #   m += k[p&3^e] ^ z
        #   z = v[p] = v[p]+m & MASK
        for p in range(n):
            y = v[p + 1]
            m = (z >> 5) ^ ((y << 2) & MASK)                    # m = z>>>5 ^ y<<2
            if mode == "legacy":
                m += ((y >> 3) ^ ((z << 4) & MASK)) ^ (d_sum ^ y)
            else:
                m = ((m + ((y >> 3) ^ ((z << 4) & MASK))) & MASK) ^ (d_sum ^ y)
            m += k[(p & 3) ^ e] ^ z                              # m += k[p&3^e] ^ z
            v[p] = (v[p] + m) & MASK                             # z = v[p] = v[p]+m & MASK
            z = v[p]

        # 处理 v[n]（长度标记）—— JS for 循环退出后 p == n，直接用 n
        y = v[0]
        m = (z >> 5) ^ ((y << 2) & MASK)
        if mode == "legacy":
            m += ((y >> 3) ^ ((z << 4) & MASK)) ^ (d_sum ^ y)
        else:
            m = ((m + ((y >> 3) ^ ((z << 4) & MASK))) & MASK) ^ (d_sum ^ y)
        m += k[(n & 3) ^ e] ^ z
        v[n] = (v[n] + m) & MASK
        z = v[n]

    # l(v, false): 转字符串，不截断
    raw_str = _uint32s_to_string(v)
    return _srun_base64_encode(raw_str.encode("latin-1"))


# ============================================================
# 哈希函数
# ============================================================
def get_md5(s: str, key: str = "") -> str:
    """与学校实际使用的 blueimp md5 一致：有 key 时为 HMAC-MD5。"""
    if key:
        return hmac.new(key.encode("utf-8"), s.encode("utf-8"), hashlib.md5).hexdigest()
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def get_sha1(s: str) -> str:
    """SHA1 哈希"""
    return hashlib.sha1(s.encode()).hexdigest()


# ============================================================
# 登录加密接口
# ============================================================
def make_encrypted_info(username: str, password: str, ip: str,
                        ac_id: str, enc_ver: str, token: str,
                        mode: str = "legacy") -> str:
    """
    加密用户信息

    JS 源码：return '{SRBX1}' + base64.encode(encode(info, token));
    """
    info = json.dumps({
        "username": username,
        "password": password,
        "ip": ip,
        "acid": ac_id,
        "enc_ver": enc_ver,
    }, separators=(",", ":"), ensure_ascii=False)
    return "{SRBX1}" + xxtea_encode(info, token, mode=mode)


def make_checksum(token: str, username: str, hmd5: str, ac_id: str,
                  ip: str, n: str, type_: str, enc_info: str) -> str:
    """
    计算校验和

    JS: sha1(token+username + token+hmd5 + token+ac_id
           + token+ip + token+n + token+type + token+i)
    """
    parts = [
        token, username,
        token, hmd5,
        token, ac_id,
        token, ip,
        token, n,
        token, type_,
        token, enc_info,
    ]
    return get_sha1("".join(parts))
