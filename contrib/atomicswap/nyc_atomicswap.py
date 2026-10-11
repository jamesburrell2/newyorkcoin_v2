#!/usr/bin/env python3
# Copyright (c) 2026 The NewYorkCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
nyc_atomicswap.py - trustless cross-chain atomic swaps for NewYorkCoin.

Implements hash time-locked contracts (HTLCs) that work between NYC and any
Bitcoin-family chain with P2SH and BIP68/112 (OP_CHECKSEQUENCEVERIFY):
Bitcoin, Litecoin, Dogecoin forks with CSV, and NYC itself.

WHY CSV AND NOT CLTV
    On NYC mainnet BIP65 (OP_CHECKLOCKTIMEVERIFY) is NOT enforced by
    consensus (BIP65Height = INT_MAX), so OP_CLTV behaves as OP_NOP2 there.
    A CLTV-based refund branch would be spendable by anyone at any time.
    CSV (BIP112) IS enforced from block 13,000,000, so every contract here
    uses relative (block-count) timelocks via OP_CHECKSEQUENCEVERIFY.

CONTRACT SCRIPT (P2SH redeem script)
    OP_IF
        OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <secret_hash> OP_EQUALVERIFY
        <recipient_pubkey>
    OP_ELSE
        <relative_locktime_blocks> OP_CHECKSEQUENCEVERIFY OP_DROP
        <refund_pubkey>
    OP_ENDIF
    OP_CHECKSIG

    The OP_SIZE check forces a 32-byte secret on both chains, which closes
    the known "secret length mismatch" attack between differently-limited
    script interpreters.

PROTOCOL (Alice has NYC and wants BTC; Bob has BTC and wants NYC)
    1. Both:   keygen                      -> exchange swap pubkeys
    2. Alice:  initiate   (NYC chain)      -> sends contract + tx to Bob
    3. Bob:    audit      (NYC chain)      -> checks Alice's contract
    4. Bob:    participate (BTC chain)     -> same secret hash, SHORTER lock
    5. Alice:  audit      (BTC chain)      -> checks Bob's contract
    6. Alice:  redeem     (BTC chain)      -> reveals the secret on-chain
    7. Bob:    extractsecret (BTC chain)   -> learns the secret
    8. Bob:    redeem     (NYC chain)      -> swap complete
    If anything stalls, each side runs `refund` after its timelock expires.

The tool has no third-party dependencies (Python 3.7+ standard library only).
Swap keys are generated locally and stored in the state file; your node's
wallet only funds contracts and receives the redeemed/refunded coins.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
import urllib.error
import urllib.request
from decimal import Decimal, ROUND_DOWN

VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# secp256k1 (pure Python; signing is deterministic per RFC 6979, low-S)
# ---------------------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % P == 0:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], P - 2, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P) % P
    x3 = (lam * lam - p1[0] - p2[0]) % P
    return (x3, (lam * (p1[0] - x3) - p1[1]) % P)


def _point_mul(k, point=G):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def pubkey_from_privkey(priv: bytes) -> bytes:
    """Compressed SEC1 public key."""
    d = int.from_bytes(priv, "big")
    if not 0 < d < N:
        raise ValueError("invalid private key")
    x, y = _point_mul(d)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def _decompress(pub: bytes):
    if len(pub) != 33 or pub[0] not in (2, 3):
        raise ValueError("expected a 33-byte compressed public key")
    x = int.from_bytes(pub[1:], "big")
    if x >= P:
        raise ValueError("invalid public key")
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if (y * y - pow(x, 3, P) - 7) % P != 0:
        raise ValueError("public key is not on the curve")
    if (y & 1) != (pub[0] & 1):
        y = P - y
    return (x, y)


def _rfc6979_nonce(priv: bytes, msg32: bytes) -> int:
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + priv + msg32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + priv + msg32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 0 < cand < N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def _der_int(i: int) -> bytes:
    b = i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def ecdsa_sign(priv: bytes, msg32: bytes) -> bytes:
    """DER-encoded, low-S ECDSA signature (BIP62/BIP146 compliant)."""
    d = int.from_bytes(priv, "big")
    z = int.from_bytes(msg32, "big")
    k = _rfc6979_nonce(priv, msg32)
    r = _point_mul(k)[0] % N
    s = pow(k, N - 2, N) * (z + r * d) % N
    if r == 0 or s == 0:
        raise ValueError("signing failed")
    if s > N // 2:
        s = N - s
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def ecdsa_verify(pub: bytes, msg32: bytes, der: bytes) -> bool:
    try:
        assert der[0] == 0x30 and der[2] == 0x02
        rlen = der[3]
        r = int.from_bytes(der[4:4 + rlen], "big")
        assert der[4 + rlen] == 0x02
        slen = der[5 + rlen]
        s = int.from_bytes(der[6 + rlen:6 + rlen + slen], "big")
        point = _decompress(pub)
    except (AssertionError, IndexError, ValueError):
        return False
    if not (0 < r < N and 0 < s < N):
        return False
    z = int.from_bytes(msg32, "big")
    w = pow(s, N - 2, N)
    res = _point_add(_point_mul(z * w % N), _point_mul(r * w % N, point))
    return res is not None and res[0] % N == r


# ---------------------------------------------------------------------------
# Script and transaction primitives
# ---------------------------------------------------------------------------
OP_0, OP_1 = 0x00, 0x51
OP_PUSHDATA1, OP_PUSHDATA2 = 0x4C, 0x4D
OP_IF, OP_ELSE, OP_ENDIF = 0x63, 0x67, 0x68
OP_DROP, OP_SIZE, OP_EQUALVERIFY = 0x75, 0x82, 0x88
OP_SHA256, OP_CHECKSIG, OP_CHECKSEQUENCEVERIFY = 0xA8, 0xAC, 0xB2

SIGHASH_ALL = 0x01
SEQUENCE_FINAL = 0xFFFFFFFF
SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31
SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22
SEQUENCE_LOCKTIME_MASK = 0x0000FFFF
SECRET_SIZE = 32


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def hash256(b: bytes) -> bytes:
    return sha256(sha256(b))


def push_data(data: bytes) -> bytes:
    n = len(data)
    if n < OP_PUSHDATA1:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([OP_PUSHDATA1, n]) + data
    if n <= 0xFFFF:
        return bytes([OP_PUSHDATA2]) + n.to_bytes(2, "little") + data
    raise ValueError("push too large")


def script_num(n: int) -> bytes:
    """Minimally-encoded CScriptNum for a non-negative integer."""
    if n == 0:
        return b""
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    if out[-1] & 0x80:
        out.append(0)
    return bytes(out)


def push_int(n: int) -> bytes:
    if n == 0:
        return bytes([OP_0])
    if 1 <= n <= 16:
        return bytes([OP_1 + n - 1])
    return push_data(script_num(n))


def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("unexpected end of data")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def varint(self) -> int:
        first = self.read(1)[0]
        if first < 0xFD:
            return first
        return int.from_bytes(self.read({0xFD: 2, 0xFE: 4, 0xFF: 8}[first]), "little")


def parse_tx(raw: bytes) -> dict:
    """Parse a (possibly segwit-serialized) transaction."""
    r = _Reader(raw)
    version = int.from_bytes(r.read(4), "little")
    n_in = r.varint()
    segwit = False
    if n_in == 0:
        if r.read(1) != b"\x01":
            raise ValueError("bad segwit flag")
        segwit = True
        n_in = r.varint()
    vin = []
    for _ in range(n_in):
        txid = r.read(32)[::-1].hex()
        vout = int.from_bytes(r.read(4), "little")
        script_sig = r.read(r.varint())
        seq = int.from_bytes(r.read(4), "little")
        vin.append({"txid": txid, "vout": vout, "scriptSig": script_sig, "sequence": seq})
    vout = []
    for _ in range(r.varint()):
        value = int.from_bytes(r.read(8), "little")
        vout.append({"value": value, "scriptPubKey": r.read(r.varint())})
    if segwit:
        for _ in range(n_in):
            for _ in range(r.varint()):
                r.read(r.varint())
    locktime = int.from_bytes(r.read(4), "little")
    if r.pos != len(raw):
        raise ValueError("trailing data after transaction")
    return {"version": version, "vin": vin, "vout": vout, "locktime": locktime}


def serialize_tx(tx: dict) -> bytes:
    out = tx["version"].to_bytes(4, "little") + varint(len(tx["vin"]))
    for i in tx["vin"]:
        out += bytes.fromhex(i["txid"])[::-1] + i["vout"].to_bytes(4, "little")
        out += varint(len(i["scriptSig"])) + i["scriptSig"] + i["sequence"].to_bytes(4, "little")
    out += varint(len(tx["vout"]))
    for o in tx["vout"]:
        out += o["value"].to_bytes(8, "little") + varint(len(o["scriptPubKey"])) + o["scriptPubKey"]
    return out + tx["locktime"].to_bytes(4, "little")


def legacy_sighash(tx: dict, in_idx: int, script_code: bytes) -> bytes:
    """Pre-segwit SIGHASH_ALL digest (used by P2SH spends on every chain)."""
    copy = {
        "version": tx["version"], "locktime": tx["locktime"], "vout": tx["vout"],
        "vin": [dict(i, scriptSig=(script_code if n == in_idx else b""))
                for n, i in enumerate(tx["vin"])],
    }
    return hash256(serialize_tx(copy) + SIGHASH_ALL.to_bytes(4, "little"))


def p2sh_script_pubkey(redeem_script: bytes) -> bytes:
    inner = sha256(redeem_script)
    h160 = hashlib.new("ripemd160", inner).digest() if _has_ripemd() else _ripemd160(inner)
    return b"\xa9\x14" + h160 + b"\x87"


def _has_ripemd() -> bool:
    try:
        hashlib.new("ripemd160")
        return True
    except ValueError:
        return False


def _ripemd160(msg: bytes) -> bytes:
    """Pure-Python RIPEMD-160 (OpenSSL 3 may not expose it via hashlib)."""
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    fs = [lambda x, y, z: x ^ y ^ z,
          lambda x, y, z: (x & y) | (~x & z),
          lambda x, y, z: (x | ~y) ^ z,
          lambda x, y, z: (x & z) | (y & ~z),
          lambda x, y, z: x ^ (y | ~z)]
    rl = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
          7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
          3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
          1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
          4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    rr = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
          6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
          8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    sl = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
          7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
          11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
          11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
          9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    sr = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
          9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
          15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
    kl = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    kr = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    ml = len(msg) * 8
    msg += b"\x80" + b"\x00" * ((55 - len(msg)) % 64) + ml.to_bytes(8, "little")
    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + 4 * i:off + 4 * i + 4], "little") for i in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            rnd = j // 16
            t = (rol((al + (fs[rnd](bl, cl, dl) & 0xFFFFFFFF) + x[rl[j]] + kl[rnd]) & 0xFFFFFFFF, sl[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t
            t = (rol((ar + (fs[4 - rnd](br, cr, dr) & 0xFFFFFFFF) + x[rr[j]] + kr[rnd]) & 0xFFFFFFFF, sr[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t
        t = (h[1] + cl + dr) & 0xFFFFFFFF
        h[1] = (h[2] + dl + er) & 0xFFFFFFFF
        h[2] = (h[3] + el + ar) & 0xFFFFFFFF
        h[3] = (h[4] + al + br) & 0xFFFFFFFF
        h[4] = (h[0] + bl + cr) & 0xFFFFFFFF
        h[0] = t
    return b"".join(v.to_bytes(4, "little") for v in h)


# ---------------------------------------------------------------------------
# HTLC contract
# ---------------------------------------------------------------------------
def build_contract(secret_hash: bytes, recipient_pub: bytes, refund_pub: bytes, lock_blocks: int) -> bytes:
    if len(secret_hash) != 32:
        raise ValueError("secret hash must be 32 bytes")
    for pk in (recipient_pub, refund_pub):
        _decompress(pk)
    if not 1 <= lock_blocks <= SEQUENCE_LOCKTIME_MASK:
        raise ValueError("relative locktime must be between 1 and 65535 blocks")
    return (bytes([OP_IF, OP_SIZE]) + push_int(SECRET_SIZE) + bytes([OP_EQUALVERIFY, OP_SHA256])
            + push_data(secret_hash) + bytes([OP_EQUALVERIFY]) + push_data(recipient_pub)
            + bytes([OP_ELSE]) + push_int(lock_blocks) + bytes([OP_CHECKSEQUENCEVERIFY, OP_DROP])
            + push_data(refund_pub) + bytes([OP_ENDIF, OP_CHECKSIG]))


def parse_contract(script: bytes) -> dict:
    """Strictly match the HTLC template. Raises ValueError on anything else."""
    r = _Reader(script)

    def expect(*ops):
        got = r.read(len(ops))
        if got != bytes(ops):
            raise ValueError("script does not match the atomic swap template")

    def read_push(size):
        if r.read(1)[0] != size:
            raise ValueError("script does not match the atomic swap template")
        return r.read(size)

    expect(OP_IF, OP_SIZE, 0x01, SECRET_SIZE, OP_EQUALVERIFY, OP_SHA256)
    secret_hash = read_push(32)
    expect(OP_EQUALVERIFY)
    recipient = read_push(33)
    expect(OP_ELSE)
    op = r.read(1)[0]
    if OP_1 <= op <= OP_1 + 15:
        lock = op - OP_1 + 1
    elif 1 <= op <= 3:
        raw = r.read(op)
        if raw[-1] & 0x80 or script_num(int.from_bytes(raw, "little")) != raw:
            raise ValueError("locktime is not minimally encoded")
        lock = int.from_bytes(raw, "little")
    else:
        raise ValueError("script does not match the atomic swap template")
    expect(OP_CHECKSEQUENCEVERIFY, OP_DROP)
    refund = read_push(33)
    expect(OP_ENDIF, OP_CHECKSIG)
    if r.pos != len(script):
        raise ValueError("trailing data in contract script")
    if build_contract(secret_hash, recipient, refund, lock) != script:
        raise ValueError("contract is not canonically encoded")
    return {"secret_hash": secret_hash, "recipient_pubkey": recipient,
            "refund_pubkey": refund, "lock_blocks": lock}


def redeem_script_sig(sig: bytes, secret: bytes, contract: bytes) -> bytes:
    return push_data(sig) + push_data(secret) + bytes([OP_1]) + push_data(contract)


def refund_script_sig(sig: bytes, contract: bytes) -> bytes:
    return push_data(sig) + bytes([OP_0]) + push_data(contract)


def script_pushes(script: bytes) -> list:
    """Decode a push-only scriptSig into its data elements."""
    r, out = _Reader(script), []
    while r.pos < len(script):
        op = r.read(1)[0]
        if op == OP_0:
            out.append(b"")
        elif op < OP_PUSHDATA1:
            out.append(r.read(op))
        elif op == OP_PUSHDATA1:
            out.append(r.read(r.read(1)[0]))
        elif op == OP_PUSHDATA2:
            out.append(r.read(int.from_bytes(r.read(2), "little")))
        elif OP_1 <= op <= OP_1 + 15:
            out.append(bytes([op - OP_1 + 1]))
        else:
            raise ValueError("scriptSig is not push-only")
    return out


# ---------------------------------------------------------------------------
# Node RPC
# ---------------------------------------------------------------------------
class RPCError(Exception):
    pass


class RPC:
    def __init__(self, url, user=None, password=None, cookie=None, wallet=None):
        self.url = url.rstrip("/") + (f"/wallet/{wallet}" if wallet else "")
        if cookie:
            with open(os.path.expanduser(cookie)) as f:
                creds = f.read().strip()
        elif user is not None:
            creds = f"{user}:{password or ''}"
        else:
            raise RPCError("provide --rpcuser/--rpcpassword or --rpccookie")
        self.auth = "Basic " + base64.b64encode(creds.encode()).decode()
        self._id = 0

    def __call__(self, method, *params):
        self._id += 1
        body = json.dumps({"jsonrpc": "1.0", "id": self._id, "method": method,
                           "params": list(params)}, default=str).encode()
        req = urllib.request.Request(self.url, data=body, headers={
            "Authorization": self.auth, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                reply = json.loads(resp.read(), parse_float=Decimal)
        except urllib.error.HTTPError as e:
            try:
                reply = json.loads(e.read(), parse_float=Decimal)
            except Exception:
                raise RPCError(f"{method}: HTTP {e.code} {e.reason}") from None
        except urllib.error.URLError as e:
            raise RPCError(f"cannot reach node at {self.url}: {e.reason}") from None
        if reply.get("error"):
            raise RPCError(f"{method}: {reply['error'].get('message', reply['error'])}")
        return reply["result"]


COIN = 100_000_000


def to_sats(amount) -> int:
    return int((Decimal(str(amount)) * COIN).to_integral_value(ROUND_DOWN))


def fmt_coins(sats: int) -> str:
    return f"{Decimal(sats) / COIN:.8f}"


def require_csv(rpc, force=False):
    """Refuse to lock funds on a chain where CSV is not enforced yet."""
    info = rpc("getblockchaininfo")
    active = None
    forks = info.get("softforks")
    if isinstance(forks, dict) and "csv" in forks:
        active = forks["csv"].get("active")
    elif isinstance(forks, list):  # very old nodes
        for fk in forks:
            if fk.get("id") == "csv":
                active = fk.get("enforce", {}).get("status") or fk.get("active")
    if active is None:
        try:
            dep = rpc("getdeploymentinfo")["deployments"].get("csv", {})
            active = dep.get("active")
        except RPCError:
            pass
    if active is True:
        return info
    if active is False:
        raise SystemExit(
            f"error: CSV (BIP68/112) is not active on this chain yet (height {info['blocks']}).\n"
            "       On NYC mainnet it activates at block 13,000,000. A CSV refund path\n"
            "       is NOT safe before activation; refusing to continue.")
    if not force:
        raise SystemExit("error: could not determine whether CSV is active on this chain; "
                         "re-run with --force if you are certain it is.")
    print("warning: CSV status unknown; continuing because --force was given", file=sys.stderr)
    return info


def avg_block_time(rpc, window=720) -> float:
    tip = rpc("getblockcount")
    start = max(1, tip - window)
    t1 = rpc("getblockheader", rpc("getblockhash", tip))["time"]
    t0 = rpc("getblockheader", rpc("getblockhash", start))["time"]
    if tip <= start or t1 <= t0:
        return 0.0
    return (t1 - t0) / (tip - start)


def resolve_lock_blocks(rpc, args) -> int:
    if args.locktime_blocks:
        blocks = args.locktime_blocks
    else:
        spacing = args.block_time or avg_block_time(rpc)
        if spacing <= 0:
            raise SystemExit("error: cannot estimate block time on this chain; "
                             "pass --locktime-blocks or --block-time")
        blocks = int(args.locktime_hours * 3600 / spacing)
    if not 1 <= blocks <= SEQUENCE_LOCKTIME_MASK:
        raise SystemExit(f"error: locktime of {blocks} blocks is outside 1..65535 "
                         "(BIP68 relative locktime limit). Adjust --locktime-*.")
    return blocks


def fee_rate_sat_vb(rpc, args) -> Decimal:
    relay = Decimal(0)
    try:
        relay = Decimal(str(rpc("getnetworkinfo")["relayfee"])) * COIN / 1000
    except (RPCError, KeyError):
        pass
    if args.feerate is not None:
        rate = Decimal(str(args.feerate))
    else:
        rate = Decimal(1)
        try:
            est = rpc("estimatesmartfee", 6)
            if "feerate" in est:
                rate = Decimal(str(est["feerate"])) * COIN / 1000
        except RPCError:
            pass
    return max(rate, relay, Decimal("0"))


def wallet_payout_script(rpc, address=None):
    """A fresh legacy (P2PKH) wallet address, or a user-supplied one."""
    if address is None:
        try:
            address = rpc("getnewaddress", "atomicswap", "legacy")
        except RPCError:
            address = rpc("getnewaddress", "atomicswap")
    info = rpc("validateaddress", address)
    if not info.get("isvalid"):
        raise SystemExit(f"error: {address} is not a valid address on this chain")
    spk = bytes.fromhex(info["scriptPubKey"])
    if spk[:1] in (b"\x00", b"\x51") and len(spk) in (22, 34):
        segwit_ok = rpc("getblockchaininfo").get("softforks", {}).get("segwit", {}).get("active", True)
        if not segwit_ok:
            raise SystemExit(f"error: {address} is a SegWit address but SegWit is not active "
                             "on this chain; use a legacy address")
    return address, spk


def p2sh_address(rpc, contract: bytes) -> str:
    decoded = rpc("decodescript", contract.hex())
    addr = decoded.get("p2sh")
    if not addr:
        raise SystemExit("error: node did not return a P2SH address for the contract")
    return addr


def find_contract_output(tx: dict, contract: bytes) -> int:
    spk = p2sh_script_pubkey(contract)
    matches = [n for n, o in enumerate(tx["vout"]) if o["scriptPubKey"] == spk]
    if not matches:
        raise SystemExit("error: transaction does not pay to this contract")
    if len(matches) > 1:
        raise SystemExit("error: transaction pays to this contract more than once")
    return matches[0]


def broadcast(rpc, raw: bytes, dry_run=False) -> str:
    hexstr = raw.hex()
    try:
        res = rpc("testmempoolaccept", [hexstr])[0]
        if not res.get("allowed"):
            reason = res.get("reject-reason", "unknown")
            if "non-BIP68-final" in reason:
                raise SystemExit("error: the relative timelock has not expired yet "
                                 f"(node says: {reason})")
            raise SystemExit(f"error: node rejected the transaction: {reason}")
    except RPCError as e:
        if "testmempoolaccept" not in str(e) or "Method not found" not in str(e):
            raise
    if dry_run:
        return hash256(raw)[::-1].hex()
    return rpc("sendrawtransaction", hexstr)


# ---------------------------------------------------------------------------
# State file
# ---------------------------------------------------------------------------
def load_state(path):
    if not os.path.exists(path):
        raise SystemExit(f"error: state file {path} not found; run `keygen` first")
    with open(path) as f:
        return json.load(f)


def save_state(path, state):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, path)


def my_keys(state):
    priv = bytes.fromhex(state["privkey"])
    return priv, pubkey_from_privkey(priv)


def parse_pubkey(hexstr):
    try:
        pk = bytes.fromhex(hexstr)
        _decompress(pk)
        return pk
    except ValueError as e:
        raise SystemExit(f"error: invalid counterparty pubkey: {e}")


def out(obj):
    print(json.dumps(obj, indent=2))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_keygen(args):
    if os.path.exists(args.state) and not args.overwrite:
        raise SystemExit(f"error: {args.state} already exists (use --overwrite to replace it; "
                         "this destroys the keys of any swap in progress)")
    while True:
        priv = secrets.token_bytes(32)
        if 0 < int.from_bytes(priv, "big") < N:
            break
    save_state(args.state, {"version": VERSION, "privkey": priv.hex(), "legs": {}})
    out({"pubkey": pubkey_from_privkey(priv).hex(), "state": args.state,
         "note": "Send this pubkey to your counterparty. Back up the state file: "
                 "it holds the key needed to redeem or refund."})


def _fund_contract(args, rpc, state, contract, role, secret_hash, extra):
    amount = to_sats(args.amount)
    if amount <= 0:
        raise SystemExit("error: amount must be positive")
    addr = p2sh_address(rpc, contract)
    if args.dry_run:
        out({"dry_run": True, "contract_address": addr, "contract": contract.hex(),
             "amount": fmt_coins(amount), **extra})
        return
    txid = rpc("sendtoaddress", addr, fmt_coins(amount))
    raw = bytes.fromhex(rpc("gettransaction", txid)["hex"])
    vout = find_contract_output(parse_tx(raw), contract)
    state["legs"][args.leg] = {"role": role, "contract": contract.hex(), "txid": txid,
                               "vout": vout, "contract_tx": raw.hex(),
                               "secret_hash": secret_hash.hex(), **extra}
    save_state(args.state, state)
    out({"contract_address": addr, "contract": contract.hex(), "contract_txid": txid,
         "contract_vout": vout, "contract_tx": raw.hex(), "secret_hash": secret_hash.hex(),
         "amount": fmt_coins(amount), **extra,
         "next": "Send contract, contract_tx and secret_hash to your counterparty."})


def cmd_initiate(args):
    rpc = make_rpc(args)
    require_csv(rpc, args.force)
    state = load_state(args.state)
    if any(leg.get("role") == "initiator" for leg in state["legs"].values()) and not args.force:
        raise SystemExit("error: this state file already has an initiated swap")
    _, mypub = my_keys(state)
    their = parse_pubkey(args.their_pubkey)
    lock = resolve_lock_blocks(rpc, args)
    secret = state.get("secret")
    secret = bytes.fromhex(secret) if secret else secrets.token_bytes(SECRET_SIZE)
    secret_hash = sha256(secret)
    if not args.dry_run:
        state["secret"] = secret.hex()  # saved BEFORE funding so it can never be lost
        save_state(args.state, state)
    contract = build_contract(secret_hash, their, mypub, lock)
    _fund_contract(args, rpc, state, contract, "initiator", secret_hash, {"lock_blocks": lock})


def cmd_participate(args):
    rpc = make_rpc(args)
    require_csv(rpc, args.force)
    state = load_state(args.state)
    _, mypub = my_keys(state)
    their = parse_pubkey(args.their_pubkey)
    try:
        secret_hash = bytes.fromhex(args.secret_hash)
        assert len(secret_hash) == 32
    except (ValueError, AssertionError):
        raise SystemExit("error: --secret-hash must be 32 bytes of hex")
    lock = resolve_lock_blocks(rpc, args)
    contract = build_contract(secret_hash, their, mypub, lock)
    _fund_contract(args, rpc, state, contract, "participant", secret_hash, {"lock_blocks": lock})


def _load_contract_args(args, state=None):
    """Contract + funding tx from args, or from a leg in the state file."""
    leg = (state or {}).get("legs", {}).get(args.leg) if state else None
    contract_hex = args.contract or (leg or {}).get("contract")
    tx_hex = args.contract_tx or (leg or {}).get("contract_tx")
    if not contract_hex or not tx_hex:
        raise SystemExit("error: pass --contract and --contract-tx (or a --leg saved in the state file)")
    try:
        contract = bytes.fromhex(contract_hex)
        raw = bytes.fromhex(tx_hex)
        terms = parse_contract(contract)
        tx = parse_tx(raw)
    except ValueError as e:
        raise SystemExit(f"error: {e}")
    vout = find_contract_output(tx, contract)
    txid = hash256(_strip_witness(raw))[::-1].hex()
    return contract, terms, tx, txid, vout


def _strip_witness(raw: bytes) -> bytes:
    return serialize_tx(parse_tx(raw))


def _confirmations(rpc, txid, vout):
    """(confirmations, unspent) using only the UTXO set (no txindex needed)."""
    utxo = rpc("gettxout", txid, vout, True)
    if utxo is None:
        return None, False
    return utxo.get("confirmations", 0), True


def cmd_audit(args):
    rpc = make_rpc(args)
    state = load_state(args.state) if os.path.exists(args.state) else None
    contract, terms, tx, txid, vout = _load_contract_args(args, state)
    confs, unspent = _confirmations(rpc, txid, vout)
    spacing = args.block_time or avg_block_time(rpc) or 0
    remaining = terms["lock_blocks"] - (confs or 0)
    report = {
        "contract_address": p2sh_address(rpc, contract),
        "contract_txid": txid, "contract_vout": vout,
        "amount": fmt_coins(tx["vout"][vout]["value"]),
        "secret_hash": terms["secret_hash"].hex(),
        "recipient_pubkey": terms["recipient_pubkey"].hex(),
        "refund_pubkey": terms["refund_pubkey"].hex(),
        "relative_locktime_blocks": terms["lock_blocks"],
        "confirmations": confs, "unspent": unspent,
        "refund_possible_in_blocks": max(remaining, 0) if unspent else None,
    }
    if spacing:
        report["refund_possible_in_hours"] = round(max(remaining, 0) * spacing / 3600, 2)
    warnings = []
    if state:
        _, mypub = my_keys(state)
        report["pays_to_me"] = terms["recipient_pubkey"] == mypub
        if not report["pays_to_me"]:
            warnings.append("recipient pubkey is NOT your swap key; do not proceed")
    if not unspent:
        warnings.append("contract output is spent or not yet in this node's UTXO set "
                        "(unconfirmed outputs are only visible once in the mempool)")
    elif confs == 0:
        warnings.append("contract transaction is unconfirmed; wait for confirmations")
    if args.expect_amount is not None and tx["vout"][vout]["value"] != to_sats(args.expect_amount):
        warnings.append(f"amount differs from the agreed {args.expect_amount}")
    if args.expect_secret_hash and terms["secret_hash"].hex() != args.expect_secret_hash.lower():
        warnings.append("secret hash differs from the expected one")
    report["warnings"] = warnings
    out(report)
    if warnings:
        sys.exit(2)


def _spend_contract(args, rpc, contract, terms, tx, txid, vout, mode, secret=None):
    priv, mypub = my_keys(load_state(args.state))
    expected = terms["recipient_pubkey"] if mode == "redeem" else terms["refund_pubkey"]
    if expected != mypub:
        raise SystemExit(f"error: this contract's {mode} key is not your swap key")
    value = tx["vout"][vout]["value"]
    address, spk = wallet_payout_script(rpc, args.address)
    seq = terms["lock_blocks"] if mode == "refund" else SEQUENCE_FINAL
    spend = {"version": 2, "locktime": 0,
             "vin": [{"txid": txid, "vout": vout, "scriptSig": b"", "sequence": seq}],
             "vout": [{"value": value, "scriptPubKey": spk}]}

    def finalize(fee):
        spend["vout"][0]["value"] = value - fee
        if spend["vout"][0]["value"] <= 0:
            raise SystemExit("error: fee exceeds contract value")
        digest = legacy_sighash(spend, 0, contract)
        sig = ecdsa_sign(priv, digest)
        assert ecdsa_verify(mypub, digest, sig), "self-check of signature failed"
        sig += bytes([SIGHASH_ALL])
        spend["vin"][0]["scriptSig"] = (redeem_script_sig(sig, secret, contract) if mode == "redeem"
                                         else refund_script_sig(sig, contract))
        return serialize_tx(spend)

    rate = fee_rate_sat_vb(rpc, args)
    size = len(finalize(0)) + 1  # +1 covers a possible longer DER signature
    fee = int((rate * size).to_integral_value())
    raw = finalize(fee)
    new_txid = broadcast(rpc, raw, args.dry_run)
    out({"mode": mode, "txid": new_txid, "paid_to": address, "amount": fmt_coins(value - fee),
         "fee": fmt_coins(fee), "size": len(raw), "dry_run": bool(args.dry_run),
         "raw_tx": raw.hex()})


def cmd_redeem(args):
    rpc = make_rpc(args)
    state = load_state(args.state)
    contract, terms, tx, txid, vout = _load_contract_args(args, state)
    secret_hex = args.secret or state.get("secret")
    if not secret_hex:
        raise SystemExit("error: no secret; pass --secret (from `extractsecret`)")
    secret = bytes.fromhex(secret_hex)
    if len(secret) != SECRET_SIZE or sha256(secret) != terms["secret_hash"]:
        raise SystemExit("error: secret does not match this contract's secret hash")
    _spend_contract(args, rpc, contract, terms, tx, txid, vout, "redeem", secret)


def cmd_refund(args):
    rpc = make_rpc(args)
    state = load_state(args.state)
    contract, terms, tx, txid, vout = _load_contract_args(args, state)
    confs, unspent = _confirmations(rpc, txid, vout)
    if not unspent:
        raise SystemExit("error: contract output is already spent (or unknown to this node)")
    # BIP68: a spend is valid in block H when H - coin_height >= lock. The next
    # block is tip + 1 and confirmations = tip - coin_height + 1, so the refund
    # becomes valid exactly when confirmations >= lock_blocks.
    if confs < terms["lock_blocks"]:
        left = terms["lock_blocks"] - confs
        raise SystemExit(f"error: timelock not expired: {confs}/{terms['lock_blocks']} "
                         f"confirmations, about {left} more blocks to wait")
    _spend_contract(args, rpc, contract, terms, tx, txid, vout, "refund")


def cmd_extractsecret(args):
    rpc = make_rpc(args)
    state = load_state(args.state) if os.path.exists(args.state) else None
    if args.redeem_tx:
        candidates = [bytes.fromhex(args.redeem_tx)]
        contract = bytes.fromhex(args.contract) if args.contract else None
        if contract is None:
            raise SystemExit("error: pass --contract with --redeem-tx")
        terms = parse_contract(contract)
        txid = vout = None
    else:
        contract, terms, _, txid, vout = _load_contract_args(args, state)
        candidates = _find_spends(rpc, txid, vout, args.from_height)
    for raw in candidates:
        tx = parse_tx(raw)
        for i in tx["vin"]:
            if txid is not None and (i["txid"], i["vout"]) != (txid, vout):
                continue
            try:
                pushes = script_pushes(i["scriptSig"])
            except ValueError:
                continue
            if len(pushes) == 4 and pushes[3] == contract and pushes[2] == b"\x01":
                secret = pushes[1]
                if sha256(secret) == terms["secret_hash"]:
                    if state is not None:
                        state["secret"] = secret.hex()
                        save_state(args.state, state)
                    out({"secret": secret.hex(), "secret_hash": terms["secret_hash"].hex(),
                         "next": "Run `redeem` on the other chain's contract with this secret."})
                    return
            if len(pushes) == 3 and pushes[2] == contract and pushes[1] == b"":
                raise SystemExit("error: the contract was REFUNDED, not redeemed; "
                                 "no secret was revealed. Refund your own contract.")
    raise SystemExit("error: no redemption found yet (counterparty has not redeemed); try again later")


def _find_spends(rpc, txid, vout, from_height=None):
    """Scan the mempool and blocks for a transaction spending txid:vout."""
    found = []
    for mtxid in rpc("getrawmempool"):
        try:
            raw = bytes.fromhex(rpc("getrawtransaction", mtxid))
        except RPCError:
            continue
        if any((i["txid"], i["vout"]) == (txid, vout) for i in parse_tx(raw)["vin"]):
            found.append(raw)
    if found:
        return found
    if from_height is None:
        try:
            from_height = rpc("getblockheader", rpc("gettransaction", txid)["blockhash"])["height"]
        except (RPCError, KeyError):
            raise SystemExit("error: cannot locate the contract's block; pass --from-height")
    tip = rpc("getblockcount")
    for h in range(from_height, tip + 1):
        block = rpc("getblock", rpc("getblockhash", h), 2)
        for t in block["tx"]:
            if any(i.get("txid") == txid and i.get("vout") == vout for i in t["vin"]):
                return [bytes.fromhex(t["hex"])]
    return []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def make_rpc(args):
    return RPC(args.rpcurl, args.rpcuser, args.rpcpassword, args.rpccookie, args.rpcwallet)


def main(argv=None):
    p = argparse.ArgumentParser(description="NYC cross-chain atomic swaps (CSV-based HTLCs)")
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, needs_rpc=True):
        sp.add_argument("--state", default="swap.json", help="swap state file (default: swap.json)")
        if needs_rpc:
            g = sp.add_argument_group("node connection")
            g.add_argument("--rpcurl", default="http://127.0.0.1:17021",
                           help="node RPC URL (NYC mainnet default: http://127.0.0.1:17021)")
            g.add_argument("--rpcuser")
            g.add_argument("--rpcpassword")
            g.add_argument("--rpccookie", help="path to the node's .cookie file")
            g.add_argument("--rpcwallet", help="wallet name for multi-wallet nodes")
            sp.add_argument("--block-time", type=float, help="seconds per block (default: measured)")
            sp.add_argument("--force", action="store_true", help="skip safety checks that cannot be verified")

    def contract_ref(sp):
        sp.add_argument("--leg", default="default", help="name of the swap leg in the state file")
        sp.add_argument("--contract", help="contract redeem script (hex)")
        sp.add_argument("--contract-tx", help="raw contract funding transaction (hex)")

    def spend_opts(sp):
        sp.add_argument("--address", help="pay to this address instead of a new wallet address")
        sp.add_argument("--feerate", type=Decimal, help="fee rate in sat/vB (default: node estimate)")
        sp.add_argument("--dry-run", action="store_true", help="build and check, but do not broadcast")

    def fund_opts(sp):
        sp.add_argument("--their-pubkey", required=True, help="counterparty's swap pubkey (hex)")
        sp.add_argument("--amount", required=True, help="amount to lock, in coins")
        lk = sp.add_mutually_exclusive_group(required=True)
        lk.add_argument("--locktime-blocks", type=int)
        lk.add_argument("--locktime-hours", type=float)
        sp.add_argument("--leg", default="default", help="name for this leg in the state file")
        sp.add_argument("--dry-run", action="store_true", help="show the contract, do not fund it")

    sp = sub.add_parser("keygen", help="create a swap key and state file")
    common(sp, needs_rpc=False)
    sp.add_argument("--overwrite", action="store_true")
    sp.set_defaults(func=cmd_keygen)

    sp = sub.add_parser("initiate", help="create the secret and fund the first contract (use ~48h)")
    common(sp); fund_opts(sp)
    sp.set_defaults(func=cmd_initiate)

    sp = sub.add_parser("participate", help="fund the second contract with the initiator's hash (use ~24h)")
    common(sp); fund_opts(sp)
    sp.add_argument("--secret-hash", required=True)
    sp.set_defaults(func=cmd_participate)

    sp = sub.add_parser("audit", help="verify a counterparty's contract before acting on it")
    common(sp); contract_ref(sp)
    sp.add_argument("--expect-amount")
    sp.add_argument("--expect-secret-hash")
    sp.set_defaults(func=cmd_audit)

    sp = sub.add_parser("redeem", help="claim a contract that pays to you, revealing the secret")
    common(sp); contract_ref(sp); spend_opts(sp)
    sp.add_argument("--secret", help="secret (hex); defaults to the one in the state file")
    sp.set_defaults(func=cmd_redeem)

    sp = sub.add_parser("refund", help="reclaim your own contract after its timelock")
    common(sp); contract_ref(sp); spend_opts(sp)
    sp.set_defaults(func=cmd_refund)

    sp = sub.add_parser("extractsecret", help="learn the secret from the counterparty's redemption")
    common(sp); contract_ref(sp)
    sp.add_argument("--redeem-tx", help="raw redemption tx (hex), instead of scanning the chain")
    sp.add_argument("--from-height", type=int, help="block height to start scanning from")
    sp.set_defaults(func=cmd_extractsecret)

    args = p.parse_args(argv)
    try:
        args.func(args)
    except RPCError as e:
        raise SystemExit(f"error: {e}")


if __name__ == "__main__":
    main()
