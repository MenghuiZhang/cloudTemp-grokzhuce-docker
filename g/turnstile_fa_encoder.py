# -*- coding: utf-8 -*-
"""
Turnstile FA encoder — XXTEA path recovered from har1 rch_big_script.js.

Confirmed pipeline (FA):
  1. Frame: [32] + FJ(plain) + [32]   # FJ ≈ compact JSON bytes
  2. Fh: [253, 1, flag] + body         # flag=1 if F6-compressed (not ported)
  3. Pad to 8 bytes with zeros; pad_byte = (8 - len % 8) % 8
  4. FC = random 128B, FC[0]=2; FV = RSA_encrypt(FC, e=65537, n=F8)
  5. k16 = gDRqi3(FC[9*pad+40 : 9*pad+56])   # gDRqi3 runtime from runProgram
  6. Fx key schedule (DELTA=0x9E3779B9) → 64 uint32
  7. Fe expand per block-index; Fi/FL encrypt 8-byte blocks (big-endian words)
  8. raw = FV(128) || pad_byte || ciphertext
  9. custom base64 with F7 alphabet

Recovered (har1 offline Node VM, 2026-07-17):
  - gDRqi3(k) = k[i] XOR s.charCodeAt(i % s.length)  (Uint8Array in/out)
  - har1 session s = \"xpGnbLPmChEjwmse\"  (injected by runProgram bc1; session-dynamic)
  - FO1 plain 47 keys: g/turnstile_fo1_plain.py
  - FO2 plain schema: hybrid dump ready (schema may rotate); F6 exact in g/turnstile_f6.py
  - F6: Node original F6.js bit-identical; zlib only fallback (TURNSTILE_F6_ZLIB=1)
  - FA decrypt (needs FC): g/turnstile_fa_decoder.py
  - FO1 + FO2 share one session FC (same RSA header). FaEncoder.session_fc reuses across encode().

HAR evidence: logs/har1/work/gDRqi3_source.js, fa_pipeline_clean.js, fo_codec_facts.json
"""
from __future__ import annotations

import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from g.turnstile_fo_codec import FoCodec, FoSessionKeys, HAR1_F7, HAR1_F8_HEX

DELTA = 0x9E3779B9

# har1 runProgram-injected XOR key (session-specific; live sessions re-extract)
HAR1_GDRQI3_S = "xpGnbLPmChEjwmse"


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _be_u32(b: bytes | bytearray, off: int) -> int:
    return struct.unpack_from(">I", b, off)[0]


def _pack_be_u32(y: int, z: int) -> bytes:
    return struct.pack(">II", _u32(y), _u32(z))


def fx_schedule(k0: int, k1: int, k2: int, k3: int) -> list[int]:
    keys = [k0, k1, k2, k3]
    out: list[int] = []
    s = 0
    for _ in range(32):
        rb = s & 3
        out.append(_u32(s + keys[rb]))
        s = _u32(s + DELTA)
        rb = 3 & (s >> 11)
        out.append(_u32(s + keys[rb]))
    return out


def fe_expand(base_sched: list[int], block_index: int) -> list[int]:
    """
    Fe: derive a per-block 64-word schedule from Fx(base).

    Critical (har1 Fi/FL/Fs):
      - FL passes an empty expanded[] into Fi; Fi does
          rA = bi*64; if expanded[rA] === undefined: Fe(base, bi, expanded, rA)
        so **block_index 0 also runs Fe** — never use raw Fx schedule for encrypt.
      - Fs precomputes Fe(base, i) for every i when plen >= 16384.
      - Fe(bi=0) != base_sched (two mixing passes + fresh Fx).
    """
    O = list(base_sched)
    while len(O) < 64:
        O.append(0)
    S = block_index & 255
    rV = 0
    rX = 0
    rc = S
    for _ in range(32):
        rX = _u32(rX + (_u32((_u32(rc << 4) ^ (rc >> 5)) + rc) ^ O[rV]))
        rV += 1
        rc = _u32(rc + (_u32((_u32(rX << 4) ^ (rX >> 5)) + rX) ^ O[rV]))
        rV += 1
    rA, rE = rX, rc
    rX = 0
    rc = (S + 1) & 255
    rV = 0
    for _ in range(32):
        rX = _u32(rX + (_u32((_u32(rc << 4) ^ (rc >> 5)) + rc) ^ O[rV]))
        rV += 1
        rc = _u32(rc + (_u32((_u32(rX << 4) ^ (rX >> 5)) + rX) ^ O[rV]))
        rV += 1
    return fx_schedule(rA, rE, rX, rc)


def xxtea_encrypt_block(y: int, z: int, sched: list[int], base: int = 0) -> tuple[int, int]:
    rA = base
    for _ in range(32):
        y = _u32(y + (_u32((_u32(z << 4) ^ (z >> 5)) + z) ^ sched[rA]))
        rA += 1
        z = _u32(z + (_u32(((y >> 5) ^ _u32(y << 4)) + y) ^ sched[rA]))
        rA += 1
    return y, z


def fj_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def fh_wrap(data: bytes, *, compressed: Optional[bytes] = None, try_f6: bool = True) -> bytes:
    """
    Fh framing: [253, 1, flag] + body.
    flag=1 when F6 compression wins (large plains / FO2 path).
    """
    if compressed is not None and len(compressed) < len(data):
        return bytes([253, 1, 1]) + compressed
    if try_f6 and len(data) >= 128:
        try:
            from g.turnstile_f6 import f6_compress

            c = f6_compress(data)
            if len(c) < len(data):
                return bytes([253, 1, 1]) + c
        except Exception:
            pass
    return bytes([253, 1, 0]) + data


def gdrqi3_identity(k16: bytes) -> bytes:
    return bytes(k16)


def gdrqi3_xor(s: str) -> Callable[[bytes], bytes]:
    """Factory: recovered gDRqi3 = bytewise XOR with repeating key string s."""
    if not s:
        raise ValueError("gDRqi3 XOR key string empty")
    key = s.encode("latin-1")

    def _fn(k16: bytes) -> bytes:
        n = len(key)
        return bytes(k16[i] ^ key[i % n] for i in range(len(k16)))

    return _fn


def gdrqi3_har1(k16: bytes) -> bytes:
    """har1 session gDRqi3 (offline sample only)."""
    return gdrqi3_xor(HAR1_GDRQI3_S)(k16)


def rsa_header(fc: bytes, n: int, e: int = 65537) -> bytes:
    if len(fc) != 128:
        raise ValueError("fc must be 128 bytes")
    fu = int.from_bytes(fc, "big") % n
    return pow(fu, e, n).to_bytes(128, "big")


@dataclass
class FaEncodeResult:
    body: str
    raw: bytes
    pad: int
    fc: bytes
    header: bytes
    payload_len: int

    def to_dict(self) -> dict:
        return {
            "body_len": len(self.body),
            "raw_len": len(self.raw),
            "pad": self.pad,
            "payload_len": self.payload_len,
            "fc_hex": self.fc.hex(),
            "header_hex": self.header.hex(),
            "body_head": self.body[:48],
        }


def make_fc(seed: Optional[bytes] = None) -> bytes:
    """Generate 128B FC material (FC[0]=2). Optional seed must be 128B."""
    if seed is not None:
        if len(seed) != 128:
            raise ValueError("fc seed must be 128 bytes")
        fc = bytearray(seed)
        fc[0] = 2
        return bytes(fc)
    fc = bytearray(os.urandom(128))
    fc[0] = 2
    return bytes(fc)


def load_fc(path_or_hex: str | bytes | bytearray | Path) -> bytes:
    """
    Load 128B FC from: raw bytes, hex string, or file path
    (.bin / .hex / capture fc0_raw.bin / fc.hex).
    """
    from pathlib import Path as _Path

    if isinstance(path_or_hex, (bytes, bytearray)):
        b = bytes(path_or_hex)
        if len(b) == 128:
            return b
        if len(b) == 256:
            # maybe hex ascii
            try:
                return bytes.fromhex(b.decode("ascii").strip())
            except Exception as e:
                raise ValueError(f"fc bytes len={len(b)} not 128") from e
        raise ValueError(f"fc bytes len={len(b)} not 128")

    s = str(path_or_hex).strip()
    p = _Path(s)
    if p.is_file():
        raw = p.read_bytes()
        if len(raw) == 128:
            return raw
        text = raw.decode("utf-8", errors="replace").strip()
        # hex file
        hx = "".join(text.split())
        if len(hx) == 256 and all(c in "0123456789abcdefABCDEF" for c in hx):
            return bytes.fromhex(hx)
        raise ValueError(f"cannot load 128B fc from {p} (size={len(raw)})")
    # bare hex
    hx = "".join(s.split())
    if len(hx) == 256 and all(c in "0123456789abcdefABCDEF" for c in hx):
        return bytes.fromhex(hx)
    raise ValueError("fc must be 128 raw bytes, 256 hex chars, or a path")


class FaEncoder:
    """
    Session-bound FA encoder (needs F7/F8 from live rch).

    Critical session rule (HAR + live capture verified):
      FO1 and FO2 share the SAME FC → same 128B RSA header.
      encode() must NOT mint a new random FC per call inside one FO session.
    """

    def __init__(
        self,
        keys: FoSessionKeys,
        *,
        gdrqi3: Optional[Callable[[bytes], bytes]] = None,
        gdrqi3_s: Optional[str] = None,
        session_fc: Optional[bytes] = None,
    ):
        self.keys = keys
        if gdrqi3 is not None:
            self.gdrqi3 = gdrqi3
        elif gdrqi3_s is not None:
            self.gdrqi3 = gdrqi3_xor(gdrqi3_s)
        else:
            # default: har1 recovered XOR (better than identity for that sample)
            self.gdrqi3 = gdrqi3_har1
        self.codec = FoCodec(keys)
        self.gdrqi3_s = gdrqi3_s
        # Bound for whole FO1→FO2 chain; set on first encode if None
        self.session_fc: Optional[bytes] = (
            make_fc(session_fc) if session_fc is not None else None
        )

    def bind_fc(self, fc: bytes) -> bytes:
        """Pin session FC (browser FO1 capture or prior encode). Returns normalized 128B."""
        if len(fc) != 128:
            raise ValueError("fc must be 128 bytes")
        self.session_fc = bytes(fc)
        if self.session_fc[0] != 2:
            # capture may already be valid; only force if clearly random without flag
            pass
        return self.session_fc

    def clear_fc(self) -> None:
        """Drop bound FC (new FO session)."""
        self.session_fc = None

    def ensure_fc(self, fc: Optional[bytes] = None, *, rotate: bool = False) -> bytes:
        """
        Resolve FC for this encode:
          - explicit fc= wins and rebinds session
          - else reuse session_fc
          - else mint once and bind (unless rotate forces new)
        """
        if fc is not None:
            return self.bind_fc(fc)
        if rotate or self.session_fc is None:
            return self.bind_fc(make_fc())
        return self.session_fc

    @classmethod
    def from_rch(cls, html_or_js: str, **kwargs) -> Optional["FaEncoder"]:
        from g.turnstile_fo_codec import extract_fo_keys_from_rch

        k = extract_fo_keys_from_rch(html_or_js)
        return cls(k, **kwargs) if k else None

    @classmethod
    def har1_sample(cls, **kwargs) -> "FaEncoder":
        kwargs.setdefault("gdrqi3_s", HAR1_GDRQI3_S)
        return cls(
            FoSessionKeys(
                alphabet=HAR1_F7[:64],
                pad_char=HAR1_F7[64],
                f7_raw=HAR1_F7,
                n=int(HAR1_F8_HEX, 16),
                e=65537,
                source="har1_sample",
            ),
            **kwargs,
        )

    def encode(
        self,
        plain: Any,
        *,
        fc: Optional[bytes] = None,
        use_fh: bool = True,
        rotate_fc: bool = False,
    ) -> FaEncodeResult:
        """
        Encode FO plain. FO1/FO2 in one session: call encode twice WITHOUT rotate_fc;
        second call reuses first call's FC → identical RSA header.

        To inject browser-captured FO1 FC for FO2:
            enc.bind_fc(load_fc('fc0_raw.bin')); enc.encode(fo2_plain)
        or: enc.encode(fo2_plain, fc=load_fc(...))
        """
        fc = self.ensure_fc(fc, rotate=rotate_fc)

        raw_json = fj_json_bytes(plain) if not isinstance(plain, (bytes, bytearray)) else bytes(plain)
        if isinstance(plain, (bytes, bytearray)):
            framed = bytes(plain)
        else:
            framed = bytes([32]) + raw_json + bytes([32])

        data = fh_wrap(framed) if use_fh else framed
        pad = (8 - (len(data) % 8)) % 8
        data = data + bytes(pad)
        plen = len(data)

        header = rsa_header(fc, self.keys.n, self.keys.e)
        off = 9 * pad + 40
        k16 = self.gdrqi3(fc[off : off + 16])
        if len(k16) != 16:
            raise ValueError("gDRqi3 must return 16 bytes")
        k0, k1, k2, k3 = _be_u32(k16, 0), _be_u32(k16, 4), _be_u32(k16, 8), _be_u32(k16, 12)
        base_sched = fx_schedule(k0, k1, k2, k3)
        expanded: dict[int, list[int]] = {}

        out = bytearray(header)
        out.append(pad)
        for off_b in range(0, plen, 8):
            bi = (off_b >> 3) & 255
            if bi not in expanded:
                expanded[bi] = fe_expand(base_sched, bi)
            y = _be_u32(data, off_b)
            z = _be_u32(data, off_b + 4)
            y2, z2 = xxtea_encrypt_block(y, z, expanded[bi], 0)
            out.extend(_pack_be_u32(y2, z2))

        raw = bytes(out)
        body = self.codec.encode(raw)
        return FaEncodeResult(body=body, raw=raw, pad=pad, fc=fc, header=header, payload_len=plen)



def self_check() -> dict:
    enc = FaEncoder.har1_sample()
    r = enc.encode({"ping": 1})
    # same session: FO2 must reuse FC → identical RSA header
    r2 = enc.encode({"pong": 2})
    same_fc = r.fc == r2.fc
    same_header = r.header == r2.header
    # rotate mints a new FC
    r3 = enc.encode({"next": 3}, rotate_fc=True)
    rotated = r3.fc != r.fc and r3.header != r.header
    # explicit bind
    enc2 = FaEncoder.har1_sample()
    fixed = make_fc()
    enc2.bind_fc(fixed)
    r4 = enc2.encode({"a": 1})
    r5 = enc2.encode({"b": 2})
    bound_ok = r4.fc == fixed and r5.fc == fixed and r4.header == r5.header
    # decode back outer shell
    parsed = enc.codec.parse_body(r.body)
    # gDRqi3 unit: known vector from Node probe
    probe_in = bytes(range(1, 17))
    probe_out = gdrqi3_har1(probe_in)
    probe_ok = probe_out.hex() == "7972446a674a57654a624e667a637c75"
    ok = (
        bool(parsed.get("ok"))
        and parsed.get("pad_byte") == r.pad
        and probe_ok
        and same_fc
        and same_header
        and rotated
        and bound_ok
    )
    return {
        "ok": ok,
        "encode": r.to_dict(),
        "session_fc": {
            "same_fc": same_fc,
            "same_header": same_header,
            "rotate_ok": rotated,
            "bind_ok": bound_ok,
            "fo1_header": r.header.hex()[:32],
            "fo2_header": r2.header.hex()[:32],
        },
        "parse": {
            "pad_byte": parsed.get("pad_byte"),
            "payload_len": parsed.get("payload_len"),
            "header_lt_n": parsed.get("header_lt_n"),
        },
        "gdrqi3": {
            "s": HAR1_GDRQI3_S,
            "probe_ok": probe_ok,
            "probe_out_hex": probe_out.hex(),
        },
        "notes": [
            "outer RSA+b64 shell OK",
            "FO1/FO2 MUST share session FC (RSA header identical)",
            "gDRqi3 = XOR with session string from runProgram (har1 s recovered)",
            "live: bind browser FO1 FC via enc.bind_fc(load_fc(...)) before FO2",
        ],
    }


if __name__ == "__main__":
    print(json.dumps(self_check(), ensure_ascii=False, indent=2))
