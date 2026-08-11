# -*- coding: utf-8 -*-
"""
Turnstile FO body codec — recovered from har1 rch_big_script.js (Reqable success chain).

Confirmed structure (per session rch):
  F7 = 65-char string: alphabet[64] + pad char (often 'y' or session-variant)
  F8 = RSA-1024 modulus (BigInt hex)
  F9 = e = 65537
  FA(payload_bytes) -> custom_b64:
      rsa_header(128) || pad_byte(1) || enc_payload
      where rsa_header = pow(random_key, e, n).to_bytes(128, 'big')
      pad_byte = (8 - plain_len % 8) % 8   (observed 0..7)

FO1/FO2 in same session share the same 128-byte RSA header (same random key).
Alphabet is session/build-dynamic — extract from each rch, never hardcode forever.

HAR evidence:
  logs/har1/extracted/fo_codec_facts.json
  logs/har1/extracted/fo1_decoded.bin / fo2_decoded.bin
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


# har1 session sample (for offline tests only)
HAR1_F7 = "-vPLbnS2fYwCRVl6DANhGmKZX$JcMxEIkgit1aT5QejFqOzrU0s3pWH97u84odB+y"
HAR1_F8_HEX = (
    "00e9d3dca1328a49ad3403e4badda37a6a13610b608b5099839e1074e720f5a33b"
    "2ebd8c2ffd12c09be0015a4635aa9d2022d8f72f90ed11610c3742b0baef5b7da7"
    "3d7e79aff6cdbdeab72492ce0a858e4c1f4c27a14ebbb4ce3beacfda982fe74463"
    "e76f654aab0c597d5e73686ea149023e8f60ae6365a30055fe2c5eb2ebfb"
)

# har2 session sample — alphabet/pad changed; RSA n same 1024-bit family
HAR2_F7 = "hRqQOPLxenXCDUYIc-AZ3FBTKjo8bzdy2u1pGM4w5vka9g7iH0+EWSftl6rsJN$mV"
HAR2_F8_HEX = (
    "e9d3dca1328a49ad3403e4badda37a6a13610b608b5099839e1074e720f5a33b"
    "2ebd8c2ffd12c09be0015a4635aa9d2022d8f72f90ed11610c3742b0baef5b7da7"
    "3d7e79aff6cdbdeab72492ce0a858e4c1f4c27a14ebbb4ce3beacfda982fe74463"
    "e76f654aab0c597d5e73686ea149023e8f60ae6365a30055fe2c5eb2ebfb"
)


@dataclass
class FoSessionKeys:
    alphabet: str  # 64 chars
    pad_char: str  # 1 char (F7[64])
    f7_raw: str  # full 65-char F7
    n: int  # RSA modulus
    e: int = 65537
    source: str = ""

    def to_dict(self) -> dict:
        return {
            "alphabet": self.alphabet,
            "pad_char": self.pad_char,
            "f7_raw": self.f7_raw,
            "n_hex": f"{self.n:x}",
            "n_bits": self.n.bit_length(),
            "e": self.e,
            "source": self.source,
        }


def extract_fo_keys_from_rch(html_or_js: str) -> Optional[FoSessionKeys]:
    """
    从 rch HTML/内联脚本抠 F7 / F8 / F9。

    历史: F7=`...65chars...`, F8=BigInt(`0x...`), F9=BigInt(65537)
    live 2026-07: 名字混淆，形如
      ii=`b2wIYM8W...C9-`, iW=BigInt(`0x00e9d3...`), id=BigInt(65537)
    pad 不再固定为 'y'，是 alphabet 第 65 字符（本样本 '-'）。
    """
    if not html_or_js:
        return None

    f7: Optional[str] = None
    # 1) classic F7=
    m7 = re.search(r"F7=`([\$\+\-A-Za-z0-9]{64,66})`", html_or_js)
    if m7:
        f7 = m7.group(1)
    # 2) adjacent alphabet + BigInt modulus (live: ii=`...`,iW=BigInt(`0x...`))
    if not f7:
        m7 = re.search(
            r"=`([\$\+\-A-Za-z0-9]{64}[A-Za-z0-9\$\+\-]?)`\s*,\s*\w+=BigInt\(`0x",
            html_or_js,
        )
        if m7:
            f7 = m7.group(1)
    # 3) any 65-char base64-ish with 64 unique symbols (prefer near BigInt)
    if not f7:
        candidates = re.findall(r"`([\$\+\-A-Za-z0-9]{64,66})`", html_or_js)
        for c in candidates:
            if len(c) >= 64 and len(set(c[:64])) >= 60:
                f7 = c
                break

    m8 = re.search(r"F8=BigInt\(`(0x[0-9a-fA-F]+|[0-9a-fA-F]{200,})`\)", html_or_js)
    if not m8:
        m8 = re.search(r"BigInt\(`(0x[0-9a-fA-F]{250,})`\)", html_or_js)
    # 65537 is the standard e; avoid grabbing BigInt(0/1/2/8) temporaries
    m9 = re.search(r"(?:F9|\w{1,4})=BigInt\((65537)\)", html_or_js)
    if not m9:
        m9 = re.search(r"BigInt\((65537)\)", html_or_js)

    if not f7 or not m8:
        return None
    if len(f7) < 64:
        return None
    alph = f7[:64]
    pad = f7[64] if len(f7) > 64 else ""
    if len(set(alph)) < 60:
        return None
    hx = m8.group(1)
    n = int(hx, 16)
    e = int(m9.group(1)) if m9 else 65537
    return FoSessionKeys(
        alphabet=alph,
        pad_char=pad,
        f7_raw=f7 if len(f7) >= 65 else alph + (pad or ""),
        n=n,
        e=e,
        source="rch_extract",
    )


class FoCodec:
    """Custom base64 + RSA-header FO body codec."""

    def __init__(self, keys: FoSessionKeys):
        self.keys = keys
        self.alphabet = keys.alphabet
        self.pad_char = keys.pad_char
        self._dec = {c: i for i, c in enumerate(self.alphabet)}

    @classmethod
    def from_rch(cls, html_or_js: str) -> Optional["FoCodec"]:
        k = extract_fo_keys_from_rch(html_or_js)
        return cls(k) if k else None

    @classmethod
    def har1_sample(cls) -> "FoCodec":
        return cls(
            FoSessionKeys(
                alphabet=HAR1_F7[:64],
                pad_char=HAR1_F7[64],
                f7_raw=HAR1_F7,
                n=int(HAR1_F8_HEX, 16),
                e=65537,
                source="har1_sample",
            )
        )

    @classmethod
    def har2_sample(cls) -> "FoCodec":
        return cls(
            FoSessionKeys(
                alphabet=HAR2_F7[:64],
                pad_char=HAR2_F7[64],
                f7_raw=HAR2_F7,
                n=int(HAR2_F8_HEX, 16),
                e=65537,
                source="har2_sample",
            )
        )

    def encode(self, data: bytes) -> str:
        alph = self.alphabet
        out: list[str] = []
        n = len(data)
        i = 0
        while i + 3 <= n:
            rc = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
            out.append(alph[(rc >> 18) & 63])
            out.append(alph[(rc >> 12) & 63])
            out.append(alph[(rc >> 6) & 63])
            out.append(alph[rc & 63])
            i += 3
        rem = n - i
        if rem == 1:
            rc = data[i] << 16
            out.append(alph[(rc >> 18) & 63])
            out.append(alph[(rc >> 12) & 63])
        elif rem == 2:
            rc = (data[i] << 16) | (data[i + 1] << 8)
            out.append(alph[(rc >> 18) & 63])
            out.append(alph[(rc >> 12) & 63])
            out.append(alph[(rc >> 6) & 63])
        return "".join(out)

    def decode(self, s: str) -> bytes:
        dec = self._dec
        n = len(s)
        while n > 0 and self.pad_char and s[n - 1] == self.pad_char:
            n -= 1
        s = s[:n]
        out = bytearray()
        i = 0
        while i + 4 <= n:
            a, b, c, d = dec[s[i]], dec[s[i + 1]], dec[s[i + 2]], dec[s[i + 3]]
            rc = (a << 18) | (b << 12) | (c << 6) | d
            out.append((rc >> 16) & 0xFF)
            out.append((rc >> 8) & 0xFF)
            out.append(rc & 0xFF)
            i += 4
        rem = n - i
        if rem == 2:
            a, b = dec[s[i]], dec[s[i + 1]]
            rc = (a << 18) | (b << 12)
            out.append((rc >> 16) & 0xFF)
        elif rem == 3:
            a, b, c = dec[s[i]], dec[s[i + 1]], dec[s[i + 2]]
            rc = (a << 18) | (b << 12) | (c << 6)
            out.append((rc >> 16) & 0xFF)
            out.append((rc >> 8) & 0xFF)
        elif rem == 1:
            raise ValueError("invalid custom-b64 remainder=1")
        return bytes(out)

    def parse_body(self, body: str) -> dict:
        """Decode FO text body → header/pad/payload parts."""
        raw = self.decode(body)
        if len(raw) < 129:
            return {"ok": False, "error": f"decoded too short: {len(raw)}", "raw_len": len(raw)}
        header = raw[:128]
        pad_byte = raw[128]
        payload = raw[129:]
        hdr_int = int.from_bytes(header, "big")
        return {
            "ok": True,
            "raw_len": len(raw),
            "header_hex": header.hex(),
            "header_bits": hdr_int.bit_length(),
            "header_lt_n": hdr_int < self.keys.n,
            "pad_byte": pad_byte,
            "payload_len": len(payload),
            "payload_entropy_hint": round(
                # cheap unique-ratio proxy
                len(set(payload)) / max(1, min(len(payload), 256)),
                3,
            ),
        }

    def wrap_rsa_header(self, enc_payload: bytes, pad_byte: int, *, key_material: bytes | None = None) -> bytes:
        """
        Build raw FO binary: RSA(header) || pad || payload.
        key_material: 128 random bytes for session key (FC); if None, uses os.urandom.
        NOTE: without private key we cannot decrypt; server verifies with its key.
        Client only needs public encrypt of random session key — this matches FA.
        """
        import os

        if not (0 <= pad_byte <= 7):
            raise ValueError("pad_byte must be 0..7")
        if key_material is None:
            # FA: crypto.getRandomValues(128), then force first byte = 2 (Fr=BigInt(2))
            fc = bytearray(os.urandom(128))
            fc[0] = 2
            key_material = bytes(fc)
        if len(key_material) != 128:
            raise ValueError("key_material must be 128 bytes")
        # Fu = int.from_bytes(FC, 'big'); FW = pow(Fu % n, e, n)
        fu = int.from_bytes(key_material, "big") % self.keys.n
        fw = pow(fu, self.keys.e, self.keys.n)
        header = fw.to_bytes(128, "big")
        return header + bytes([pad_byte]) + enc_payload


def verify_har1_roundtrip() -> dict:
    """Offline self-check against har1 FO samples."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "logs" / "har1" / "extracted"
    codec = FoCodec.har1_sample()
    out: dict = {"ok": True, "checks": []}
    for name in ("fo_01_e8_req.txt", "fo_02_e20_req.txt"):
        p = root / name
        if not p.exists():
            out["checks"].append({"file": name, "ok": False, "error": "missing"})
            out["ok"] = False
            continue
        body = p.read_text(encoding="utf-8").strip()
        try:
            raw = codec.decode(body)
            reenc = codec.encode(raw)
            parsed = codec.parse_body(body)
            ok = reenc == body and parsed.get("ok")
            out["checks"].append(
                {
                    "file": name,
                    "ok": ok,
                    "decoded_len": len(raw),
                    "pad_byte": parsed.get("pad_byte"),
                    "payload_len": parsed.get("payload_len"),
                    "header_lt_n": parsed.get("header_lt_n"),
                }
            )
            if not ok:
                out["ok"] = False
        except Exception as e:
            out["checks"].append({"file": name, "ok": False, "error": str(e)})
            out["ok"] = False
    return out


# ── Live session F7 auto-detection ──

# Known base alphabet (HAR1 character set, shared across builds)
_F7_BASE_CHARS = "-vPLbnS2fYwCRVl6DANhGmKZX$JcMxEIkgit1aT5QejFqOzrU0s3pWH97u84odB+y"


def detect_f7_from_body(fo_body: str, n: int, e: int = 65537) -> Optional[FoSessionKeys]:
    """
    Auto-detect F7 alphabet from a FO body by trying rotations of the known base alphabet.
    Returns FoSessionKeys if found, None otherwise.

    The F7 alphabet is a rotation of the HAR1 base charset (max 1 pair swap).
    We find it by checking parse validity: pad_byte must be 0-7.
    """
    alpha64 = _F7_BASE_CHARS[:64]
    pad_base = _F7_BASE_CHARS[64]

    best = None
    best_score = 999

    # Try rotations
    for rot in range(64):
        base = list(alpha64[rot:] + alpha64[:rot])

        # Try pure rotation
        for pad_char in (pad_base, "y"):
            f7 = "".join(base) + pad_char
            keys = FoSessionKeys(alphabet=f7[:64], pad_char=f7[64], f7_raw=f7, n=n, e=e)
            codec = FoCodec(keys)
            try:
                p = codec.parse_body(fo_body)
                if p["ok"]:
                    score = p["pad_byte"] if p["pad_byte"] > 7 else 0
                    if score < best_score:
                        best_score = score
                        best = keys
                        if score == 0:
                            return best
            except Exception:
                pass

        # Try swapping adjacent pair (common variation)
        for i in range(63):
            chars = base[:]
            chars[i], chars[i + 1] = chars[i + 1], chars[i]
            for pad_char in (pad_base, "y"):
                f7 = "".join(chars) + pad_char
                keys = FoSessionKeys(alphabet=f7[:64], pad_char=f7[64], f7_raw=f7, n=n, e=e)
                codec = FoCodec(keys)
                try:
                    p = codec.parse_body(fo_body)
                    if p["ok"]:
                        score = p["pad_byte"] if p["pad_byte"] > 7 else 0
                        if score < best_score:
                            best_score = score
                            best = keys
                            if score == 0:
                                return best
                except Exception:
                    pass

    # Try wider swap search if pure rotation + adjacent didn't work
    if best is None or best_score > 0:
        for rot in range(64):
            base = list(alpha64[rot:] + alpha64[:rot])
            for i in range(64):
                for j in range(i + 1, min(i + 50, 64)):
                    chars = base[:]
                    chars[i], chars[j] = chars[j], chars[i]
                    for pad_char in (pad_base, "y"):
                        f7 = "".join(chars) + pad_char
                        keys = FoSessionKeys(alphabet=f7[:64], pad_char=f7[64], f7_raw=f7, n=n, e=e)
                        codec = FoCodec(keys)
                        try:
                            p = codec.parse_body(fo_body)
                            if p["ok"]:
                                score = p["pad_byte"] if p["pad_byte"] > 7 else 0
                                if score < best_score:
                                    best_score = score
                                    best = keys
                                    if score == 0:
                                        return best
                        except Exception:
                            pass

    return best


def extract_fo_keys_from_live_session(
    html_or_js: str,
    fo1_body: str,
) -> Optional[FoSessionKeys]:
    """
    Extract FO keys for a live Turnstile session.
    1. Extract F8 (RSA modulus) and F9 (exponent) from RCH page
    2. Auto-detect F7 alphabet from FO1 body
    Returns complete FoSessionKeys.
    """
    # First try standard extraction (works for older builds)
    keys = extract_fo_keys_from_rch(html_or_js)
    if keys:
        return keys

    # For newer builds: extract F8 from RCH, detect F7 from FO1 body
    import re

    m8 = re.search(r"F8=BigInt\(`(0x[0-9a-fA-F]+|[0-9a-fA-F]{200,})`\)", html_or_js)
    if not m8:
        m8 = re.search(r"BigInt\(`(0x[0-9a-fA-F]{250,})`\)", html_or_js)

    m9 = re.search(r"F9=BigInt\((\d+)\)", html_or_js)
    e = int(m9.group(1)) if m9 else 65537

    if not m8:
        # Use known HAR1 modulus as fallback
        n = int(HAR1_F8_HEX, 16)
    else:
        hx = m8.group(1)
        n = int(hx, 16)

    return detect_f7_from_body(fo1_body, n, e)


if __name__ == "__main__":
    import json

    print(json.dumps(verify_har1_roundtrip(), ensure_ascii=False, indent=2))
