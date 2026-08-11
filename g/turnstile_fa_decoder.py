# -*- coding: utf-8 -*-
"""FA / XXTEA decrypt (session FC required). Recovered inverse of FaEncoder."""
from __future__ import annotations

import struct
from typing import Callable, Optional

from g.turnstile_fa_encoder import (
    _be_u32,
    _pack_be_u32,
    _u32,
    fe_expand,
    fx_schedule,
    gdrqi3_har1,
)


def xxtea_decrypt_block(y: int, z: int, sched: list[int], base: int = 0) -> tuple[int, int]:
    rA = base + 63
    for _ in range(32):
        z = _u32(z - (_u32(((y >> 5) ^ _u32(y << 4)) + y) ^ sched[rA]))
        rA -= 1
        y = _u32(y - (_u32((_u32(z << 4) ^ (z >> 5)) + z) ^ sched[rA]))
        rA -= 1
    return y, z


def fa_decrypt_raw(
    raw: bytes,
    fc: bytes,
    *,
    gdrqi3: Optional[Callable[[bytes], bytes]] = None,
) -> dict:
    """
    Decrypt FO raw (header||pad||payload) given FC (128B session key material).
    Returns framed plaintext after XXTEA (+ strip pad).
    """
    if len(raw) < 129:
        return {"ok": False, "error": "raw too short"}
    if len(fc) != 128:
        return {"ok": False, "error": "fc must be 128"}
    pad = raw[128]
    payload = raw[129:]
    if len(payload) % 8:
        return {"ok": False, "error": "payload not multiple of 8"}
    g = gdrqi3 or gdrqi3_har1
    off = 9 * pad + 40
    k16 = g(fc[off : off + 16])
    base_sched = fx_schedule(
        _be_u32(k16, 0), _be_u32(k16, 4), _be_u32(k16, 8), _be_u32(k16, 12)
    )
    expanded: dict[int, list[int]] = {}
    out = bytearray()
    for off_b in range(0, len(payload), 8):
        bi = (off_b >> 3) & 255
        if bi not in expanded:
            expanded[bi] = fe_expand(base_sched, bi)
        y = _be_u32(payload, off_b)
        z = _be_u32(payload, off_b + 4)
        y2, z2 = xxtea_decrypt_block(y, z, expanded[bi], 0)
        out.extend(_pack_be_u32(y2, z2))
    if pad:
        out = out[: len(out) - pad]
    data = bytes(out)
    fh = None
    body = data
    if len(data) >= 3 and data[0] == 253 and data[1] == 1:
        fh = {"magic": 253, "ver": data[1], "flag": data[2]}
        body = data[3:]
        if fh["flag"] == 1:
            try:
                from g.turnstile_f6 import f6_decompress

                body = f6_decompress(body)
            except Exception as e:
                return {
                    "ok": False,
                    "error": f"f6_decompress: {e}",
                    "pad": pad,
                    "fh": fh,
                    "comp_len": len(data) - 3,
                }
    # strip space framing
    if body[:1] == b" " and body[-1:] == b" ":
        body = body[1:-1]
    # Wrong gdrqi3_s / FC yields garbage that still "decrypts" — require JSON plain.
    head = body.lstrip()[:1]
    if head not in (b"{", b"["):
        return {
            "ok": False,
            "error": "decrypted body is not JSON (bad FC or gdrqi3_s)",
            "pad": pad,
            "fh": fh,
            "body_len": len(body),
            "body_head": body[:80],
        }
    return {
        "ok": True,
        "pad": pad,
        "fh": fh,
        "body": body,
        "body_len": len(body),
        "body_head": body[:80],
    }
