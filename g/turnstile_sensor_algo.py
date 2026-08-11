# -*- coding: utf-8 -*-
"""
FO2 sensor algorithm recovery — pure reverse (no browser).

Confirmed 2026-07-24 from:
  - logs/hybrid_fo2/20260723_130631/plains/02_fo2.json  (schema-drift live)
  - logs/fc_captures/20260721_175819/fo2_plain.json      (catalog names)
  - logs/fc_captures/20260722_161812/                    (cross-session)
  - pure FO1 F5 dig s3d/s3e (packer NOT in SETPROP)

==============================================================================
RECOVERED MODEL
==============================================================================

1) FO2 plain layout
   - keys "1".."37" FIRST (each value = sensor bag object)
   - then ~50 named keys (session/runtime; names rotate per rch)

2) Sensor bag = CORE + optional PAYLOAD
   CORE (always, 7 fields; names rotate):

     catalog          hybrid(20260723)   meaning
     ---------------  -----------------  ---------------------------------
     XsAVh8           eXxSy3             envelope A  ver=1.2.1.1
     oHTRn9           ofjO7              envelope B  ver=1.3.1.1
     qlAo5            (folded)           short 43-char token (older schema)
     qPgf1            mlsbV4             const int 3 (observed)
     ucpv9            Kerdl9             usually ""
     GqRg5            kznA6              t_start ms
     OwbxU6           BEJV6              t_end ms
     eOLK2            jxeDo4             (t_end - t_start) or size proxy

3) Envelope format (CONFIRMED)
     {p0}-{unix_ts}-{ver}-{rest}

     p0:
       - always 43 chars url-safe base64 alphabet [A-Za-z0-9._-]
       - decodes to ~29–32 bytes (most 32)
       - unique per sensor entry; p0_a != p0_b always
       - NOT shared with FO1/rch preseed p0 (overlap=0)
       - NOT sha256/sha1/md5 of payload JSON (tested)

     ver:
       - envelope A: "1.2.1.1"
       - envelope B: "1.3.1.1"

     rest (envelope A / eXx / XsA):
       - lengths cluster {64, 86, 107} chars (~48 / 61–64 / 77–80 raw)
       - hybrid map: 107→sensors[1,2,7]; 86→majority; 64→[5,17,21,32]
       - high entropy

     rest (envelope B / ofj / oHT):
       - era-dependent: hybrid ~683–768 chars (raw ~492–564);
         older fc_captures ~790–811 chars (raw ~567–608)
       - high entropy; pairwise shared prefix/suffix = 0
       - does NOT scale with payload JSON size (empty≈heavy buckets)
       - therefore: fixed-size session MAC / AEAD proof, NOT payload ciphertext
       - NOT direct xor/HMAC/SHA of raw FC|gDRqi3 with p0|rest_a (O2 probe unhit)

4) TOKEN / clearance (CONFIRMED hybrid_130631)
     final turnstile token == "1.2.1.1-" + sensor[1].eXxSy3.rest
     (ver + rest_a only; p0/ts stripped)
     cf_clearance cookie uses same envelope grammar with longer rest body

5) Payload (optional extra keys on each bag)
   - Typed collector output: DOM prop table, WebGL, UA, keyboard map,
     feature bool[120], canvas/audio hex64, permissions JSON, CSS probe, etc.
   - Index order is SESSION-DYNAMIC (async completion order), NOT fixed slot-id.
     Evidence: catalog session A vs B — same index holds different payload kinds;
     hybrid vs catalog also reorders (WebGL at hybrid#6, catalog#24-ish).

6) Timing
   - t_end >= t_start; dt typically 0–300ms
   - unix_ts in envelopes is second-granularity of the FO2 assembly window

7) Session binding (why pure HTTP FO2 400)
   - envelopes (p0+rest) are session-crypto products
   - stale catalog sensors + live FO1 FC → HTTP 400 (proven pure_http_20260724)
   - structural clone alone is insufficient

8) Envelope mint location (O2c)
   - rch HTML version hits are PRESEEDED full envelopes in window._cf_chl_opt
     (hybrid: uWspn0/YBOCB4/WSVD3/OxOB2/kDeQp6/nextRcV) — not join templates
   - no bare "1.2.1.1" string literal for mint; no dash-join candidates in rch
   - mint lives in F5 VM bytecode / runtime host helpers (not SETPROP, not rch plaintext)
   - FO1 OxOB2 = huge 1.2.1.1 rest (~1127 raw) site/challenge seed ≠ per-sensor ofj

9) Packer location (negative results)
   - NOT FO1 F5 SETPROP Wg/Wf/Wf0/h5 (setprop_on_rl_S=0)
   - NOT a secondary program in FO1 HTTP response (resp F5 == fo1_f5_full)
   - IS browser FO1-stage multi-collector → FA(plain) path (CDP dump only so far)

==============================================================================
OPEN (next reverse targets)
==============================================================================
  O1. How p0 (32B) is minted — random? HMAC(session_key, slot||nonce)?
  O2. ofj rest key schedule — FO1-VM-derived key (not raw FC); need live hook
      on string join of ver+rest OR F5 opcode path that builds envelope
  O3. Per-collector pure JS reimplementation (WebGL/DOM/canvas…) for payload only
  O4. Wire from collector result → bag assembly opcode in FO1 F5 (non-SETPROP path)

Artifacts:
  logs/pure_http_algo/o2_mac_analysis.json
  logs/pure_http_algo/o2_mac_deep.json
  logs/pure_http_algo/o2_rch_hunt.json
  logs/pure_http_algo/o2_preseed.json
  logs/_algo_o2_mac.py / _algo_o2_deep.py / _algo_o2_rch_hunt.py / _algo_o2_preseed.py

Usage:
  python -m g.turnstile_sensor_algo
  from g.turnstile_sensor_algo import SensorAlgo, build_probe_sensors
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]

# ── confirmed catalog ↔ hybrid core map ─────────────────────────────────────
CORE_MAP_CATALOG_TO_HYBRID: dict[str, str] = {
    "XsAVh8": "eXxSy3",  # envelope A 1.2.1.1
    "oHTRn9": "ofjO7",   # envelope B 1.3.1.1
    "qPgf1": "mlsbV4",   # flag int
    "ucpv9": "Kerdl9",   # status / empty
    "GqRg5": "kznA6",    # t0
    "OwbxU6": "BEJV6",   # t1
    "eOLK2": "jxeDo4",   # duration
}

CORE_CATALOG: tuple[str, ...] = (
    "XsAVh8",
    "qlAo5",
    "oHTRn9",
    "qPgf1",
    "ucpv9",
    "wZHkQ5",
    "kExc4",
    "GqRg5",
    "OwbxU6",
    "eOLK2",
)

CORE_HYBRID: tuple[str, ...] = (
    "eXxSy3",
    "ofjO7",
    "mlsbV4",
    "Kerdl9",
    "kznA6",
    "BEJV6",
    "jxeDo4",
)

ENVELOPE_VER_A = "1.2.1.1"
ENVELOPE_VER_B = "1.3.1.1"
P0_LEN = 43  # urlsafe b64 of 32 bytes
SENSOR_COUNT = 37

ENVELOPE_RE = re.compile(
    r"^(?P<p0>[A-Za-z0-9._-]{20,})-(?P<ts>\d{10})-"
    r"(?P<ver>\d+\.\d+\.\d+\.\d+)-(?P<rest>.+)$"
)

# Observed payload archetypes (content-based, index-agnostic)
PAYLOAD_ARCHETYPES = {
    "dom_prop_table": "numeric-key dict of property-name lists (window/document/nav)",
    "webgl_gpu": "ANGLE/WebGL vendor + limits + feature lists",
    "navigator_ua": "ua/platform/language/hardware fields",
    "keyboard_map": "KeyboardLayoutMap-like key code object",
    "feature_bools": "long bool list (~120)",
    "canvas_or_crypto_hex64": "one or more 64-hex digests",
    "user_agent_data": "brands/fullVersionList/architecture/bitness",
    "permissions": "geolocation/notifications/media permission states",
    "css_probe": "injected CSS text / computed style fingerprint",
    "stack_trace": "RR@ or Error stack string",
    "net_status": "status_400 / fetch_error style",
    "empty_slot": "core only, no extra keys",
}


@dataclass
class Envelope:
    p0: str
    ts: int
    ver: str
    rest: str
    raw: str

    @property
    def p0_bytes(self) -> Optional[bytes]:
        try:
            pad = "=" * ((4 - len(self.p0) % 4) % 4)
            return base64.urlsafe_b64decode(self.p0 + pad)
        except Exception:
            return None

    @property
    def p0_len(self) -> int:
        return len(self.p0)

    @property
    def rest_len(self) -> int:
        return len(self.rest)

    def to_dict(self) -> dict:
        b = self.p0_bytes
        return {
            "p0": self.p0,
            "p0_len": self.p0_len,
            "p0_raw_len": len(b) if b else None,
            "p0_hex": b.hex() if b else None,
            "ts": self.ts,
            "ver": self.ver,
            "rest_len": self.rest_len,
            "raw_len": len(self.raw),
        }


def parse_envelope(s: str) -> Optional[Envelope]:
    if not isinstance(s, str):
        return None
    m = ENVELOPE_RE.match(s)
    if not m:
        return None
    return Envelope(
        p0=m.group("p0"),
        ts=int(m.group("ts")),
        ver=m.group("ver"),
        rest=m.group("rest"),
        raw=s,
    )


def format_envelope(p0: str, ts: int, ver: str, rest: str) -> str:
    return f"{p0}-{int(ts)}-{ver}-{rest}"


def token_from_sensor1(bag: dict) -> Optional[str]:
    """CONFIRMED: turnstile token = 1.2.1.1-{envelope_a.rest of sensor index 1}."""
    env_s = bag.get("eXxSy3") or bag.get("XsAVh8")
    env = parse_envelope(str(env_s or ""))
    if not env or env.ver != ENVELOPE_VER_A:
        return None
    return f"{ENVELOPE_VER_A}-{env.rest}"


def b64url_32(data32: bytes) -> str:
    if len(data32) != 32:
        raise ValueError("need 32 bytes")
    return base64.urlsafe_b64encode(data32).decode("ascii").rstrip("=")


def classify_payload(extra: dict[str, Any]) -> list[str]:
    """Heuristic archetype tags for bag extras."""
    tags: list[str] = []
    if not extra:
        return ["empty_slot"]
    for k, v in extra.items():
        if isinstance(v, dict) and v and all(str(x).isdigit() for x in list(v.keys())[:8]):
            # list-of-names under numeric keys
            sample = next(iter(v.values()))
            if isinstance(sample, list) and sample and isinstance(sample[0], str):
                if any("innerWidth" in str(x) or "hardwareConcurrency" in str(x) for x in sample):
                    tags.append("dom_prop_table")
                else:
                    tags.append("numdict_strlists")
            else:
                tags.append("numdict")
        elif isinstance(v, dict):
            keys = set(v.keys())
            if {"brands", "fullVersionList"} & keys or "architecture" in keys:
                tags.append("user_agent_data")
            elif any("WebGL" in str(x) or "ANGLE" in str(x) for x in v.values()):
                tags.append("webgl_gpu")
            elif any(str(x).startswith("Digit") or str(x) == "Backquote" for x in keys):
                tags.append("keyboard_map")
            else:
                tags.append(f"obj[{len(v)}]")
        elif isinstance(v, list):
            if v and isinstance(v[0], bool) and len(v) >= 80:
                tags.append("feature_bools")
            elif v and isinstance(v[0], list):
                flat = str(v)
                if "ANGLE" in flat or "WebGL" in flat or "nvidia" in flat.lower():
                    tags.append("webgl_gpu")
                else:
                    tags.append("nested_lists")
            elif v and isinstance(v[0], dict):
                tags.append("list_of_obj")
            elif v and isinstance(v[0], str) and len(v) >= 50:
                tags.append("str_list_long")
            else:
                tags.append(f"list[{len(v)}]")
        elif isinstance(v, str):
            if re.fullmatch(r"[0-9a-f]{64}", v):
                tags.append("canvas_or_crypto_hex64")
            elif re.fullmatch(r"[0-9a-f]{32}", v):
                tags.append("hex32")
            elif "status_" in v or "fetch_error" in v:
                tags.append("net_status")
            elif "background" in v or v.strip().startswith("."):
                tags.append("css_probe")
            elif "RR@" in v or "Error" in v:
                tags.append("stack_trace")
            elif v.startswith("http"):
                tags.append("url")
            elif v.startswith("["):
                try:
                    arr = json.loads(v)
                    if isinstance(arr, list) and arr and isinstance(arr[0], dict) and "state" in arr[0]:
                        tags.append("permissions")
                    else:
                        tags.append("jsonstr")
                except Exception:
                    tags.append("jsonstr")
            else:
                tags.append(f"str[{len(v)}]")
        elif isinstance(v, bool):
            tags.append("bool")
        elif isinstance(v, int):
            tags.append("int")
        elif isinstance(v, float):
            tags.append("float")
    # dedupe preserve order
    seen = set()
    out = []
    for t in tags:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out or ["unknown"]


@dataclass
class SensorBag:
    index: int
    core: dict[str, Any]
    payload: dict[str, Any]
    schema: str  # "catalog" | "hybrid" | "unknown"
    envelope_a: Optional[Envelope] = None
    envelope_b: Optional[Envelope] = None
    archetypes: list[str] = field(default_factory=list)

    def to_wire(self) -> dict[str, Any]:
        out = dict(self.core)
        out.update(self.payload)
        return out


def split_bag(index: int, bag: dict) -> SensorBag:
    if not isinstance(bag, dict):
        return SensorBag(index, {}, {}, "unknown")
    if "XsAVh8" in bag:
        schema = "catalog"
        core_names = set(CORE_CATALOG)
        ea = parse_envelope(str(bag.get("XsAVh8") or ""))
        eb = parse_envelope(str(bag.get("oHTRn9") or ""))
    elif "eXxSy3" in bag:
        schema = "hybrid"
        core_names = set(CORE_HYBRID)
        ea = parse_envelope(str(bag.get("eXxSy3") or ""))
        eb = parse_envelope(str(bag.get("ofjO7") or ""))
    else:
        schema = "unknown"
        core_names = set()
        ea = eb = None
        # best-effort: any envelope-looking string
        for v in bag.values():
            if isinstance(v, str) and ENVELOPE_RE.match(v):
                env = parse_envelope(v)
                if env and env.ver == ENVELOPE_VER_A and ea is None:
                    ea = env
                elif env and env.ver == ENVELOPE_VER_B and eb is None:
                    eb = env
    core = {k: bag[k] for k in bag if k in core_names}
    payload = {k: bag[k] for k in bag if k not in core_names}
    return SensorBag(
        index=index,
        core=core,
        payload=payload,
        schema=schema,
        envelope_a=ea,
        envelope_b=eb,
        archetypes=classify_payload(payload),
    )


class SensorAlgo:
    """Analyzer + structural synthesizer for FO2 sensors."""

    def __init__(self, plain: dict):
        self.plain = plain
        self.sensors: list[SensorBag] = []
        for i in range(1, SENSOR_COUNT + 1):
            if str(i) in plain and isinstance(plain[str(i)], dict):
                self.sensors.append(split_bag(i, plain[str(i)]))
        self.named = {k: v for k, v in plain.items() if not str(k).isdigit()}

    def analyze(self) -> dict[str, Any]:
        eas = [s.envelope_a for s in self.sensors if s.envelope_a]
        ebs = [s.envelope_b for s in self.sensors if s.envelope_b]
        rest_a = [e.rest_len for e in eas]
        rest_b = [e.rest_len for e in ebs]
        p0_lens = [e.p0_len for e in eas]
        p0_raw = [len(e.p0_bytes) for e in eas if e.p0_bytes]
        arche = []
        for s in self.sensors:
            arche.append({"i": s.index, "archetypes": s.archetypes, "payload_keys": list(s.payload.keys())})

        # ofj rest vs payload size (proves fixed MAC)
        corr = []
        for s in self.sensors:
            jlen = len(json.dumps(s.payload, separators=(",", ":"), ensure_ascii=False))
            corr.append(
                {
                    "i": s.index,
                    "payload_json_len": jlen,
                    "rest_a": s.envelope_a.rest_len if s.envelope_a else None,
                    "rest_b": s.envelope_b.rest_len if s.envelope_b else None,
                }
            )

        return {
            "sensor_count": len(self.sensors),
            "named_count": len(self.named),
            "schema": self.sensors[0].schema if self.sensors else None,
            "envelope_a": {
                "count": len(eas),
                "versions": sorted({e.ver for e in eas}),
                "p0_lens": sorted(set(p0_lens)),
                "p0_raw_lens": sorted(set(p0_raw)),
                "rest_lens": sorted(set(rest_a)),
                "all_p0_unique": len({e.p0 for e in eas}) == len(eas),
                "ts_set": sorted({e.ts for e in eas}),
            },
            "envelope_b": {
                "count": len(ebs),
                "versions": sorted({e.ver for e in ebs}),
                "rest_lens": sorted(set(rest_b)),
                "rest_len_min": min(rest_b) if rest_b else None,
                "rest_len_max": max(rest_b) if rest_b else None,
                "all_p0_unique": len({e.p0 for e in ebs}) == len(ebs),
            },
            "rest_vs_payload": corr,
            "rest_b_independent_of_payload": (
                max(rest_b) - min(rest_b) < 100
                and max(c["payload_json_len"] for c in corr) > 1000
            )
            if rest_b and corr
            else None,
            "archetypes_by_index": arche,
            "core_map": CORE_MAP_CATALOG_TO_HYBRID,
            "conclusions": {
                "p0_is_32_bytes_b64url": set(p0_raw) == {32} if p0_raw else False,
                "envelope_b_fixed_size_mac": (
                    max(rest_b) - min(rest_b) < 120 if rest_b else False
                ),
                "index_order_is_async_not_fixed_slot": True,
                "payload_only_synth_insufficient": True,
            },
        }

    def structural_template(self) -> dict[str, Any]:
        """Redact session crypto; keep shape + relative timing."""
        out: dict[str, Any] = {
            "_meta": {
                "valid_for_post": False,
                "note": "envelopes redacted; payload structure kept",
            }
        }
        base = None
        for s in self.sensors:
            t0_key = "GqRg5" if s.schema == "catalog" else "kznA6"
            t1_key = "OwbxU6" if s.schema == "catalog" else "BEJV6"
            t0 = s.core.get(t0_key) or 0
            t1 = s.core.get(t1_key) or 0
            if base is None:
                base = t0
            red_payload = {}
            for k, v in s.payload.items():
                if isinstance(v, str) and ENVELOPE_RE.match(v):
                    red_payload[k] = f"<envelope len={len(v)}>"
                elif isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v):
                    red_payload[k] = "<hex64>"
                else:
                    red_payload[k] = v
            out[str(s.index)] = {
                "envelope_a": f"<p0-ts-{ENVELOPE_VER_A}-rest>",
                "envelope_b": f"<p0-ts-{ENVELOPE_VER_B}-rest_mac~506B>",
                "flag": 3,
                "status": "",
                "t0_rel_ms": t0 - base,
                "t1_rel_ms": t1 - base,
                "dt_ms": t1 - t0,
                "payload": red_payload,
                "archetypes": s.archetypes,
            }
        return out


def build_probe_sensors(
    *,
    mode: str = "catalog",
    n: int = SENSOR_COUNT,
    now_ms: Optional[int] = None,
    mac_rest_len: int = 683,
) -> dict[str, dict]:
    """
    Structurally valid, cryptographically invalid sensors.
    p0 = sha256-derived 32B (NOT CF algorithm) — for shape tests only.
    """
    now = int(now_ms if now_ms is not None else time.time() * 1000)
    ts = now // 1000
    out: dict[str, dict] = {}
    for i in range(1, n + 1):
        p0 = b64url_32(hashlib.sha256(f"probe-a-{i}-{ts}".encode()).digest())
        p0b = b64url_32(hashlib.sha256(f"probe-b-{i}-{ts}".encode()).digest())
        # fake fixed-size rest (not valid MAC)
        rest_a = base64.urlsafe_b64encode(
            hashlib.sha256(f"resta-{i}".encode()).digest() * 2
        ).decode().rstrip("=")[:86]
        rest_b = base64.urlsafe_b64encode(
            hashlib.sha512(f"restb-{i}".encode()).digest() * 8
        ).decode().rstrip("=")[:mac_rest_len]
        t0 = now + i * 3
        t1 = t0 + max(1, (i * 7) % 40)
        if mode == "hybrid":
            out[str(i)] = {
                "eXxSy3": format_envelope(p0, ts, ENVELOPE_VER_A, rest_a),
                "ofjO7": format_envelope(p0b, ts, ENVELOPE_VER_B, rest_b),
                "mlsbV4": 3,
                "Kerdl9": "",
                "kznA6": t0,
                "BEJV6": t1,
                "jxeDo4": t1 - t0,
            }
        else:
            out[str(i)] = {
                "XsAVh8": format_envelope(p0, ts, ENVELOPE_VER_A, rest_a),
                "qlAo5": p0,
                "oHTRn9": format_envelope(p0b, ts, ENVELOPE_VER_B, rest_b),
                "qPgf1": 3,
                "ucpv9": "",
                "GqRg5": t0,
                "OwbxU6": t1,
                "eOLK2": t1 - t0,
            }
    return out


def algo_status() -> dict:
    return {
        "sensor_count": SENSOR_COUNT,
        "envelope_ver_a": ENVELOPE_VER_A,
        "envelope_ver_b": ENVELOPE_VER_B,
        "p0_len": P0_LEN,
        "p0_raw_bytes": 32,
        "core_map_catalog_to_hybrid": CORE_MAP_CATALOG_TO_HYBRID,
        "payload_archetypes": PAYLOAD_ARCHETYPES,
        "token_formula": "1.2.1.1-{sensor[1].envelope_a.rest}",
        "o2_partial": {
            "token_is_sensor1_rest_a": True,
            "ofj_not_payload_ct": True,
            "ofj_not_raw_fc_hmac": True,
            "rch_versions_are_preseed_only": True,
            "mint_in_f5_vm_not_rch_html": True,
            "key_schedule_open": True,
        },
        "blocker": (
            "ofj rest MAC key schedule still open (not raw FC/gdr simple HMAC); "
            "mint is F5-VM side — need live join hook or opcode path"
        ),
        "open": [
            "O1 p0 mint",
            "O2 ofj MAC key schedule (F5/VM)",
            "O3 pure collectors",
            "O4 F5 assembly path",
        ],
        "module": "g.turnstile_sensor_algo",
    }


def _demo() -> dict:
    hy_p = ROOT / "logs" / "hybrid_fo2" / "20260723_130631" / "plains" / "02_fo2.json"
    cat_p = ROOT / "logs" / "fc_captures" / "20260721_175819" / "fo2_plain.json"
    out_dir = ROOT / "logs" / "pure_http_algo"
    out_dir.mkdir(parents=True, exist_ok=True)

    result: dict[str, Any] = {"status": algo_status()}
    if hy_p.exists():
        hy = json.loads(hy_p.read_text(encoding="utf-8"))
        an = SensorAlgo(hy)
        result["hybrid"] = an.analyze()
        (out_dir / "algo_hybrid_analyze.json").write_text(
            json.dumps(result["hybrid"], ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (out_dir / "algo_structural_template.json").write_text(
            json.dumps(an.structural_template(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    if cat_p.exists():
        cat = json.loads(cat_p.read_text(encoding="utf-8"))
        result["catalog"] = SensorAlgo(cat).analyze()
        (out_dir / "algo_catalog_analyze.json").write_text(
            json.dumps(result["catalog"], ensure_ascii=False, indent=2), encoding="utf-8"
        )

    probe = build_probe_sensors(mode="catalog")
    (out_dir / "algo_probe_sensors.json").write_text(
        json.dumps(probe, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # write recovered algorithm brief (json only — no md docs unless asked)
    brief = {
        "recovered": {
            "bag_core": CORE_MAP_CATALOG_TO_HYBRID,
            "envelope": "{p0:b64url32}-{ts}-{ver}-{rest}",
            "ver_a": ENVELOPE_VER_A,
            "ver_b": ENVELOPE_VER_B,
            "p0_raw_bytes": 32,
            "envelope_b_rest": "era-dependent session MAC/proof (hybrid raw~492-564; old~567-608)",
            "token": "1.2.1.1-{sensor[1].eXxSy3.rest}",
            "index_semantics": "async completion order, not fixed collector id",
            "flag_const": 3,
            "rch_preseed_envs": "full envelopes in _cf_chl_opt; not mint templates",
        },
        "disproved": {
            "p0_is_payload_hash": True,
            "ofj_rest_is_payload_ciphertext": True,
            "ofj_rest_hmac_raw_fc_gdr": True,
            "ofj_rest_xor_fc_window": True,
            "version_join_template_in_rch_html": True,
            "packer_in_FO1_SETPROP": True,
            "secondary_F5_in_fo1_resp": True,
        },
        "hybrid_conclusions": (result.get("hybrid") or {}).get("conclusions"),
        "o2_artifacts": [
            "logs/pure_http_algo/o2_mac_analysis.json",
            "logs/pure_http_algo/o2_mac_deep.json",
            "logs/pure_http_algo/o2_rch_hunt.json",
            "logs/pure_http_algo/o2_preseed.json",
        ],
        "next_reverse": [
            "O1: mint of 32B p0 (random vs HMAC(session, i||nonce))",
            "O2: ofj MAC key = FO1-VM derived (not raw FC); hook envelope join or F5 opcode",
            "O3: reimplement collectors for payload only (still need O1/O2 for POST)",
            "O4: FO1 F5 non-SETPROP assembly (Object.assign / host helper / array bulk)",
        ],
    }
    (out_dir / "algo_recovered.json").write_text(
        json.dumps(brief, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    result["brief"] = brief
    result["out"] = str(out_dir)
    return result


if __name__ == "__main__":
    print(json.dumps(_demo(), ensure_ascii=False, indent=2, default=str)[:8000])
