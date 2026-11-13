"""
Real CKKS (TenSEAL / Microsoft SEAL) privacy-preserving numeric engine.

Roles are separated so the privacy claim is meaningful:
  * CKKSKeyHolder      - owns the secret key; encrypts and decrypts. (gateway side)
  * CKKSComputeServer  - receives ONLY the public context (no secret key) and
                         serialized ciphertexts; evaluates SUM/SUB/AVG/MUL/PCT
                         homomorphically and returns ciphertext. It cannot decrypt.

Flow: numbers in a prompt are encrypted and replaced by tokens such as
[CKKS_NUM_ab12cd34_1]. The LLM never sees plaintext numbers; it may request a
calculation like CKKS_SUM([..._1], [..._2]). The compute server evaluates it on
ciphertexts and the key holder decrypts only the final result.

Reference: Cheon, Kim, Kim, Song, "Homomorphic Encryption for Arithmetic of
Approximate Numbers", ASIACRYPT 2017.
"""
import re
import time
import uuid
import logging
import threading
from typing import Dict, List, Optional, Tuple

import tenseal as ts

logger = logging.getLogger("securesphere.ckks")

SCHEME_LABEL = "CKKS (TenSEAL/SEAL, approximate HE)"
TOKEN_RE = re.compile(r"\[CKKS_NUM_([0-9a-f]{8})_(\d+)\]")
LOOSE_TOKEN_RE = re.compile(r"\[?CKKS_NUM_([0-9a-f]{8})_(\d+)\b\]?")
_ARG_TOKEN_RE = re.compile(r"[\s`'\"*\[(]*CKKS_NUM_([0-9a-f]{8})_(\d+)[\s`'\"*\])]*")
OP_RE = re.compile(r"\bCKKS_(SUM|SUB|AVG|MUL|PCT)\(([^()]*)\)")
_NUM_RE = re.compile(r"\d[\d,]*(?:\.\d+)?")
_CUR_RE = re.compile(r"[\$€£₹]|Rs\.?|USD|EUR|INR")

SESSION_TTL_SECONDS = 600
MAX_SESSIONS = 500


class CKKSKeyHolder:
    """Holds the secret key. Encrypts inputs, decrypts results."""

    def __init__(self, poly_modulus_degree: int = 8192, coeff_mod_bit_sizes=(58, 50, 50, 58), scale_bits: int = 50):
        self._ctx = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=poly_modulus_degree,
                               coeff_mod_bit_sizes=list(coeff_mod_bit_sizes))
        self._ctx.global_scale = 2 ** scale_bits

    def public_context_bytes(self) -> bytes:
        """Serialized context WITHOUT the secret key (what the compute server gets)."""
        return self._ctx.serialize(save_public_key=True, save_secret_key=False,
                                   save_galois_keys=False, save_relin_keys=True)

    def encrypt(self, value: float) -> bytes:
        return ts.ckks_vector(self._ctx, [float(value)]).serialize()

    def decrypt(self, ciphertext: bytes) -> float:
        return float(ts.ckks_vector_from(self._ctx, ciphertext).decrypt()[0])


class CKKSComputeServer:
    """Untrusted evaluator: public context only, so it can compute but never decrypt."""

    def __init__(self, public_context: bytes):
        self._ctx = ts.context_from(public_context)
        if self._ctx.has_secret_key():
            raise ValueError("CKKSComputeServer must not be given a secret key")

    def _load(self, ct: bytes):
        return ts.ckks_vector_from(self._ctx, ct)

    def evaluate(self, op: str, cts: List[bytes], consts: List[float]) -> bytes:
        op = op.upper()
        if op in ("SUM", "AVG", "SUB"):
            if not cts:
                raise ValueError(f"{op} needs encrypted arguments")
            vecs = [self._load(c) for c in cts]
            if op == "SUB":
                if len(vecs) != 2:
                    raise ValueError("SUB takes exactly two arguments")
                res = vecs[0] - vecs[1]
            else:
                res = vecs[0]
                for v in vecs[1:]:
                    res = res + v
                if op == "AVG":
                    res = res * (1.0 / len(vecs))
        elif op in ("MUL", "PCT"):
            if len(cts) != 1 or len(consts) != 1:
                raise ValueError(f"{op} takes one encrypted value and one plain constant")
            factor = consts[0] / 100.0 if op == "PCT" else consts[0]
            res = self._load(cts[0]) * factor
        else:
            raise ValueError(f"Unsupported operation {op}")
        return res.serialize()


def _parse_number(raw: str) -> Optional[Tuple[float, dict]]:
    m = _NUM_RE.search(raw)
    if not m:
        return None
    digits = m.group(0)
    try:
        value = float(digits.replace(",", ""))
    except ValueError:
        return None
    prefix, suffix = raw[:m.start()], raw[m.end():]
    cur = _CUR_RE.search(prefix)
    fmt = {
        "prefix": prefix, "suffix": suffix,
        "currency": cur.group(0) if cur else "",
        "commas": "," in digits,
        "decimals": len(digits.split(".")[1]) if "." in digits else 0,
    }
    return value, fmt


def _render(value: float, fmt: dict, use_affixes: bool) -> str:
    dec = fmt["decimals"] if use_affixes else (0 if abs(value - round(value)) < 0.005 else 2)
    value = round(value, dec)
    if dec == 0:
        value = int(round(value))
        body = f"{value:,}" if fmt["commas"] else str(value)
    else:
        body = f"{value:,.{dec}f}" if fmt["commas"] else f"{value:.{dec}f}"
    if use_affixes:
        return f"{fmt['prefix']}{body}{fmt['suffix']}"
    return f"{fmt['currency']}{body}"


class CKKSNumericEngine:
    """Gateway-facing API used by the PII pipeline."""

    def __init__(self):
        self._lock = threading.Lock()
        self._holder: Optional[CKKSKeyHolder] = None
        self._server: Optional[CKKSComputeServer] = None
        self._sessions: Dict[str, dict] = {}

    def _ensure(self):
        with self._lock:
            if self._holder is None:
                self._holder = CKKSKeyHolder()
                self._server = CKKSComputeServer(self._holder.public_context_bytes())
                logger.info("CKKS context initialised (poly_modulus_degree=8192).")

    def _prune(self):
        now = time.time()
        for rid in [r for r, s in self._sessions.items() if now - s["t"] > SESSION_TTL_SECONDS]:
            self._sessions.pop(rid, None)
        while len(self._sessions) > MAX_SESSIONS:
            self._sessions.pop(min(self._sessions, key=lambda r: self._sessions[r]["t"]), None)

    def new_session(self) -> str:
        self._ensure()
        rid = uuid.uuid4().hex[:8]
        with self._lock:
            self._prune()
            self._sessions[rid] = {"t": time.time(), "items": {}, "n": 0}
        return rid

    def encrypt_numeric(self, rid: str, raw: str) -> Optional[str]:
        """Encrypts the number found in `raw`; returns the placeholder token or None."""
        parsed = _parse_number(raw)
        if parsed is None:
            return None
        value, fmt = parsed
        sess = self._sessions[rid]
        sess["n"] += 1
        token = f"[CKKS_NUM_{rid}_{sess['n']}]"
        sess["items"][token] = {"ct": self._holder.encrypt(value), "fmt": fmt, "raw": raw}
        return token

    def last_token(self, rid: str) -> str:
        return f"[CKKS_NUM_{rid}_{self._sessions[rid]['n']}]"

    def has_tokens(self, text: str) -> bool:
        return bool(TOKEN_RE.search(text))

    def _lookup(self, token: str) -> Optional[dict]:
        m = _ARG_TOKEN_RE.fullmatch(token.strip())
        if not m:
            return None
        canonical = f"[CKKS_NUM_{m.group(1)}_{m.group(2)}]"
        sess = self._sessions.get(m.group(1))
        return sess["items"].get(canonical) if sess else None

    def _eval_expr(self, op: str, args_text: str) -> Optional[str]:
        args = [a.strip() for a in args_text.split(",") if a.strip()]
        items, consts = [], []
        for a in args:
            it = self._lookup(a)
            if it is not None:
                items.append(it)
                continue
            try:
                consts.append(float(a.replace("%", "")))
            except ValueError:
                return None  # unknown argument -> leave the text untouched
        if not items:
            return None
        try:
            out = self._server.evaluate(op, [i["ct"] for i in items], consts)
            return _render(self._holder.decrypt(out), items[0]["fmt"], use_affixes=False)
        except Exception as e:  # e.g. depth exceeded / bad arity
            logger.warning(f"CKKS evaluation of {op} failed: {e}")
            return None

    def restore(self, text: str) -> str:
        """Evaluates requested operations on ciphertexts, then decrypts remaining tokens."""
        if not self._holder or "CKKS_" not in text:
            return text
        text = OP_RE.sub(lambda m: self._eval_expr(m.group(1), m.group(2)) or m.group(0), text)

        def _bare(m):
            it = self._lookup(m.group(0))
            if it is None:
                return m.group(0)
            return _render(self._holder.decrypt(it["ct"]), it["fmt"], use_affixes=True)
        return LOOSE_TOKEN_RE.sub(_bare, text)


PROMPT_NOTE = (
    "\n\n[SecureSphere note: numbers above are encrypted placeholders; do not try to read or compute with them. "
    "To request a calculation, write CKKS_SUM(a, b), CKKS_SUB(a, b), CKKS_AVG(a, b), CKKS_MUL(a, constant) "
    "or CKKS_PCT(a, percent), using the placeholders exactly as written, including the square brackets, as the arguments. The gateway evaluates it on encrypted data.]"
)

ckks_engine = CKKSNumericEngine()
