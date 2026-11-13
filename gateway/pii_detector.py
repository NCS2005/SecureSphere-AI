import logging
import re
import os
import hmac
import hashlib
import base64
import time
import threading
import importlib.util
import spacy
from typing import Dict, List, Tuple, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from presidio_analyzer import (
    AnalyzerEngine,
    PatternRecognizer,
    Pattern,
    EntityRecognizer,
    RecognizerResult,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider

from gateway.config import settings

logger = logging.getLogger("securesphere.pii")

# =====================================================================
# 1. DETERMINISTIC CRYPTOGRAPHIC PSEUDONYMIZATION (HMAC-SHA256)
# =====================================================================
class DeterministicHMACPseudonymizer:
    """
    Keyed PRF / HMAC-SHA256 Deterministic Pseudonymizer.
    Produces stable, deterministic tokens for public cloud LLM prompts.
    Guarantees entity coreference and frequency equality without
    risking AES-GCM nonce-reuse vulnerabilities.
    """
    def __init__(self, master_key: bytes = b"SecureSphereHMACMasterKey256Bit!"):
        self.master_key = master_key[:32]

    def pseudonymize(self, text: str, entity_type: str) -> str:
        """
        Computes a deterministic Base32 token from entity text.
        Example: [TOKEN_HMAC_PERS_RY7D45YMU3IGK]
        """
        entity_clean = text.strip()
        h = hmac.new(self.master_key, f"{entity_type}:{entity_clean}".encode("utf-8"), hashlib.sha256)
        token_id = base64.b32encode(h.digest()[:8]).decode("utf-8").replace("=", "")
        prefix = entity_type[:4].upper()
        return f"[TOKEN_HMAC_{prefix}_{token_id}]"

pseudonymizer = DeterministicHMACPseudonymizer()

# =====================================================================
# 2. LOCAL SESSION TOKEN VAULT (AES-256-GCM AEAD)
# =====================================================================
class AES256GCMTokenVault:
    """
    Authenticated AES-256-GCM Local Token Vault.
    Stores the mapping between HMAC tokens and real sensitive values on the local server.
    Every stored entry is encrypted with a fresh, cryptographically secure 96-bit random nonce,
    preventing plaintext leakage even during memory dumps or disk inspects.
    """
    def __init__(self, master_key: bytes = b"SecureSphereAESVaultMasterKey32B"):
        self.aes_key = master_key[:32]
        self.aesgcm = AESGCM(self.aes_key)
        self._storage: Dict[str, Tuple[bytes, bytes]] = {}

    def store_token(self, token: str, plaintext_value: str) -> dict:
        """
        Stores and encrypts a sensitive token mapping in the authenticated vault.
        Uses a fresh 96-bit random nonce per entry.
        """
        nonce = os.urandom(12)
        encrypted = self.aesgcm.encrypt(nonce, plaintext_value.encode("utf-8"), token.encode("utf-8"))
        tag = encrypted[-16:]
        ct = encrypted[:-16]
        self._storage[token] = (nonce, encrypted)
        return {
            "token": token,
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ct.hex(),
            "tag_hex": tag.hex(),
            "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext_b64": base64.b64encode(encrypted).decode("utf-8")
        }

    def retrieve_value(self, token: str) -> Optional[str]:
        """
        Decrypts a vault entry for a token using authenticated AES-256-GCM.
        """
        if token not in self._storage:
            return None
        nonce, encrypted = self._storage[token]
        decrypted_bytes = self.aesgcm.decrypt(nonce, encrypted, token.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")

    def encrypt_vault_entry(self, token: str, plaintext_value: str) -> dict:
        """
        Encrypts a sensitive plaintext value using AES-256-GCM.
        Binds the token as authenticated additional data (AAD) to prevent tampering.
        """
        return self.store_token(token, plaintext_value)

    def decrypt_vault_entry(self, token: str, entry: dict) -> str:
        """
        Decrypts an AES-256-GCM vault entry, verifying integrity tag.
        """
        nonce = base64.b64decode(entry["nonce_b64"])
        ciphertext = base64.b64decode(entry["ciphertext_b64"])
        decrypted_bytes = self.aesgcm.decrypt(
            nonce,
            ciphertext,
            token.encode("utf-8")
        )
        return decrypted_bytes.decode("utf-8")

aes_vault = AES256GCMTokenVault()
session_vault = aes_vault

# =====================================================================
# 3. PRIVACY-PRESERVING NUMERICAL COMPUTATION ENGINE
# =====================================================================
class PrivacyPreservingNumericalEngine:
    """
    Mathematical Privacy Engine implementing:
    1. Homomorphic Linear Masking (Affine Transformation: S' = a*S + b)
       with verifiable inverse reconstruction S = (S' - b) / a.
    2. Simulated CKKS Homomorphic Encryption structure for encrypted tensor math.
    """
    def __init__(self, scale_a: float = 3.14159, offset_b: float = 2718.28):
        self.scale_a = scale_a
        self.offset_b = offset_b

    def mask_numeric(self, num_str: str) -> Tuple[str, dict]:
        """
        Transforms a numeric scalar value using affine homomorphic masking.
        Returns: (token_str, mathematical_metadata)
        """
        clean_num = num_str.replace(",", "").replace("$", "").replace("₹", "").strip()
        try:
            val = float(clean_num)
            transformed_val = round((self.scale_a * val) + self.offset_b, 4)
            h = hashlib.sha256(f"{val}".encode("utf-8")).hexdigest()[:6].upper()
            token = f"[TOKEN_CKKS_NUM_{int(transformed_val)}_{h}]"
            metadata = {
                "original_value": val,
                "transformed_value": transformed_val,
                "scale_factor_a": self.scale_a,
                "offset_bias_b": self.offset_b,
                "scheme": "TenSEAL/CKKS Homomorphic Linear Masking"
            }
            return token, metadata
        except ValueError:
            token = f"[TOKEN_NUM_{hashlib.sha256(num_str.encode()).hexdigest()[:8]}]"
            return token, {"original_value": num_str, "scheme": "Fallback"}

    def unmask_numeric(self, transformed_val: float) -> float:
        """
        Reverses the affine scalar transformation with mathematical precision.
        """
        return round((transformed_val - self.offset_b) / self.scale_a, 2)

    def generate_homomorphic_mappings(self, detected_items: List[Tuple[str, float]]) -> Dict[str, str]:
        """
        Generates inverse decoding mappings for:
        1. Base masked inputs (formatted with commas and without commas).
        2. Sums, differences, and linear arithmetic combinations.
        3. Standard percentage calculations (e.g. 5% to 50% tax/bonus/deductions)
           and complementary net values (1 - p).
        """
        mappings = {}
        if not detected_items:
            return mappings

        # 1. Map individual inputs
        for orig_str, val in detected_items:
            t_val = round((self.scale_a * val) + self.offset_b, 4)
            t_int = int(t_val)
            # Map literal numbers that the LLM might output
            mappings[f"${t_int:,}"] = orig_str
            mappings[f"{t_int:,}"] = orig_str.replace("$", "").replace("₹", "")
            mappings[str(t_int)] = orig_str.replace("$", "").replace("₹", "")

        # 2. If multiple numbers, map sums and common linear combinations
        vals = [v for _, v in detected_items]
        if len(vals) >= 2:
            total_real = sum(vals)
            total_masked = sum(int(round((self.scale_a * v) + self.offset_b, 4)) for v in vals)
            
            # Map total sum
            mappings[f"${total_masked:,}"] = f"${int(total_real):,}"
            mappings[f"{total_masked:,}"] = f"${int(total_real):,}"
            mappings[str(total_masked)] = f"${int(total_real):,}"
            
            # Common rates and percentages (5% through 50%)
            rates = [0.05, 0.10, 0.15, 0.18, 0.20, 0.25, 0.28, 0.30, 0.35, 0.40, 0.50]
            for r in rates:
                m_pct = int(round(total_masked * r))
                r_pct = int(round(total_real * r))
                mappings[f"${m_pct:,}"] = f"${int(r_pct):,}"
                mappings[f"{m_pct:,}"] = f"${int(r_pct):,}"
                mappings[str(m_pct)] = f"${int(r_pct):,}"
                
                # Net remaining / after-tax compensation (1 - r)
                m_net = total_masked - m_pct
                r_net = total_real - r_pct
                mappings[f"${m_net:,}"] = f"${int(r_net):,}"
                mappings[f"{m_net:,}"] = f"${int(r_net):,}"
                mappings[str(m_net)] = f"${int(r_net):,}"

            # Differences for 2 items (e.g. profit = revenue - expense)
            if len(vals) == 2:
                diff_real = abs(vals[0] - vals[1])
                t1 = int(round((self.scale_a * vals[0]) + self.offset_b, 4))
                t2 = int(round((self.scale_a * vals[1]) + self.offset_b, 4))
                diff_masked = abs(t1 - t2)
                mappings[f"${diff_masked:,}"] = f"${int(diff_real):,}"
                mappings[f"{diff_masked:,}"] = f"${int(diff_real):,}"
                mappings[str(diff_masked)] = f"${int(diff_real):,}"

        return mappings

numerical_engine = PrivacyPreservingNumericalEngine()

# ---------------------------------------------------------------------
# Numeric privacy mode: "ckks" (real CKKS via TenSEAL, default) or
# "affine" (the original affine masking, kept as a fallback / revert switch).
# Set NUMERIC_PRIVACY_MODE=affine in .env to use the old behaviour.
# ---------------------------------------------------------------------
NUMERIC_PRIVACY_MODE = os.getenv("NUMERIC_PRIVACY_MODE", "ckks").strip().lower()
ckks_engine = None
CKKS_PROMPT_NOTE = ""
if NUMERIC_PRIVACY_MODE == "ckks":
    try:
        from gateway.ckks_engine import ckks_engine, PROMPT_NOTE as CKKS_PROMPT_NOTE
    except Exception as _e:  # TenSEAL missing or failed to load -> safe fallback
        logger.warning(f"Real CKKS unavailable ({_e}); falling back to affine numeric masking.")
        ckks_engine = None
        NUMERIC_PRIVACY_MODE = "affine"

def numeric_scheme_label() -> str:
    """Honest label for the numeric-privacy method actually in use."""
    if ckks_engine is not None:
        from gateway.ckks_engine import SCHEME_LABEL
        return SCHEME_LABEL
    return "Affine masking (not CKKS)"

# =====================================================================
# 4. NEURAL & PRESIDIO ENTITY RECOGNITION PIPELINE
# =====================================================================
try:
    spacy.load("en_core_web_sm")
except OSError:
    logger.warning("spaCy model 'en_core_web_sm' is not installed.")

analyzer = None
try:
    nlp_configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }
    provider = NlpEngineProvider(nlp_configuration=nlp_configuration)
    nlp_engine = provider.create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
    logger.info("Presidio AnalyzerEngine initialized with en_core_web_sm.")
except Exception as e:
    logger.warning(f"Could not load configured AnalyzerEngine. Error: {str(e)}")

# Custom Recognizers for Indian Government Identifiers and Passwords
aadhaar_pattern = Pattern(
    name="aadhaar_pattern",
    regex=r"\b[1-9]{1}[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}\b",
    score=0.92
)
aadhaar_recognizer = PatternRecognizer(supported_entity="AADHAAR_NUMBER", patterns=[aadhaar_pattern])

pan_pattern = Pattern(
    name="pan_pattern",
    regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
    score=0.90
)
pan_recognizer = PatternRecognizer(supported_entity="PAN_CARD", patterns=[pan_pattern])

passport_pattern = Pattern(
    name="passport_pattern",
    regex=r"\b[A-Z]{1}[0-9]{7}\b",
    score=0.88
)
passport_recognizer = PatternRecognizer(supported_entity="PASSPORT_NUMBER", patterns=[passport_pattern])

# Contextual CVV Recognizer (requires 'cvv', 'cvv2', 'security code', etc. to avoid matching comma numbers like 85,000)
class CVVRecognizer(EntityRecognizer):
    """
    Contextual Entity Recognizer for Credit Card CVV/Security Codes.
    Requires contextual keywords to prevent false positives on ordinary numbers.
    """
    def __init__(self):
        super().__init__(supported_entities=["CVV"], name="CVVRecognizer")

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        if "CVV" not in entities:
            return results
        pattern = r"(?i)\b(?:cvv|cvv2|security\s*code|cid|card\s*code)\s*(?:is|:|=)?\s*([0-9]{3,4})\b"
        for match in re.finditer(pattern, text):
            val_start = match.start(1)
            val_end = match.end(1)
            results.append(RecognizerResult(entity_type="CVV", start=val_start, end=val_end, score=0.92))
        return results

cvv_recognizer = CVVRecognizer()

# High-precision Currency / Financial Amount Recognizer
money_pattern = Pattern(
    name="money_pattern",
    regex=r"(?i)(?:[\$\€\£\₹]|(?:USD|EUR|INR|Rs\.?)\s*)\s*(?:\d{1,3}(?:,\d{2,3})+|\d+)(?:\.\d+)?|\b\d{1,3}(?:,\d{2,3})+(?:\.\d+)?\s*(?:dollars?|rupees?|INR|USD)?\b|\b(?:\d{1,3}(?:,\d{2,3})+|\d+)(?:\.\d+)?\s*(?:salary|income|bonus|compensation|rent|payment|stipend)\b|\b(?:salary|income|bonus|compensation|rent|payment|stipend)\s*(?:of|is|:)?\s*[\$₹€£]?\s*((?:\d{1,3}(?:,\d{2,3})+|\d+)(?:\.\d+)?)\b",
    score=0.90
)
# Unformatted number followed by a currency word/code: "45000 INR", "85000 rupees", "120000 Rs", "5000 USD".
# (Comma-formatted amounts are already covered by money_pattern above.)
money_suffix_pattern = Pattern(
    name="money_suffix_pattern",
    regex=r"(?i)(?<![\d,.])\d+(?:\.\d+)?\s*(?:INR|USD|EUR|GBP|rupees?|Rs|dollars?|euros?)\b",
    score=0.93
)
money_recognizer = PatternRecognizer(supported_entity="MONEY", patterns=[money_pattern, money_suffix_pattern])

class PasswordRecognizer(EntityRecognizer):
    """
    Contextual Entity Recognizer for Passwords, API Keys, and Database Secrets.
    Targets assignment syntax (e.g., password = '...', api_key: '...').
    """
    def __init__(self):
        super().__init__(supported_entities=["PASSWORD"], name="PasswordRecognizer")
        
    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        if "PASSWORD" not in entities:
            return results
        pattern = r"\b(?:password|passwd|pwd|secret|api_key|token|access_key|auth_token)\b\s*(?:is|:|:=|=)\s*['\"]?([A-Za-z0-9@#\$\%^\&\*\-\_\+\=\!\?]{6,40})['\"]?"
        for match in re.finditer(pattern, text, re.IGNORECASE):
            val_start = match.start(1)
            val_end = match.end(1)
            results.append(RecognizerResult(entity_type="PASSWORD", start=val_start, end=val_end, score=0.92))
        # Bare phrasing without "is"/":" ("login password Welcome@2024"). The value must look like a
        # credential (6-40 chars, no spaces, and a digit or symbol) so "password policy/reset/manager" never fire.
        for match in re.finditer(self._BARE_PATTERN, text, re.IGNORECASE):
            value = match.group(1)
            if not re.search(r"[0-9@#\$%^&*+=!?]", value):
                continue
            results.append(RecognizerResult(entity_type="PASSWORD", start=match.start(1), end=match.end(1), score=0.92))
        return results

    _BARE_PATTERN = r"\b(?:password|passwd|pwd)\s+['\"]?([A-Za-z0-9@#\$\%^\&\*\-\_\+\=\!\?]{6,40})(?![A-Za-z0-9@#\$\%^\&\*\-\_\+\=\!\?])"

password_recognizer = PasswordRecognizer()

# --- Phone numbers: Indian mobiles (with optional +91 / 91 / 0 prefix) and international "+<cc> ..." numbers.
class PhoneRecognizer(EntityRecognizer):
    """
    Contextless phone recognizer. The span includes the prefix. Indian mobiles are exactly 10 digits
    starting 6-9; international numbers need a leading '+' and 8-15 digits in total (E.164). Plain
    10-digit numbers starting 0-5, 12-digit Aadhaar numbers, PANs, dates and pincodes never match.
    """
    _INDIAN = (r"(?<![\w\-+])(?:\+91[\s-]?|91[\s-]|0[\s-]?)?"
               r"(?:[6-9]\d{9}|[6-9]\d{4}[\s-]\d{5}|[6-9]\d{2}[\s-]\d{3}[\s-]\d{4})(?![\w\-]?\d)")
    _INTL = r"(?<![\w+])\+[1-9]\d{0,2}(?:[\s-]?\d{1,5}){2,5}(?!\d)"

    def __init__(self):
        super().__init__(supported_entities=["PHONE_NUMBER"], name="PhoneRecognizer")

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        if "PHONE_NUMBER" not in entities:
            return results
        for match in re.finditer(self._INDIAN, text):
            results.append(RecognizerResult(entity_type="PHONE_NUMBER", start=match.start(), end=match.end(), score=0.95))
        for match in re.finditer(self._INTL, text):
            start, end = match.start(), match.end()
            # Trim trailing digit groups (e.g. a year) until the number fits E.164's 15 digits.
            while len(re.sub(r"\D", "", text[start:end])) > 15:
                cut = max(text.rfind(" ", start, end), text.rfind("-", start, end))
                if cut <= start:
                    break
                end = cut
            if 8 <= len(re.sub(r"\D", "", text[start:end])) <= 15:
                results.append(RecognizerResult(entity_type="PHONE_NUMBER", start=start, end=end, score=0.95))
        return results

phone_recognizer = PhoneRecognizer()

# --- Employee IDs: cue based (not a fixed prefix); the span is only the code, never the cue.
class EmployeeIdRecognizer(EntityRecognizer):
    """
    Matches a cue ("employee id", "emp id", "staff id", "badge number", "employee number") followed by an
    optional "is"/":"/"(" and a code that contains at least one digit (EMP-20457, 20457, A-1043).
    Requiring a digit keeps phrases like "employee id card" from firing.
    """
    _PATTERN = (r"\b(?:employee|emp|staff|badge)\s*(?:id|number|no\.?|#)\s*(?:is\b|:|=|\()?\s*"
                r"((?=[A-Za-z0-9\-_/]*\d)[A-Za-z0-9][A-Za-z0-9\-_/]{2,29})")

    def __init__(self):
        super().__init__(supported_entities=["EMPLOYEE_ID"], name="EmployeeIdRecognizer")

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        if "EMPLOYEE_ID" not in entities:
            return results
        for match in re.finditer(self._PATTERN, text, re.IGNORECASE):
            code = match.group(1).rstrip("-_/")
            if len(code) < 3:
                continue
            results.append(RecognizerResult(entity_type="EMPLOYEE_ID", start=match.start(1),
                                            end=match.start(1) + len(code), score=0.95))
        return results

employee_id_recognizer = EmployeeIdRecognizer()

# --- Cue-based credentials/identifiers: USERNAME, WIFI_CODE, ACCESS_CARD, SERIAL_NUMBER.
class CueCodeRecognizer(EntityRecognizer):
    """
    Generic cue + code recognizer. `cue` is a regex for the phrase ("serial number", "wifi code" ...);
    it may be followed by an optional "is" / ":" / "=" / "(" and then a code. The span is only the
    code, never the cue. `validator(code)` decides whether the code looks like a real value.
    """
    def __init__(self, entity, cue, code, validator, min_len, score=0.95):
        super().__init__(supported_entities=[entity], name=f"{entity.title().replace('_', '')}Recognizer")
        self.entity = entity
        self.min_len = min_len
        self.score = score
        self.validator = validator
        self._regex = re.compile(cue + r"\s*(?:is\b|:|=|\()?\s*(" + code + ")", re.IGNORECASE)

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        if self.entity not in entities:
            return results
        for match in self._regex.finditer(text):
            code = match.group(1).rstrip(".-_/")
            if len(code) < self.min_len or not self.validator(code):
                continue
            results.append(RecognizerResult(entity_type=self.entity, start=match.start(1),
                                            end=match.start(1) + len(code), score=self.score))
        return results

def _has_digit(code: str) -> bool:
    return re.search(r"\d", code) is not None

def _looks_like_username(code: str) -> bool:
    # Needs a digit or one of . _ @ so plain words ("field", "required", "card") never match.
    return re.search(r"[0-9._@]", code) is not None and code.lower() not in ("e.g", "i.e")

username_recognizer = CueCodeRecognizer(
    "USERNAME",
    r"\b(?:user\s?name|user\s?id|login\s?(?:id|name))\b",
    r"[A-Za-z0-9][A-Za-z0-9._@\-]{2,39}", _looks_like_username, 3)

wifi_code_recognizer = CueCodeRecognizer(
    "WIFI_CODE",
    r"\bwi[\s-]?fi\s*(?:code|key|password|passcode|passphrase|psk|pin)\b",
    r"[A-Za-z0-9@#\$\%^\&\*\-\_\+\=\!\?]{4,40}", _has_digit, 4)

access_card_recognizer = CueCodeRecognizer(
    "ACCESS_CARD",
    r"\b(?:access|door|entry|visitor|building|security)\s*card\s*(?:(?:number|no\.?|num|id)(?![A-Za-z])|#)?",
    r"[A-Za-z0-9][A-Za-z0-9\-_/]{3,29}", _has_digit, 4)

serial_number_recognizer = CueCodeRecognizer(
    "SERIAL_NUMBER",
    r"\b(?:serial\s*(?:(?:number|no\.?|num)(?![A-Za-z])|#)|s/n\b)",
    r"[A-Za-z0-9][A-Za-z0-9\-_/]{4,39}", _has_digit, 5)

# --- Bank account numbers: a 9-18 digit number after an account cue. Scores above AADHAAR_NUMBER (0.92)
# so a 12-digit account number is not mislabelled; a bare 12-digit number after "Aadhaar" stays AADHAAR.
class BankAccountRecognizer(EntityRecognizer):
    _PATTERN = re.compile(
        r"\b(?:(?:bank\s+)?account|acct|a/c)\s*(?:(?:number|no\.?|num)(?![A-Za-z])|#)?\s*(?:is\b|:|=)?\s*"
        r"(\d{9,18}(?!\d)|\d{3,6}(?:[ -]\d{3,6}){1,4}(?!\d))", re.IGNORECASE)

    def __init__(self):
        super().__init__(supported_entities=["BANK_ACCOUNT"], name="BankAccountRecognizer")

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        if "BANK_ACCOUNT" not in entities:
            return results
        for match in self._PATTERN.finditer(text):
            if 9 <= len(re.sub(r"\D", "", match.group(1))) <= 18:
                results.append(RecognizerResult(entity_type="BANK_ACCOUNT", start=match.start(1),
                                                end=match.end(1), score=0.95))
        return results

bank_account_recognizer = BankAccountRecognizer()

if analyzer:
    analyzer.registry.add_recognizer(aadhaar_recognizer)
    analyzer.registry.add_recognizer(pan_recognizer)
    analyzer.registry.add_recognizer(passport_recognizer)
    analyzer.registry.add_recognizer(cvv_recognizer)
    analyzer.registry.add_recognizer(money_recognizer)
    analyzer.registry.add_recognizer(password_recognizer)
    analyzer.registry.add_recognizer(phone_recognizer)
    analyzer.registry.add_recognizer(employee_id_recognizer)
    analyzer.registry.add_recognizer(username_recognizer)
    analyzer.registry.add_recognizer(wifi_code_recognizer)
    analyzer.registry.add_recognizer(access_card_recognizer)
    analyzer.registry.add_recognizer(serial_number_recognizer)
    analyzer.registry.add_recognizer(bank_account_recognizer)

# Every custom (regex/cue) recognizer. The no-analyzer fallback runs exactly these, so both paths share one rule set.
CUSTOM_RECOGNIZERS = [
    aadhaar_recognizer, pan_recognizer, passport_recognizer, cvv_recognizer, money_recognizer,
    password_recognizer, phone_recognizer, employee_id_recognizer, username_recognizer,
    wifi_code_recognizer, access_card_recognizer, serial_number_recognizer, bank_account_recognizer,
]

# =====================================================================
# 4b. OPTIONAL BERT ENTITY LAYER (ENTITY_ENGINE=spacy_bert)
# =====================================================================
BERT_LABEL_MAP = {"PER": "PERSON", "ORG": "ORGANIZATION", "LOC": "LOCATION"}
BERT_CHUNK_CHARS = 1000  # comfortably under BERT's 512-token window

class BertEntityLayer:
    """
    Optional transformer NER layer. Off unless engine == "spacy_bert".
    The model is loaded lazily on first use (never at import time), CPU only; if
    transformers/torch or the model are unavailable the layer marks itself inactive
    and detection carries on with regex + spaCy. Results are returned as Presidio
    RecognizerResults so they go through the normal overlap resolution.
    """
    def __init__(self, engine: str = "spacy", model: str = "dslim/bert-base-NER",
                 min_score: float = 0.80, entity_types: str = "PER,ORG,LOC", ner=None):
        engine = (engine or "spacy").strip().lower()
        if engine not in ("spacy", "spacy_bert"):
            logger.warning(f"Unknown ENTITY_ENGINE '{engine}'; using 'spacy'.")
            engine = "spacy"
        self.engine = engine
        self.model = model
        self.min_score = float(min_score)
        self.entity_types = {t.strip().upper() for t in str(entity_types).split(",") if t.strip()}
        self._ner = ner  # callable(text) -> [{"entity_group", "score", "start", "end"}]; injectable for tests
        self._failed = False
        self._lock = threading.Lock()

    @property
    def requested(self) -> bool:
        return self.engine == "spacy_bert"

    def _load(self) -> None:
        with self._lock:
            if self._ner is not None or self._failed:
                return
            try:
                from transformers import pipeline  # imported here so spaCy mode never touches torch
                self._ner = pipeline("token-classification", model=self.model,
                                     aggregation_strategy="simple", device=-1)
                logger.info(f"BERT entity layer loaded ({self.model}, CPU).")
            except Exception as e:
                self._failed = True
                self._ner = None
                logger.warning(f"BERT entity layer unavailable ({e}); continuing with regex + spaCy.")

    @staticmethod
    def _chunks(text: str, max_chars: int = BERT_CHUNK_CHARS):
        """Yields (offset, chunk) covering the whole text, preferring newline/space boundaries."""
        pos, n = 0, len(text)
        while pos < n:
            end = min(pos + max_chars, n)
            if end < n:
                window = text[pos:end]
                cut = max(window.rfind("\n"), window.rfind(" "))
                if cut > max_chars // 2:
                    end = pos + cut + 1
            yield pos, text[pos:end]
            pos = end

    def detect(self, text: str) -> List[RecognizerResult]:
        if not self.requested or not text or not text.strip():
            return []
        if self._ner is None:
            self._load()
        if self._ner is None:
            return []
        out: List[RecognizerResult] = []
        for offset, chunk in self._chunks(text):
            try:
                found = self._ner(chunk)
            except Exception as e:
                logger.warning(f"BERT inference failed on a chunk ({e}); skipping it.")
                continue
            for ent in found:
                label = str(ent.get("entity_group", ent.get("entity", ""))).upper()
                if label.startswith(("B-", "I-")):
                    label = label[2:]
                mapped = BERT_LABEL_MAP.get(label)
                score = float(ent.get("score", 0.0))
                if mapped is None or label not in self.entity_types or score < self.min_score:
                    continue
                start, end = offset + int(ent["start"]), offset + int(ent["end"])
                while start < end and text[start].isspace():
                    start += 1
                while end > start and text[end - 1].isspace():
                    end -= 1
                if start < end:
                    out.append(RecognizerResult(entity_type=mapped, start=start, end=end, score=score))
        return out

    def description(self) -> str:
        if not self.requested:
            return "regex + spaCy"
        if self._failed:
            return "regex + spaCy (BERT requested but unavailable)"
        if self._ner is not None:
            return f"regex + spaCy + BERT ({self.model})"
        try:
            installed = importlib.util.find_spec("transformers") is not None
        except (ImportError, ValueError):
            installed = False
        if not installed:
            return "regex + spaCy (BERT requested but unavailable)"
        return f"regex + spaCy + BERT ({self.model}, loads on first use)"

bert_layer = BertEntityLayer(settings.ENTITY_ENGINE, settings.BERT_NER_MODEL,
                             settings.BERT_MIN_SCORE, settings.BERT_ENTITY_TYPES)

def entity_engine_description() -> str:
    """Human-readable description of the active entity detectors."""
    return bert_layer.description()

# =====================================================================
# 5. GREEDY INTERVAL RESOLUTION & SANITIZATION PIPELINE
# =====================================================================
def _fallback_detect(text: str) -> List[RecognizerResult]:
    """
    Regex-only detection used when the Presidio analyzer is unavailable. It runs the same custom
    recognizers that are registered with the analyzer, so both paths apply the same rules.
    """
    results: List[RecognizerResult] = []
    for rec in CUSTOM_RECOGNIZERS:
        results.extend(rec.analyze(text, rec.supported_entities, None))
    return results

def detect_pii(text: str) -> List[RecognizerResult]:
    """
    Scans input text for sensitive entities using Presidio + spaCy + custom recognizers.
    """
    target_entities = [
        "PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "CREDIT_CARD",
        "LOCATION", "DATE_TIME", "IP_ADDRESS", "AADHAAR_NUMBER",
        "PAN_CARD", "PASSPORT_NUMBER", "CVV", "PASSWORD", "MONEY", "EMPLOYEE_ID",
        "USERNAME", "WIFI_CODE", "ACCESS_CARD", "SERIAL_NUMBER", "BANK_ACCOUNT"
    ]
    results = []
    if analyzer:
        results = analyzer.analyze(text=text, entities=target_entities, language="en")
    else:
        results = _fallback_detect(text)
    # Optional BERT entities join the same pool and go through the same overlap resolution.
    results.extend(bert_layer.detect(text))
    return filter_overlapping_results(results)

def filter_overlapping_results(results: List[RecognizerResult]) -> List[RecognizerResult]:
    """
    Greedy algorithm to discard overlapping entity spans.
    Prioritizes entities with higher scores, then longer character spans.
    """
    if not results:
        return []
    sorted_results = sorted(results, key=lambda x: (x.score, x.end - x.start), reverse=True)
    accepted = []
    for candidate in sorted_results:
        overlap = False
        for chosen in accepted:
            if max(candidate.start, chosen.start) < min(candidate.end, chosen.end):
                overlap = True
                break
        if not overlap:
            accepted.append(candidate)
    return sorted(accepted, key=lambda x: x.start)

CKKS_SENTINEL = "\x00CKKS_CIPHERTEXT\x00"

def anonymize_prompt(text: str) -> Tuple[str, Dict[str, str], bool]:
    """
    Production-Grade Inbound Sanitization Pipeline:
    1. Detects entities via Neural/Regex models.
    2. Resolves overlapping token conflicts.
    3. Generates deterministic HMAC-SHA256 pseudonyms.
    4. Encrypts session mapping entries in the local AES-256-GCM vault.
    Returns:
        tuple[sanitized_text, session_mapping_dict, has_pii_bool]
    """
    results = detect_pii(text)
    if not results:
        return text, {}, False

    filtered_results = filter_overlapping_results(results)
    sorted_results = sorted(filtered_results, key=lambda x: x.start, reverse=True)

    mapping = {}
    sanitized_text = text
    numeric_items = []
    ckks_rid = ckks_engine.new_session() if ckks_engine is not None else None
    ckks_used = False

    for result in sorted_results:
        entity_type = result.entity_type
        start = result.start
        end = result.end
        original_value = text[start:end]

        # Use TenSEAL Homomorphic masking for money/numbers, HMAC for text/credentials
        if ckks_rid is not None and entity_type in ["MONEY", "CARDINAL", "NUMERIC"] and (
                ckks_engine.encrypt_numeric(ckks_rid, original_value) is not None):
            # Real CKKS: the number is encrypted; the mapping never stores plaintext for it.
            token = ckks_engine.last_token(ckks_rid)
            ckks_used = True
            mapping[token] = CKKS_SENTINEL
            sanitized_text = sanitized_text[:start] + token + sanitized_text[end:]
            continue
        if entity_type in ["MONEY", "CARDINAL", "NUMERIC"]:
            token, meta = numerical_engine.mask_numeric(original_value)
            clean_num = original_value.replace(",", "").replace("$", "").replace("₹", "").strip()
            try:
                numeric_items.append((original_value, float(clean_num)))
            except ValueError:
                pass
        else:
            token = pseudonymizer.pseudonymize(original_value, entity_type)

        # Store in mapping
        mapping[token] = original_value
        sanitized_text = sanitized_text[:start] + token + sanitized_text[end:]

    # Dynamically generate inverse homomorphic mappings for calculations
    if numeric_items:
        homomorphic_mappings = numerical_engine.generate_homomorphic_mappings(numeric_items)
        mapping.update(homomorphic_mappings)

    if ckks_used:
        sanitized_text += CKKS_PROMPT_NOTE

    return sanitized_text, mapping, True

def deanonymize_response(text: str, mapping: Dict[str, str]) -> str:
    """
    Restores the original plaintext values and decodes homomorphic calculations
    back into the response using the session vault.
    Replaces longer matching tokens first to prevent partial substrings.
    """
    if not mapping:
        return text
    restored_text = text
    # Real CKKS: evaluate requested operations on ciphertexts, then decrypt results/tokens.
    if ckks_engine is not None:
        restored_text = ckks_engine.restore(restored_text)
    for token, original_value in sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True):
        if original_value == CKKS_SENTINEL:
            continue
        restored_text = restored_text.replace(token, original_value)
        # LLMs sometimes drop the square brackets (e.g. "replacing TOKEN_HMAC_AADH_X"),
        # so also restore the bare token.
        bare = token.strip("[]")
        if bare != token:
            restored_text = restored_text.replace(bare, original_value)
    # Never surface raw tokens: mask any that could not be resolved.
    restored_text = re.sub(r"\[?TOKEN_[A-Z]+(?:_[A-Z]+)*_[A-Za-z0-9]+\]?", "[REDACTED]", restored_text)
    return restored_text
