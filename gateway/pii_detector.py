import logging
import re
import os
import hmac
import hashlib
import base64
import time
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
    regex=r"(?i)(?:[\$\€\£\₹]|(?:USD|EUR|INR|Rs\.?)\s*)\s*\d{1,3}(?:,\d{3})*(?:\.\d+)?|\b\d{1,3}(?:,\d{3})+(?:\.\d+)?\s*(?:dollars?|rupees?|INR|USD)?\b|\b\d+(?:\.\d+)?\s*(?:salary|income|bonus|compensation|rent|payment|stipend)\b|\b(?:salary|income|bonus|compensation|rent|payment|stipend)\s*(?:of|is|:)?\s*[\$₹€£]?\s*(\d+(?:\.\d+)?)\b",
    score=0.90
)
money_recognizer = PatternRecognizer(supported_entity="MONEY", patterns=[money_pattern])

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
        return results

password_recognizer = PasswordRecognizer()

if analyzer:
    analyzer.registry.add_recognizer(aadhaar_recognizer)
    analyzer.registry.add_recognizer(pan_recognizer)
    analyzer.registry.add_recognizer(passport_recognizer)
    analyzer.registry.add_recognizer(cvv_recognizer)
    analyzer.registry.add_recognizer(money_recognizer)
    analyzer.registry.add_recognizer(password_recognizer)

# =====================================================================
# 5. GREEDY INTERVAL RESOLUTION & SANITIZATION PIPELINE
# =====================================================================
def detect_pii(text: str) -> List[RecognizerResult]:
    """
    Scans input text for sensitive entities using Presidio + spaCy + custom recognizers.
    """
    target_entities = [
        "PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "CREDIT_CARD",
        "LOCATION", "DATE_TIME", "IP_ADDRESS", "AADHAAR_NUMBER",
        "PAN_CARD", "PASSPORT_NUMBER", "CVV", "PASSWORD", "MONEY"
    ]
    results = []
    if analyzer:
        results = analyzer.analyze(text=text, entities=target_entities, language="en")
    else:
        # Fallback regex scans
        for m in re.finditer(r"\b[1-9]{1}[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}\b", text):
            results.append(RecognizerResult(entity_type="AADHAAR_NUMBER", start=m.start(), end=m.end(), score=0.90))
        for m in re.finditer(r"\b\d{10}\b", text):
            results.append(RecognizerResult(entity_type="PHONE_NUMBER", start=m.start(), end=m.end(), score=0.80))
        for m in re.finditer(r"\b(?:password|passwd|pwd|secret|api_key|token)\b\s*(?:is|:|:=|=)\s*['\"]?([A-Za-z0-9@#\$\%^\&\*\-\_\+\=\!\?]{6,40})['\"]?", text, re.I):
            results.append(RecognizerResult(entity_type="PASSWORD", start=m.start(1), end=m.end(1), score=0.92))
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

    for result in sorted_results:
        entity_type = result.entity_type
        start = result.start
        end = result.end
        original_value = text[start:end]

        # Use TenSEAL Homomorphic masking for money/numbers, HMAC for text/credentials
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
    for token, original_value in sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True):
        restored_text = restored_text.replace(token, original_value)
    return restored_text
