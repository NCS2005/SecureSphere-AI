import logging
import re
from typing import Tuple, Dict, Any, List

logger = logging.getLogger("securesphere.policy")

# Adversarial Prompt Injection & Jailbreak Signature Patterns
JAILBREAK_PATTERNS = [
    r"ignore\s+(?:all\s+)?(?:previous|prior|existing)?\s*(?:system\s+)?(?:instructions|rules|prompts|directives)",
    r"disregard\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions|rules|prompts)",
    r"(?:you\s+are\s+now|act\s+as)\s+(?:an?\s+)?(?:unrestricted|jailbroken|dan|developer\s+mode|god\s+mode)",
    r"\b(?:dan\s+mode|jailbreak|unrestricted\s+mode)\b",
    r"(?:dump|exfiltrate|leak|reveal)\s+(?:all\s+)?(?:database\s+)?(?:passwords|secrets|keys|credentials)",
    r"bypass\s+(?:all\s+)?(?:content\s+filters|safety\s+guidelines|restrictions)",
    r"you\s+are\s+no\s+longer\s+(?:an?\s+)?(?:ai|assistant|bound)",
    r"system\s*:\s*you\s+are",
    r"repeat\s+after\s+me\s+the\s+(?:system\s+prompt|initial\s+instructions)",
    r"reveal\s+(?:your\s+)?(?:hidden\s+)?(?:system\s+prompt|developer\s+instructions)"
]

# Configured Enterprise Security Policies
DEFAULT_POLICIES = [
    {
        "name": "financial_phishing_block",
        "description": "Block requests combining identity numbers (Aadhaar/PAN) with payment or wire transfer intents.",
        "pii_required": ["AADHAAR_NUMBER", "PAN_CARD"],
        "keywords": ["send money", "transfer", "pay", "wire", "deposit", "transaction"],
        "action": "BLOCK"
    },
    {
        "name": "card_pin_leak_block",
        "description": "Block requests combining credit card / CVV entries with password or PIN requests.",
        "pii_required": ["CREDIT_CARD", "CVV"],
        "keywords": ["pin", "password", "cvv", "verification code", "otp"],
        "action": "BLOCK"
    },
    {
        "name": "credential_exfiltration_block",
        "description": "Block requests attempting to dump or exfiltrate private database passwords and API tokens.",
        "pii_required": ["PASSWORD"],
        "keywords": ["dump", "exfiltrate", "leak", "export all", "show all passwords"],
        "action": "BLOCK"
    }
]

def calculate_adversarial_score(prompt: str) -> Tuple[float, List[str]]:
    """
    Computes a prompt injection & jailbreak vulnerability score from 0.0 to 1.0.
    """
    prompt_lower = prompt.lower()
    matches = []
    
    for pattern in JAILBREAK_PATTERNS:
        if re.search(pattern, prompt_lower):
            matches.append(pattern)
            
    # Each matched jailbreak pattern contributes significantly to risk
    score = min(len(matches) * 0.45, 1.0)
    return score, matches

def evaluate_policy(prompt: str, detected_entities: list) -> Tuple[bool, str, float]:
    """
    Dual-Phase Guardrail Evaluation:
    1. Phase 1: Inbound Prompt Injection & Jailbreak Attack Scan.
    2. Phase 2: Contextual Enterprise Compliance Policies.
    Returns:
        tuple[is_blocked_bool, block_reason_str, adversarial_risk_score]
    """
    # 1. Inbound Prompt Injection Scan
    risk_score, injection_matches = calculate_adversarial_score(prompt)
    if risk_score >= 0.40:
        logger.warning(f"Inbound adversarial attack blocked (Risk Score: {risk_score:.2f})")
        return True, f"Security Violation [ADVERSARIAL_INJECTION]: Prompt blocked due to detected jailbreak/override intent (Risk Score: {risk_score:.2f}).", risk_score

    # 2. Contextual PII Policy Evaluation
    prompt_lower = prompt.lower()
    detected_types = {result.entity_type for result in detected_entities}

    for policy in DEFAULT_POLICIES:
        pii_match = any(pii_type in detected_types for pii_type in policy["pii_required"])
        keyword_match = any(keyword in prompt_lower for keyword in policy["keywords"])
        
        if pii_match and keyword_match:
            logger.warning(f"Policy violation triggered: {policy['name']} - {policy['description']}")
            return True, f"Security Violation [{policy['name']}]: Request blocked by enterprise compliance policy.", risk_score
            
    return False, "", risk_score
