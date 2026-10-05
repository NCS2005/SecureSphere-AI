import logging

logger = logging.getLogger("securesphere.policy")

# Default configurable rules
# Each rule checks if a specific set of PII is present alongside suspicious keywords.
DEFAULT_POLICIES = [
    {
        "name": "financial_phishing_block",
        "description": "Block requests that combine identity cards (Aadhaar/PAN) with payment or transfer intents.",
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
    }
]

def evaluate_policy(prompt: str, detected_entities: list) -> tuple[bool, str]:
    """
    Evaluates prompt against configured policies.
    Returns:
        tuple[is_blocked_bool, block_reason_str]
    """
    prompt_lower = prompt.lower()
    detected_types = {result.entity_type for result in detected_entities}

    for policy in DEFAULT_POLICIES:
        # Check if any of the required PII types are in the prompt
        pii_match = any(pii_type in detected_types for pii_type in policy["pii_required"])
        
        # Check if any of the suspicious keywords are in the prompt
        keyword_match = any(keyword in prompt_lower for keyword in policy["keywords"])
        
        if pii_match and keyword_match:
            logger.warning(f"Policy violation triggered: {policy['name']} - {policy['description']}")
            return True, f"Policy violation ({policy['name']}): Request blocked. Combining {list(pii_match for pii_match in policy['pii_required'] if pii_match in detected_types)} with financial keywords is prohibited."
            
    return False, ""
