import logging
from gateway.config import settings
from gateway.pii_detector import detect_pii

logger = logging.getLogger("securesphere.validator")

# Lazy load Hugging Face pipeline to prevent slow startup
toxicity_pipeline = None

# Offline/local fallback list of offensive terms to check in case model loading is bypassed or fails
OFFENSIVE_KEYWORDS = [
    "abuse", "harass", "slur", "bastard", "idiot", "jerk", "asshole", 
    "bitch", "scam", "fraud", "hacker", "cheat", "stupid AI", "kill yourself"
]

def load_toxicity_model():
    """
    Attempts to load the Hugging Face toxicity model.
    """
    global toxicity_pipeline
    if toxicity_pipeline is not None:
        return
        
    if not settings.ENFORCE_TOXICITY:
        logger.info("Toxicity evaluation is disabled in configuration.")
        toxicity_pipeline = "DISABLED"
        return

    try:
        from transformers import pipeline
        logger.info("Loading Hugging Face model 'unitary/toxic-bert' on CPU...")
        # device=-1 forces CPU execution (safe for laptops running docker/dev environments)
        toxicity_pipeline = pipeline("text-classification", model="unitary/toxic-bert", device=-1)
        logger.info("Toxicity classifier loaded successfully.")
    except Exception as e:
        logger.warning(f"Failed to load Hugging Face toxicity classifier: {str(e)}. Using keyword-based fallback.")
        toxicity_pipeline = "FALLBACK"


def evaluate_toxicity(text: str) -> float:
    """
    Evaluates the toxicity score of the text. Returns a score between 0.0 and 1.0.
    """
    load_toxicity_model()
    
    if toxicity_pipeline == "DISABLED":
        return 0.0
        
    if toxicity_pipeline == "FALLBACK" or toxicity_pipeline is None:
        # Rule-based fallback: check count of offensive terms
        text_lower = text.lower()
        matches = sum(1 for word in OFFENSIVE_KEYWORDS if word in text_lower)
        # Score is proportional to matches, capped at 1.0
        return min(0.3 * matches, 1.0)
        
    try:
        results = toxicity_pipeline(text)
        # unitary/toxic-bert returns classifications. 'toxic' label value is what we want
        # For simplicity, if label is 'toxic' (or 'TOXIC'), return its score, else return low score
        if results and isinstance(results, list):
            res = results[0]
            label = res.get("label", "").upper()
            score = res.get("score", 0.0)
            if "TOXIC" in label or "LABEL_1" in label:  # LABEL_1 is typically toxic in binary classifiers
                return score
        return 0.0
    except Exception as e:
        logger.error(f"Error executing toxicity model: {str(e)}")
        return 0.0


def validate_response(response_text: str) -> tuple[bool, str, str]:
    """
    Validates the outgoing response.
    Checks for:
        1. Toxicity (Hugging Face)
        2. Leaked PII patterns
    Returns:
        tuple[is_violating_bool, action_taken_str, processed_response_text]
    """
    # 1. Check Toxicity
    toxicity_score = evaluate_toxicity(response_text)
    if toxicity_score >= settings.TOXICITY_THRESHOLD:
        logger.warning(f"Response blocked: Toxicity score {toxicity_score:.2f} meets or exceeds threshold {settings.TOXICITY_THRESHOLD:.2f}.")
        blocked_msg = "[BLOCKED] Outbound response intercepted due to corporate safety policy violations (High Toxicity detected)."
        return True, "BLOCK", blocked_msg

    # 2. Check for Critical Credential Leakage
    import re
    CRITICAL_LEAK_TYPES = {"CREDIT_CARD", "AADHAAR_NUMBER", "PAN_CARD", "PASSWORD"}
    pii_results = detect_pii(response_text)
    
    # Filter for genuine critical leaks only (Aadhaar, PAN, Credit Card, Passwords)
    # Ignore internal tokens, benign entities, and general knowledge nouns
    actual_leaks = []
    for result in pii_results:
        entity_text = response_text[result.start:result.end].strip()
        
        # Skip our internal pseudonym tokens
        if re.match(r"^\[(?:TOKEN_[A-Z0-9_]+|ENC_[A-Z0-9_]+|[A-Z_]+_\d+)\]$", entity_text):
            continue
            
        # Only trigger on critical security credential types
        if result.entity_type in CRITICAL_LEAK_TYPES:
            actual_leaks.append((result, entity_text))

    if actual_leaks:
        logger.warning(f"Critical credential leak detected in outgoing LLM response: {[l[0].entity_type for l in actual_leaks]}")
        # Selectively redact only the leaked critical credentials without breaking general text
        sanitized_response = response_text
        for leak_result, entity_text in sorted(actual_leaks, key=lambda x: x[0].start, reverse=True):
            s, e = leak_result.start, leak_result.end
            sanitized_response = sanitized_response[:s] + f"[REDACTED_{leak_result.entity_type}]" + sanitized_response[e:]
        return True, "MASK", sanitized_response

    return False, "ALLOW", response_text
