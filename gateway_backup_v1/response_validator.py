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

    # 2. Check for PII Leakage
    import re
    pii_results = detect_pii(response_text)
    
    # Filter out non-critical entities (like DATE_TIME) and our own placeholder tokens
    # so they don't trigger false positive leak detections
    actual_leaks = []
    for result in pii_results:
        entity_text = response_text[result.start:result.end]
        logger.info(f"[Outbound Scan] Detected entity: type={result.entity_type}, text='{entity_text}', score={result.score:.2f}")
        if result.entity_type == "DATE_TIME":
            continue
        # Match tokens like [PERSON_1], [DATE_TIME_3]
        if re.match(r"^\[[A-Z_]+_\d+\]$", entity_text):
            continue
        actual_leaks.append(result)
        
    if actual_leaks:
        logger.warning("PII leak detected in outgoing LLM response! Masking output.")
        # Re-mask the response text so the customer doesn't see leaked PII
        from gateway.pii_detector import anonymize_prompt
        masked_response, _, _ = anonymize_prompt(response_text)
        return True, "MASK", masked_response

    return False, "ALLOW", response_text
