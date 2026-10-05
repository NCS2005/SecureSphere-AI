import logging
import re
import spacy
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, EntityRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import SpacyNlpEngine

logger = logging.getLogger("securesphere.pii")

# Ensure spaCy model en_core_web_sm is loaded or warn
try:
    spacy.load("en_core_web_sm")
except OSError:
    logger.warning("spaCy model 'en_core_web_sm' is not installed. Fallback regex model will be used.")

# Initialize Analyzer Engine with explicit en_core_web_sm model config
from presidio_analyzer.nlp_engine import NlpEngineProvider
analyzer = None
try:
    nlp_configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }
    provider = NlpEngineProvider(nlp_configuration=nlp_configuration)
    nlp_engine = provider.create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
    logger.info("Presidio AnalyzerEngine successfully initialized with en_core_web_sm.")
except Exception as e:
    logger.warning(f"Could not load configured AnalyzerEngine. Initializing manual fallback. Error: {str(e)}")

# Define Custom Indian PII Recognizers
# 1. Aadhaar Card Number
aadhaar_pattern = Pattern(
    name="aadhaar_pattern",
    regex=r"\b[2-9]{1}[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}\b",
    score=0.85
)
aadhaar_recognizer = PatternRecognizer(
    supported_entity="AADHAAR_NUMBER",
    patterns=[aadhaar_pattern]
)

# 2. PAN Card Number (Permanent Account Number)
pan_pattern = Pattern(
    name="pan_pattern",
    regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
    score=0.85
)
pan_recognizer = PatternRecognizer(
    supported_entity="PAN_CARD",
    patterns=[pan_pattern]
)

# 3. Indian Passport Number
passport_pattern = Pattern(
    name="passport_pattern",
    regex=r"\b[A-Z]{1}[0-9]{7}\b",
    score=0.85
)
passport_recognizer = PatternRecognizer(
    supported_entity="PASSPORT_NUMBER",
    patterns=[passport_pattern]
)

# 4. CVV Number (Credit Card CVV)
cvv_pattern = Pattern(
    name="cvv_pattern",
    regex=r"\b\d{3,4}\b",  # Match 3 or 4 digit numbers with surrounding CVV context
    score=0.40  # Lower baseline score, depends on context
)
cvv_recognizer = PatternRecognizer(
    supported_entity="CVV",
    patterns=[cvv_pattern],
    context=["cvv", "cvv2", "card verification", "security code"]
)

# 5. Password / API Key Recognizer
# Custom class-based recognizer using contextual assignments to extract credentials
class PasswordRecognizer(EntityRecognizer):
    def __init__(self):
        super().__init__(supported_entities=["PASSWORD"], name="PasswordRecognizer")
        
    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        if "PASSWORD" not in entities:
            return results
            
        pattern = r"\b(?:password|passwd|pwd|secret|api_key|token|key)\b\s*(?:is|:|:=|=)\s*['\"]?([A-Za-z0-9@#\$\%^\&\*\-\_\+\=\!\?]{6,30})['\"]?"
        for match in re.finditer(pattern, text, re.IGNORECASE):
            val_start = match.start(1)
            val_end = match.end(1)
            results.append(RecognizerResult(
                entity_type="PASSWORD",
                start=val_start,
                end=val_end,
                score=0.85
            ))
        return results

password_recognizer = PasswordRecognizer()

# Register custom recognizers to the analyzer
if analyzer:
    analyzer.registry.add_recognizer(aadhaar_recognizer)
    analyzer.registry.add_recognizer(pan_recognizer)
    analyzer.registry.add_recognizer(passport_recognizer)
    analyzer.registry.add_recognizer(cvv_recognizer)
    analyzer.registry.add_recognizer(password_recognizer)


def detect_pii(text: str) -> list:
    """
    Scans the text for PII entities and returns a list of results.
    """
    if not analyzer:
        # Fallback basic regex detector if Presidio failed to load
        return fallback_detect_pii(text)
    
    # We scan for standard entities + our custom registered entities
    entities_to_scan = [
        "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "CRYPTO", "DATE_TIME", 
        "IP_ADDRESS", "AADHAAR_NUMBER", "PAN_CARD", "PASSPORT_NUMBER", "CVV", "PASSWORD"
    ]
    
    results = analyzer.analyze(text=text, language="en", entities=entities_to_scan)
    return results


def fallback_detect_pii(text: str) -> list:
    """
    A lightweight, pure-regex fallback detector in case spacy or Presidio analyzer
    fails to load properly.
    """
    class MockResult:
        def __init__(self, entity_type, start, end, score):
            self.entity_type = entity_type
            self.start = start
            self.end = end
            self.score = score

    results = []
    
    # Simple regex patterns (use capture group 1 for values requiring context matches)
    patterns = {
        "EMAIL_ADDRESS": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "PHONE_NUMBER": r"\b(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b",
        "CREDIT_CARD": r"\b(?:\d[ -]*?){13,19}\b",
        "AADHAAR_NUMBER": r"\b[2-9]{1}[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}\b",
        "PAN_CARD": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
        "PASSPORT_NUMBER": r"\b[A-Z]{1}[0-9]{7}\b",
        "PASSWORD": r"\b(?:password|passwd|pwd|secret|api_key|token)\b\s*(?:is|:|:=|=)\s*([A-Za-z0-9@#\$\%^\&\*\-\_\+\=\!\?]{6,30})",
    }
    
    for entity, pattern in patterns.items():
        for match in re.finditer(pattern, text):
            # Use group 1 if present, otherwise whole match
            start = match.start(1) if match.groups() else match.start()
            end = match.end(1) if match.groups() else match.end()
            results.append(MockResult(
                entity_type=entity,
                start=start,
                end=end,
                score=0.85
            ))
            
    return results


def filter_overlapping_results(results):
    """
    Filters out overlapping PII matches, keeping only the highest scoring
    and longest spans.
    """
    # Sort by score descending, then by span length descending
    sorted_results = sorted(results, key=lambda x: (x.score, x.end - x.start), reverse=True)
    
    selected = []
    for res in sorted_results:
        # Check if this overlaps with any already selected
        overlap = False
        for sel in selected:
            # Overlap condition: max(start1, start2) < min(end1, end2)
            if max(res.start, sel.start) < min(res.end, sel.end):
                overlap = True
                break
        if not overlap:
            selected.append(res)
            
    return selected


def anonymize_prompt(text: str) -> tuple[str, dict[str, str], bool]:
    """
    Masks all detected PII in the text with secure placeholders.
    Returns:
        tuple[sanitized_text, mapping_dict, has_pii_boolean]
    """
    results = detect_pii(text)
    if not results:
        return text, {}, False
        
    # Filter out overlapping entity matches (e.g. CVV inside Aadhaar digits)
    filtered_results = filter_overlapping_results(results)
    
    # Sort results in reverse order of start position to prevent index offset shifts
    sorted_results = sorted(filtered_results, key=lambda x: x.start, reverse=True)
    
    mapping = {}
    counters = {}
    sanitized_text = text
    
    for result in sorted_results:
        entity_type = result.entity_type
        start = result.start
        end = result.end
        original_value = text[start:end]
        
        # Manage entity numbering (e.g. EMAIL_ADDRESS_1, AADHAAR_NUMBER_1)
        if entity_type not in counters:
            counters[entity_type] = 1
        else:
            counters[entity_type] += 1
            
        token = f"[{entity_type}_{counters[entity_type]}]"
        
        # Save placeholder mapping (for restoration)
        mapping[token] = original_value
        
        # Replace original PII with placeholder token
        sanitized_text = sanitized_text[:start] + token + sanitized_text[end:]
        
    return sanitized_text, mapping, True


def deanonymize_response(text: str, mapping: dict[str, str]) -> str:
    """
    Restores the original PII values back into the response from the mapping dictionary.
    """
    restored_text = text
    for token, original_value in mapping.items():
        restored_text = restored_text.replace(token, original_value)
    return restored_text
