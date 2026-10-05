import spacy
try:
    nlp = spacy.load("en_core_web_sm")
    print("SUCCESS: loaded en_core_web_sm")
except Exception as e:
    print("FAILED:", type(e), str(e))
