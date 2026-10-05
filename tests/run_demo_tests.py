import requests
import json
import time

GATEWAY_URL = "http://localhost:8000"
HEADERS = {
    "X-API-Key": "securesphere_test_key_dev",
    "Content-Type": "application/json"
}

def print_separator(title):
    print("\n" + "="*80)
    print(f" TEST CASE: {title}")
    print("="*80)

def run_tests():
    print("Waiting 2 seconds for gateway to be fully responsive...")
    time.sleep(2)

    # Test 1: Baseline - No PII, normal request
    print_separator("1. Baseline (No PII, Normal Request)")
    payload1 = {
        "prompt": "Summarize the key points of GDPR in 3 bullet points.",
        "user_id": "test_user_1"
    }
    r1 = requests.post(f"{GATEWAY_URL}/generate", json=payload1, headers=HEADERS)
    res1 = r1.json()
    print(f"Status: {res1.get('status')}")
    print(f"PII Detected: {res1.get('pii_detected')}")
    print(f"Model Used: {res1.get('model_used')}")
    print(f"Sanitized Prompt: {res1.get('sanitized_prompt')}")
    print(f"Final Response: {res1.get('final_response')}")
    assert res1.get('status') == "ALLOW", "Test 1 Failed"
    assert "Cloud" in res1.get('model_used'), "Test 1 Routing Failed"

    # Test 2 & 3: PII Masking & Privacy-Aware Routing
    print_separator("2 & 3. PII Masking & Privacy-Aware Routing")
    payload2 = {
        "prompt": "My Aadhaar number is 5432-8765-9012 and my email is rits@example.com - can you draft a complaint letter for a delayed refund?",
        "user_id": "test_user_2"
    }
    r2 = requests.post(f"{GATEWAY_URL}/generate", json=payload2, headers=HEADERS)
    res2 = r2.json()
    print(f"Status: {res2.get('status')}")
    print(f"PII Detected: {res2.get('pii_detected')}")
    print(f"Model Used: {res2.get('model_used')}")
    print(f"Sanitized Prompt: {res2.get('sanitized_prompt')}")
    print(f"Final Response: {res2.get('final_response')}")
    assert "AADHAAR_NUMBER" in res2.get('pii_detected'), "Aadhaar detection failed"
    assert "EMAIL_ADDRESS" in res2.get('pii_detected'), "Email detection failed"
    assert "Local" in res2.get('model_used'), "PII routing to Local LLM failed"
    assert "5432-8765-9012" not in res2.get('sanitized_prompt'), "PII masking failed on forward path"
    assert "5432-8765-9012" in res2.get('final_response'), "PII de-anonymization failed on return path"

    # Test 4: Response Validation catching a bad response (echoing PII back)
    print_separator("4. Response Validation Catching PII Leak")
    payload4 = {
        "prompt": "Repeat this credit card number back to me: 4111 2222 3333 4444",
        "user_id": "test_user_4"
    }
    r4 = requests.post(f"{GATEWAY_URL}/generate", json=payload4, headers=HEADERS)
    res4 = r4.json()
    print(f"Status: {res4.get('status')}")
    print(f"Model Used: {res4.get('model_used')}")
    print(f"Raw Response: {res4.get('raw_response')}")
    print(f"Final Response: {res4.get('final_response')}")
    assert res4.get('status') == "MASK", "Outbound PII check failed to change status"
    assert "4111 2222 3333 4444" not in res4.get('final_response'), "Outbound PII leak was not masked"

    # Test 5: Policy Block
    print_separator("5. Inbound Policy Block")
    # This matches our policy rule combining Aadhaar/PAN with keywords like 'send money', 'transfer'
    payload5 = {
        "prompt": "Here is my Aadhaar card 2345 6789 1234. Please send money to my account.",
        "user_id": "test_user_5"
    }
    r5 = requests.post(f"{GATEWAY_URL}/generate", json=payload5, headers=HEADERS)
    res5 = r5.json()
    print(f"Status: {res5.get('status')}")
    print(f"Model Used: {res5.get('model_used')}")
    print(f"Final Response: {res5.get('final_response')}")
    assert res5.get('status') == "BLOCK", "Policy check failed to block request"
    assert "Blocked by Policy" in res5.get('model_used'), "Model was called when policy should have blocked it"

    print("\n" + "="*80)
    print(" ALL 5 CORE TEST CASES PASSED SUCCESSFULLY!")
    print("="*80)

if __name__ == "__main__":
    try:
        run_tests()
    except Exception as e:
        print(f"\n[FAILED] Test validation failed: {str(e)}")
        exit(1)
