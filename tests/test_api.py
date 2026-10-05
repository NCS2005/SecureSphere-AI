import os
import httpx
import json

KEY = os.getenv("GEMINI_API_KEY", "")

def test_model(model_name):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={KEY}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{"parts": [{"text": "Hello, say test!"}]}]
    }
    try:
        r = httpx.post(url, json=payload, headers=headers, timeout=10.0)
        print(f"Model: {model_name} -> Status: {r.status_code}")
        if r.status_code == 200:
            print("Response:", r.json()["candidates"][0]["content"]["parts"][0]["text"])
            return True
        else:
            print("Error Details:", r.text)
            return False
    except Exception as e:
        print(f"Exception: {e}")
        return False

if __name__ == "__main__":
    test_model("gemini-2.5-flash")
