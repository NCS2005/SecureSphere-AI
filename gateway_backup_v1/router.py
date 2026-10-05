import httpx
import logging
from gateway.config import settings

logger = logging.getLogger("securesphere.router")

async def call_cloud_llm(prompt: str) -> str:
    """
    Sends the sanitized prompt to the external Cloud LLM (Gemini or OpenAI).
    Falls back to a Mock response if settings.MOCK_CLOUD is True.
    """
    if settings.MOCK_CLOUD:
        logger.info("[Mock Mode] Simulating Cloud LLM call...")
        return f"[Cloud LLM (Mock GPT-4o)] Here is the clean response. You requested details on: '{prompt}'."

    # Try Google Gemini first
    if settings.GEMINI_API_KEY:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key={settings.GEMINI_API_KEY}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ]
        }
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(url, json=payload, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    text = data["candidates"][0]["content"]["parts"][0]["text"]
                    return text
                else:
                    logger.error(f"Gemini API returned error {response.status_code}: {response.text}")
        except Exception as e:
            logger.error(f"Failed to communicate with Gemini API: {str(e)}")

    # Try OpenAI if Gemini key is not set but OpenAI is
    if settings.OPENAI_API_KEY:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.OPENAI_API_KEY}"
        }
        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(url, json=payload, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    text = data["choices"][0]["message"]["content"]
                    return text
                else:
                    logger.error(f"OpenAI API returned error {response.status_code}: {response.text}")
        except Exception as e:
            logger.error(f"Failed to communicate with OpenAI API: {str(e)}")

    # Fallback if both keys are missing or failed
    logger.warning("No valid Cloud API keys found or cloud calls failed. Falling back to local cloud mock.")
    return f"[Cloud LLM (Local Fallback)] You sent: '{prompt}'. (Note: Provide a Gemini/OpenAI API key in .env to call the real cloud model)."


async def call_local_llm(prompt: str) -> str:
    """
    Sends the prompt to a locally hosted LLM via Ollama.
    Falls back to a local mock model response if Ollama is not running.
    """
    url = f"{settings.LOCAL_LLM_URL}/api/generate"
    payload = {
        "model": settings.LOCAL_LLM_MODEL,
        "prompt": prompt,
        "stream": False
    }
    
    try:
        async with httpx.AsyncClient(timeout=45.0) as client:
            response = await client.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                return data.get("response", "")
            else:
                logger.error(f"Ollama returned error {response.status_code}: {response.text}")
    except Exception as e:
        logger.warning(f"Ollama connection failed (Is Ollama running?). Falling back to Mock Ollama response. Error: {str(e)}")
        
    if "Repeat this credit card number" in prompt:
        # Deliberately output a raw credit card leak to test the Response Validator
        return "Sure, the card number you gave me is 4111 2222 3333 4444."
        
    return f"[Local LLM (Offline {settings.LOCAL_LLM_MODEL})] Safe, offline response processed locally. Masked prompt received: '{prompt}'."


async def route_request(original_prompt: str, sanitized_prompt: str, has_pii: bool) -> tuple[str, str]:
    """
    Routes the request based on PII detection and settings.
    Returns:
        tuple[response_content, model_name]
    """
    # Check if we should bypass the local routing rule
    if settings.BYPASS_PII_ROUTING:
        logger.info("Routing request to Cloud LLM (PII routing bypass active).")
        response = await call_cloud_llm(sanitized_prompt)
        return response, "Cloud LLM (Gemini/OpenAI)"

    if has_pii:
        logger.info(f"PII detected. Routing request to Local LLM ({settings.LOCAL_LLM_MODEL}).")
        # Notice that we send the sanitized (masked) prompt to Ollama as well,
        # ensuring the local model doesn't store PII in its history or prompt context.
        response = await call_local_llm(sanitized_prompt)
        return response, f"Local LLM ({settings.LOCAL_LLM_MODEL})"
    else:
        logger.info("No PII detected. Routing request to Cloud LLM.")
        response = await call_cloud_llm(sanitized_prompt)
        return response, "Cloud LLM (Gemini/OpenAI)"
