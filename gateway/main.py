import time
import logging
from fastapi import FastAPI, Depends, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

from gateway.config import settings
from gateway.auth import verify_api_key, check_rate_limit
from gateway.pii_detector import anonymize_prompt, deanonymize_response, detect_pii
from gateway.vision_detector import vision_detector
from gateway.policy_engine import evaluate_policy
from gateway.router import route_request
from gateway.response_validator import validate_response, evaluate_toxicity
from gateway.database import log_transaction

# Configure logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("securesphere.main")

app = FastAPI(
    title="SecureSphere-AI Gateway",
    description="Private LLM Deployment & Intelligent AI Guardrail Gateway",
    version="1.0.0"
)

# Enable CORS for the Streamlit dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Input schemas
class GenerateRequest(BaseModel):
    prompt: str = Field(..., example="My Aadhaar number is 1234 5678 9012. Write a letter.")
    user_id: Optional[str] = Field("dev_user", example="user_123")


# OpenAI compatible schemas
class ChatMessage(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    model: str = "gpt-4o-mini"
    messages: List[ChatMessage]
    temperature: Optional[float] = 0.7


@app.on_event("startup")
def startup_event():
    logger.info("SecureSphere-AI Gateway starting up...")
    logger.info(f"Configuration: MOCK_CLOUD={settings.MOCK_CLOUD}, BYPASS_PII_ROUTING={settings.BYPASS_PII_ROUTING}")


@app.get("/")
def read_root():
    return {
        "app": "SecureSphere-AI Gateway",
        "status": "Online",
        "endpoints": {
            "root": "/",
            "health": "/health",
            "generate": "/generate (Diagnostic)",
            "completions": "/v1/chat/completions (OpenAI Compatible)"
        }
    }


@app.get("/health")
def health_check():
    """
    Service health and database status check.
    """
    from gateway.database import db_use_sqlite
    return {
        "status": "Healthy",
        "database": "SQLite (Fallback)" if db_use_sqlite else "MongoDB (Active)",
        "bypass_pii_routing": settings.BYPASS_PII_ROUTING,
        "enforce_toxicity": settings.ENFORCE_TOXICITY,
        "vision_engine": vision_detector.cv2_enabled
    }

class ImageAnonymizeRequest(BaseModel):
    image_base64: str
    mode: Optional[str] = "MODE_A"

@app.post("/anonymize-image")
def anonymize_image_endpoint(req: ImageAnonymizeRequest):
    """
    Anonymizes sensitive visual elements (faces, license plates, text PII) using OpenCV.
    """
    import base64
    try:
        raw_bytes = base64.b64decode(req.image_base64)
        anonymized_bytes, telemetry = vision_detector.anonymize_image_bytes(raw_bytes, mode=req.mode or "MODE_A")
        anonymized_base64 = base64.b64encode(anonymized_bytes).decode('utf-8')
        return {
            "status": "SUCCESS",
            "anonymized_image_base64": anonymized_base64,
            "telemetry": telemetry
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Image processing error: {str(e)}")


class MultimodalGenerateRequest(BaseModel):
    prompt: str = Field(..., example="Extract text and summarize details from this image.")
    image_base64: str
    mode: Optional[str] = "MODE_A"
    user_id: Optional[str] = "multimodal_user"


@app.post("/generate-multimodal")
async def generate_multimodal_endpoint(
    req: MultimodalGenerateRequest,
    client_name: str = Depends(verify_api_key)
):
    """
    Multimodal Pipeline:
    1. Anonymizes biometric faces in image locally via OpenCV Gaussian Blur.
    2. Sanitizes sensitive PII in prompt via HMAC-SHA256.
    3. Calls Cloud Multimodal LLM (Gemini Vision) with REDACTED image + sanitized prompt.
    4. Restores PII in response and returns full audit telemetry.
    """
    import base64
    from gateway.router import call_cloud_multimodal
    start_time = time.time()
    
    # 1. Image Anonymization (Biometrics/Faces + Mode B Text Redaction)
    raw_bytes = base64.b64decode(req.image_base64)
    anonymized_bytes, vision_telemetry = vision_detector.anonymize_image_bytes(raw_bytes, mode=req.mode or "MODE_A")
    anonymized_base64 = base64.b64encode(anonymized_bytes).decode('utf-8')
    
    # 2. Text PII Sanitization for user prompt
    sanitized_prompt, pii_mapping, has_pii = anonymize_prompt(req.prompt)
    
    # 3. Call Cloud Vision LLM with Redacted Image
    raw_response = await call_cloud_multimodal(sanitized_prompt, anonymized_base64)
    
    # 4. Outbound Validation & Restoration
    is_violating, action_taken, processed_response = validate_response(raw_response)
    final_response = deanonymize_response(processed_response, pii_mapping)
    
    latency_ms = int((time.time() - start_time) * 1000)
    return {
        "status": "SUCCESS",
        "final_response": final_response,
        "vision_telemetry": vision_telemetry,
        "has_pii": has_pii,
        "latency_ms": latency_ms
    }


@app.post("/generate")
async def generate_diagnostic(
    request_data: GenerateRequest,
    request: Request,
    client_name: str = Depends(verify_api_key)
):
    """
    Diagnostic endpoint that runs the full security pipeline and returns all
    intermediate logs, scores, and routing details.
    """
    start_time = time.time()
    
    # Rate Limiter
    check_rate_limit(client_name)
    
    original_prompt = request_data.prompt
    user_id = request_data.user_id or "diagnostic_user"
    
    # 1. PII Scan and Masking
    sanitized_prompt, pii_mapping, has_pii = anonymize_prompt(original_prompt)
    detected_entities = detect_pii(original_prompt)
    pii_types = list({res.entity_type for res in detected_entities})
    
    # 2. Inbound Policy & Toxicity Evaluation
    is_blocked, block_reason, risk_score = evaluate_policy(original_prompt, detected_entities)
    
    # Check toxicity of the input prompt
    from gateway.response_validator import evaluate_toxicity
    inbound_toxicity = evaluate_toxicity(original_prompt)
    if inbound_toxicity >= settings.TOXICITY_THRESHOLD:
        is_blocked = True
        block_reason = "[BLOCKED] Inbound prompt intercepted due to corporate safety policy violations (High Toxicity detected)."
        
    if is_blocked:
        latency_ms = int((time.time() - start_time) * 1000)
        log_transaction(
            user_id=user_id,
            prompt=original_prompt,
            sanitized_prompt=sanitized_prompt,
            response=block_reason,
            model_used="None (Blocked by Policy)",
            pii_detected=has_pii,
            pii_types=pii_types,
            status="BLOCK",
            toxicity_score=inbound_toxicity if inbound_toxicity >= settings.TOXICITY_THRESHOLD else 0.0,
            latency_ms=latency_ms
        )
        return {
            "status": "BLOCK",
            "reason": block_reason,
            "original_prompt": original_prompt,
            "sanitized_prompt": sanitized_prompt,
            "has_pii": has_pii,
            "pii_detected": pii_types,
            "model_used": "None (Blocked by Policy)",
            "raw_response": "",
            "final_response": block_reason,
            "toxicity_score": inbound_toxicity if inbound_toxicity >= settings.TOXICITY_THRESHOLD else 0.0,
            "risk_score": round(risk_score, 3),
            "latency_ms": latency_ms,
            "crypto_telemetry": {
                "pseudonym_scheme": "HMAC-SHA256 Base32",
                "vault_encryption": "AES-256-GCM (96-bit Nonce)",
                "homomorphic_scheme": "CKKS / Affine Masking"
            }
        }
        
    # 3. Model Routing
    raw_response, model_used = await route_request(original_prompt, sanitized_prompt, has_pii)
    
    # 4. Outbound Response Validation & Toxicity check
    is_violating, action_taken, processed_response = validate_response(raw_response)
    
    # If the response was blocked due to toxicity
    status_flag = "ALLOW"
    if is_violating:
        status_flag = action_taken # "BLOCK" or "MASK"
        
    # 5. De-anonymize response (skip if BLOCKED due to toxicity)
    final_response = processed_response
    if status_flag != "BLOCK":
        final_response = deanonymize_response(processed_response, pii_mapping)
        
    # Measure latency
    latency_ms = int((time.time() - start_time) * 1000)
    toxicity_score = evaluate_toxicity(raw_response)
    
    # 6. Log Transaction
    log_transaction(
        user_id=user_id,
        prompt=original_prompt,
        sanitized_prompt=sanitized_prompt,
        response=final_response,
        model_used=model_used,
        pii_detected=has_pii,
        pii_types=pii_types,
        status=status_flag,
        toxicity_score=toxicity_score,
        latency_ms=latency_ms
    )
    
    return {
        "status": status_flag,
        "original_prompt": original_prompt,
        "sanitized_prompt": sanitized_prompt,
        "has_pii": has_pii,
        "pii_detected": pii_types,
        "model_used": model_used,
        "raw_response": raw_response,
        "final_response": final_response,
        "toxicity_score": round(toxicity_score, 4),
        "risk_score": round(risk_score, 3),
        "latency_ms": latency_ms,
        "crypto_telemetry": {
            "pseudonym_scheme": "HMAC-SHA256 Base32",
            "vault_encryption": "AES-256-GCM (96-bit Nonce)",
            "homomorphic_scheme": "CKKS / Affine Masking"
        },
        "tokens_vaulted": len(pii_mapping)
    }


@app.post("/v1/chat/completions")
async def chat_completions(
    request_data: ChatCompletionRequest,
    request: Request,
    client_name: str = Depends(verify_api_key)
):
    """
    OpenAI-compatible chat completion endpoint. 
    Drop-in replacement for OpenAI SDK or client applications.
    """
    start_time = time.time()
    
    # Rate Limiter
    check_rate_limit(client_name)
    
    # Extract last user message as prompt
    user_message = ""
    for msg in reversed(request_data.messages):
        if msg.role == "user":
            user_message = msg.content
            break
            
    if not user_message:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No user message found in the chat request history."
        )

    # 1. PII Scan and Masking
    sanitized_prompt, pii_mapping, has_pii = anonymize_prompt(user_message)
    detected_entities = detect_pii(user_message)
    pii_types = list({res.entity_type for res in detected_entities})
    
    # 2. Inbound Policy & Toxicity Evaluation
    is_blocked, block_reason, risk_score = evaluate_policy(user_message, detected_entities)
    
    # Check toxicity of the input prompt
    from gateway.response_validator import evaluate_toxicity
    inbound_toxicity = evaluate_toxicity(user_message)
    if inbound_toxicity >= settings.TOXICITY_THRESHOLD:
        is_blocked = True
        block_reason = "[BLOCKED] Inbound prompt intercepted due to corporate safety policy violations (High Toxicity detected)."
        
    if is_blocked:
        latency_ms = int((time.time() - start_time) * 1000)
        log_transaction(
            user_id=client_name,
            prompt=user_message,
            sanitized_prompt=sanitized_prompt,
            response=block_reason,
            model_used="None (Blocked by Policy)",
            pii_detected=has_pii,
            pii_types=pii_types,
            status="BLOCK",
            toxicity_score=inbound_toxicity if inbound_toxicity >= settings.TOXICITY_THRESHOLD else 0.0,
            latency_ms=latency_ms
        )
        return create_openai_response(block_reason, "None (Blocked by Policy)")
        
    # 3. Model Routing
    raw_response, model_used = await route_request(user_message, sanitized_prompt, has_pii)
    
    # 4. Outbound Response Validation (Toxicity & Leak check)
    is_violating, action_taken, processed_response = validate_response(raw_response)
    
    status_flag = "ALLOW"
    if is_violating:
        status_flag = action_taken
        
    # 5. De-anonymize response (skip if BLOCKED due to toxicity)
    final_response = processed_response
    if status_flag != "BLOCK":
        final_response = deanonymize_response(processed_response, pii_mapping)
        
    latency_ms = int((time.time() - start_time) * 1000)
    toxicity_score = evaluate_toxicity(raw_response)
    
    # 6. Log Transaction
    log_transaction(
        user_id=client_name,
        prompt=user_message,
        sanitized_prompt=sanitized_prompt,
        response=final_response,
        model_used=model_used,
        pii_detected=has_pii,
        pii_types=pii_types,
        status=status_flag,
        toxicity_score=toxicity_score,
        latency_ms=latency_ms
    )
    
    return create_openai_response(final_response, model_used)


def create_openai_response(content: str, model: str) -> Dict[str, Any]:
    """
    Helper function to wrap response in OpenAI completion JSON structure.
    """
    prompt_tokens = len(content.split()) # Rough estimate
    completion_tokens = len(content.split())
    return {
        "id": f"chatcmpl-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens
        }
    }
