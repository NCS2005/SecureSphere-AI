import time
import logging
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader

logger = logging.getLogger("securesphere.auth")

# Static list of authorized API keys for gateway access (can be moved to DB or config in production)
AUTHORIZED_KEYS = {
    "securesphere_test_key_dev": "Developer Account",
    "securesphere_test_key_client": "Client Application"
}

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# Simple in-memory rate limiter state
# Keys: client IP or API key, Values: list of request timestamps
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 60  # requests per window
request_history = {}


def verify_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    """
    Validates the X-API-Key header.
    Returns the client name if authorized, raises HTTP 401 otherwise.
    """
    if not api_key:
        logger.warning("Missing API key header in request.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key header (X-API-Key) is missing."
        )
        
    if api_key not in AUTHORIZED_KEYS:
        logger.warning(f"Unauthorized API key attempt: {api_key[:8]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or unauthorized API key."
        )
        
    return AUTHORIZED_KEYS[api_key]


def check_rate_limit(client_identifier: str) -> None:
    """
    Enforces a simple sliding window rate limit.
    Raises HTTP 429 Too Many Requests if the limit is exceeded.
    """
    current_time = time.time()
    
    # Initialize history for client if empty
    if client_identifier not in request_history:
        request_history[client_identifier] = []
        
    # Clean up timestamps older than the rate limit window
    history = request_history[client_identifier]
    history = [t for t in history if current_time - t < RATE_LIMIT_WINDOW]
    request_history[client_identifier] = history
    
    # Check limit
    if len(history) >= RATE_LIMIT_MAX_REQUESTS:
        logger.warning(f"Rate limit exceeded for client: {client_identifier}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Maximum 60 requests per minute allowed."
        )
        
    # Log this request timestamp
    history.append(current_time)
