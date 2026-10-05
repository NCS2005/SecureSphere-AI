import os
from pathlib import Path
from dotenv import load_dotenv

# Resolve the project root directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env
load_dotenv(dotenv_path=BASE_DIR / ".env")

class Settings:
    # Gateway Server Settings
    PORT: int = int(os.getenv("PORT", 8000))
    HOST: str = os.getenv("HOST", "0.0.0.0")

    # Cloud LLM Settings
    MOCK_CLOUD: bool = os.getenv("MOCK_CLOUD", "true").lower() in ("true", "1", "yes")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")

    # Local LLM (Ollama) Settings
    LOCAL_LLM_URL: str = os.getenv("LOCAL_LLM_URL", "http://localhost:11434")
    LOCAL_LLM_MODEL: str = os.getenv("LOCAL_LLM_MODEL", "llama3.2:1b")

    # Database Settings
    MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    MONGODB_DB_NAME: str = os.getenv("MONGODB_DB_NAME", "securesphere")

    # Security & Routing Policies
    BYPASS_PII_ROUTING: bool = os.getenv("BYPASS_PII_ROUTING", "false").lower() in ("true", "1", "yes")
    ENFORCE_TOXICITY: bool = os.getenv("ENFORCE_TOXICITY", "true").lower() in ("true", "1", "yes")
    TOXICITY_THRESHOLD: float = float(os.getenv("TOXICITY_THRESHOLD", 0.80))
    LOG_RAW_PII: bool = os.getenv("LOG_RAW_PII", "false").lower() in ("true", "1", "yes")

settings = Settings()
