import logging
import sqlite3
import json
from datetime import datetime
from gateway.config import settings

logger = logging.getLogger("securesphere.db")

# Initialize database connections
mongo_client = None
db_use_sqlite = True

# Try connecting to MongoDB first
try:
    from pymongo import MongoClient
    # Set a short connection timeout so we don't hang if Mongo is offline
    mongo_client = MongoClient(settings.MONGODB_URI, serverSelectionTimeoutMS=2000)
    # Trigger a call to verify connection
    mongo_client.server_info()
    db_use_sqlite = False
    logger.info("Successfully connected to MongoDB database.")
except Exception as e:
    logger.warning(f"MongoDB connection failed (Is MongoDB running?). Falling back to local SQLite database. Error: {str(e)}")
    db_use_sqlite = True


# Initialize SQLite Database if fallback active
def init_sqlite_db():
    conn = sqlite3.connect("securesphere.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            user_id TEXT,
            prompt TEXT,
            sanitized_prompt TEXT,
            response TEXT,
            model_used TEXT,
            pii_detected INTEGER,
            pii_types TEXT,
            status TEXT,
            toxicity_score REAL,
            latency_ms INTEGER
        )
    """)
    conn.commit()
    conn.close()

if db_use_sqlite:
    init_sqlite_db()


def log_transaction(
    user_id: str,
    prompt: str,
    sanitized_prompt: str,
    response: str,
    model_used: str,
    pii_detected: bool,
    pii_types: list,
    status: str,
    toxicity_score: float,
    latency_ms: int
):
    """
    Logs a request transaction to MongoDB or SQLite.
    Conforms to the LOG_RAW_PII privacy setting.
    """
    timestamp = datetime.utcnow().isoformat()
    
    # Enforce data minimization: if LOG_RAW_PII is false, do not log the sensitive prompt
    logged_prompt = prompt if settings.LOG_RAW_PII else sanitized_prompt
    logged_response = response
    
    # If blocked or PII masked, response might be clean, but we mask the output anyway
    pii_types_str = ",".join(pii_types) if pii_types else ""

    if not db_use_sqlite and mongo_client:
        try:
            db = mongo_client[settings.MONGODB_DB_NAME]
            logs = db.audit_logs
            record = {
                "timestamp": timestamp,
                "user_id": user_id,
                "prompt": logged_prompt,
                "sanitized_prompt": sanitized_prompt,
                "response": logged_response,
                "model_used": model_used,
                "pii_detected": int(pii_detected),
                "pii_types": pii_types,
                "status": status,
                "toxicity_score": toxicity_score,
                "latency_ms": latency_ms
            }
            logs.insert_one(record)
            return
        except Exception as e:
            logger.error(f"Failed to log transaction to MongoDB: {str(e)}. Falling back to SQLite.")

    # SQLite Logging
    try:
        conn = sqlite3.connect("securesphere.db")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_logs (
                timestamp, user_id, prompt, sanitized_prompt, response, 
                model_used, pii_detected, pii_types, status, toxicity_score, latency_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp, user_id, logged_prompt, sanitized_prompt, logged_response,
                model_used, int(pii_detected), pii_types_str, status, toxicity_score, latency_ms
            )
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log transaction to SQLite: {str(e)}")


def get_recent_logs(limit: int = 50) -> list:
    """
    Retrieves the most recent audit logs for the dashboard.
    """
    if not db_use_sqlite and mongo_client:
        try:
            db = mongo_client[settings.MONGODB_DB_NAME]
            logs = list(db.audit_logs.find().sort("timestamp", -1).limit(limit))
            # Convert ObjectId to string for JSON serialization
            for log in logs:
                log["_id"] = str(log["_id"])
            return logs
        except Exception as e:
            logger.error(f"Failed to fetch logs from MongoDB: {str(e)}")

    # SQLite Fetch
    try:
        conn = sqlite3.connect("securesphere.db")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        
        logs = []
        for row in rows:
            log = dict(row)
            # Reformat list fields
            log["pii_detected"] = bool(log["pii_detected"])
            log["pii_types"] = log["pii_types"].split(",") if log["pii_types"] else []
            logs.append(log)
        return logs
    except Exception as e:
        logger.error(f"Failed to fetch logs from SQLite: {str(e)}")
        return []


def get_aggregate_stats() -> dict:
    """
    Computes summary metrics (counts, splits, latencies) for the Streamlit dashboard.
    """
    logs = get_recent_logs(1000)
    
    total = len(logs)
    if total == 0:
        return {
            "total_requests": 0,
            "blocked_requests": 0,
            "pii_detections": 0,
            "local_count": 0,
            "cloud_count": 0,
            "avg_latency": 0
        }
        
    blocked = sum(1 for log in logs if log["status"] == "BLOCK")
    pii = sum(1 for log in logs if log["pii_detected"])
    local = sum(1 for log in logs if "Local" in str(log["model_used"]))
    cloud = sum(1 for log in logs if "Cloud" in str(log["model_used"]))
    avg_latency = sum(log["latency_ms"] for log in logs) / total
    
    return {
        "total_requests": total,
        "blocked_requests": blocked,
        "pii_detections": pii,
        "local_count": local,
        "cloud_count": cloud,
        "avg_latency": round(avg_latency, 2)
    }
