# SecureSphere-AI 🛡️

**A private LLM gateway with AI guardrails — PII masking, policy enforcement, intelligent routing, and a real-time security dashboard.**

---

## Overview

SecureSphere-AI sits between your client applications and large language models, acting as an intelligent security layer. Every prompt is scanned for sensitive data and policy violations before it ever reaches a cloud LLM. When PII is detected, the request is rerouted to a local model — your data never leaves your machine.

```
Client App → [SecureSphere Gateway] → Local LLM (Ollama)  ← PII detected
                                    → Cloud LLM (Gemini/OpenAI) ← clean prompt
```

---

## Features

### 🔍 PII Detection
- Powered by **Microsoft Presidio** + **spaCy** + custom regex patterns
- Detects: Aadhaar numbers, PAN cards, passport numbers, CVV codes, passwords, monetary values, emails, phone numbers, and more
- PII tokens replaced with deterministic **HMAC-SHA256 pseudonyms** — consistent across the session, reversible at response time

### 🔒 Encryption & Masking
- **AES-256-GCM vault** for field-level encryption of sensitive values
- **Affine masking** for numeric PII (branded as homomorphic-style protection)
- Full **deanonymization** on the response path — users see real values in replies

### 🧠 Policy Engine
- Jailbreak and prompt-injection detection via regex scoring
- Enterprise policy blocks: financial phishing, credential harvesting, and more
- Configurable policy rules — extend for your org's compliance requirements

### 🔀 Intelligent Router
- **PII present** → routes to local **Ollama** model (air-gapped, zero data leakage)
- **Clean prompt** → routes to cloud LLM (**Gemini** or **OpenAI**)
- `MOCK_CLOUD=true` default — runs fully offline without real API keys

### 🖼️ Vision Module
- Blurs faces and license plates in images before sending to multimodal LLMs
- **MODE_A**: blurs biometric regions (faces)
- **MODE_B**: additionally black-boxes name/ID text regions on documents
- Built on **OpenCV** heuristics; **YOLOv8** available as an optional enhancer

### ✅ Response Validation
- Output scanned via **toxic-bert** (or keyword fallback)
- Credential-leak redaction on all LLM responses
- Audit log of every request/response pair

### 📊 Dashboard
- **Streamlit** dashboard with live metrics: usage split, incidents, blocked prompts, full audit log
- Custom image-paste component for multimodal testing
- Incident timeline and policy trigger breakdown

### 🗄️ Audit Logging
- Primary: **MongoDB** (port 27017)
- Fallback: local **SQLite** (`securesphere.db`) — works with zero infrastructure

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   SecureSphere Gateway                   │
│                    (FastAPI · port 8000)                 │
│                                                         │
│  Inbound Request                                        │
│       │                                                 │
│       ▼                                                 │
│  ┌─────────────┐    ┌────────────────┐                  │
│  │ PII Detector│───▶│ Policy Engine  │                  │
│  │ (Presidio + │    │ (jailbreak +   │                  │
│  │  spaCy +    │    │  enterprise    │                  │
│  │  regex)     │    │  rules)        │                  │
│  └─────────────┘    └───────┬────────┘                  │
│                             │                           │
│                             ▼                           │
│                    ┌────────────────┐                   │
│                    │    Router      │                   │
│                    │  PII? → Ollama │                   │
│                    │  Clean → Cloud │                   │
│                    └───────┬────────┘                   │
│                             │                           │
│                             ▼                           │
│                    ┌────────────────┐                   │
│                    │   Response     │                   │
│                    │   Validator    │                   │
│                    │ + Deanonymize  │                   │
│                    └───────┬────────┘                   │
│                             │                           │
│                             ▼                           │
│                    ┌────────────────┐                   │
│                    │  Audit Logger  │                   │
│                    │ MongoDB/SQLite │                   │
│                    └────────────────┘                   │
└─────────────────────────────────────────────────────────┘
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/chat/completions` | OpenAI-compatible chat endpoint |
| `POST` | `/generate` | Diagnostic text generation |
| `POST` | `/generate-multimodal` | Multimodal (text + image) generation |
| `POST` | `/anonymize-image` | Vision PII redaction only |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Gateway | Python · FastAPI |
| PII Detection | Microsoft Presidio · spaCy · custom regex |
| Local LLM | Ollama |
| Cloud LLM | Google Gemini · OpenAI API |
| Vision | OpenCV · YOLOv8 (optional) |
| Dashboard | Streamlit |
| Audit DB | MongoDB · SQLite (fallback) |
| Containerization | Docker Compose |

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.10+
- Ollama (for local LLM routing)

### Run with Docker Compose

```bash
git clone https://github.com/NCS2005/securesphere-ai.git
cd securesphere-ai

# Copy environment config
cp .env.example .env

# Start all services (gateway + dashboard + MongoDB)
docker compose up
```

Services started:
- **Gateway** → `http://localhost:8000`
- **Dashboard** → `http://localhost:8501`
- **MongoDB** → `localhost:27017`

> By default, `MOCK_CLOUD=true` — the gateway runs fully offline without real API keys.

### Run Locally (without Docker)

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg

# Start gateway
uvicorn gateway.main:app --host 0.0.0.0 --port 8000

# Start dashboard (separate terminal)
streamlit run dashboard/app.py
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MOCK_CLOUD` | `true` | Use mock cloud responses (no API key needed) |
| `GEMINI_API_KEY` | — | Google Gemini API key (for real cloud routing) |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Local Ollama endpoint |
| `MONGO_URI` | `mongodb://localhost:27017` | MongoDB connection string |

---

## Project Structure

```
securesphere-ai/
├── gateway/                  # FastAPI gateway
│   ├── main.py               # Entry point, route definitions
│   ├── pii_detector.py       # Presidio + spaCy + regex PII scanner
│   ├── policy_engine.py      # Jailbreak / enterprise policy checks
│   ├── router.py             # Local vs cloud LLM routing logic
│   ├── response_validator.py # Output toxicity check + credential redaction
│   ├── anonymizer.py         # HMAC pseudonymization + vault + affine masking
│   └── vision_detector.py    # OpenCV face/plate blur (MODE_A / MODE_B)
├── dashboard/
│   └── app.py                # Streamlit dashboard (~44KB)
├── gateway_backup_v1/        # Snapshot of gateway before current iteration
├── dashboard_backup_v1/      # Snapshot of dashboard before current iteration
├── securesphere.db           # SQLite audit log (auto-created if MongoDB unavailable)
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## Security Notes

- **PII pseudonymization** uses deterministic HMAC-SHA256 — tokens are consistent within a session and fully reversible.
- **Numeric masking** uses affine transformation (presented as homomorphic-style protection) — suitable for demonstrations and privacy-by-design architectures, not production cryptographic guarantees.
- **Vision PII blurring** uses OpenCV skin-tone and contour heuristics — effective for common cases; YOLOv8 integration available for production-grade detection.
- Audit logs capture every request/response pair. Treat the MongoDB instance and `securesphere.db` as sensitive assets.

---

## Roadmap

- [ ] Real homomorphic encryption integration (Microsoft SEAL / OpenFHE)
- [ ] YOLOv8 face/plate detection enabled by default
- [ ] Policy rule UI in dashboard
- [ ] Role-based access control on the gateway
- [ ] Prometheus metrics export
- [ ] Multi-tenant audit log support

---

## Author

**Nagarjuna Chaitanya Sandeep**  
**Y.Samuel Dan**
**Rithika Chalva**
B.E. CSE (Data Science) · MVSR Engineering College · Hyderabad  
GitHub: [NCS2005](https://github.com/NCS2005) · LinkedIn: [chaitanya-nagarjuna](https://linkedin.com/in/chaitanya-nagarjuna-3564302a8)

---

## License

This project is for academic and research purposes.
