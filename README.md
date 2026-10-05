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

### 🔍 PII Detection & Pseudonymization
- Powered by **Microsoft Presidio** + **spaCy** + custom regex patterns (supporting Indian & global identifiers: Aadhaar, PAN cards, passport numbers, CVV codes, passwords, monetary values, emails, phone numbers).
- PII tokens replaced with deterministic **HMAC-SHA256 pseudonyms** — consistent across the session, reversible at response time.

### 🔒 Cryptographic Encryption & Masking
- **AES-256-GCM vault** for authenticated field-level encryption of sensitive values.
- **Affine Homomorphic Scalar Masking** ($S' = aS + b$) for numeric PII with verifiable inverse decoding.
- Full **deanonymization** on the response path — users see real values in replies.

### 🧠 Dual-Phase Policy & Jailbreak Guardrail
- Jailbreak and prompt-injection detection via regex scoring (DAN, persona overrides, exfiltration).
- Enterprise policy blocks: financial phishing, credential harvesting, card PIN exfiltration.

### 🔀 Intelligent Router
- **PII present** → routes to local **Ollama** model (air-gapped, zero data leakage).
- **Clean prompt** → routes to cloud LLM (**Gemini 2.5 Flash** or **OpenAI**).
- `MOCK_CLOUD=true` default option — runs offline or with live API keys.

### 🖼️ Multimodal Vision Guardrail
- Blurs faces and license plates in images before sending to multimodal LLMs.
- **MODE_A**: Blurs biometric regions (faces & license plates).
- **MODE_B**: Zero-Knowledge air-gap with document text black-boxing and vehicle plate redaction.
- Built on **OpenCV** heuristics with interactive custom navigation paste bar.

### ✅ Outbound Response Validation
- Output scanned via **toxic-bert** (or keyword fallback).
- Credential-leak redaction on all LLM responses.
- Audit log of every request/response pair.

### 📊 Security Operations Center (SOC) Dashboard
- **Streamlit** dashboard with live metrics: usage split, incidents, blocked prompts, full audit log.
- Custom navigation paste component with blinking cursor for direct `Ctrl+V` screenshot ingress.
- Incidents timeline, cryptographic verification studio, and policy trigger breakdown.

---

## Project Structure

```
securesphere-ai/
├── gateway/                  # FastAPI gateway & guardrail engines
│   ├── main.py               # Entry point & OpenAI-compatible endpoints
│   ├── pii_detector.py       # Presidio + spaCy + regex PII scanner
│   ├── policy_engine.py      # Dual-phase jailbreak & policy guardrail
│   ├── router.py             # Sensitivity-based routing engine
│   ├── response_validator.py # Outbound leak & toxicity classifier
│   ├── vision_detector.py    # OpenCV dual-mode biometric & text redactor
│   ├── config.py             # Environment configuration
│   └── database.py           # MongoDB & SQLite audit logger
├── dashboard/
│   ├── app.py                # Streamlit SOC Dashboard
│   └── components/           # Custom Streamlit UI components
│       └── nav_paste_bar/    # Navigation paste bar with blinking cursor
├── docker-compose.yml
├── requirements.txt
└── README.md
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
| Gateway | Python · FastAPI · Uvicorn |
| PII Detection | Microsoft Presidio · spaCy · Regex |
| Local LLM | Ollama (Llama 3.2) |
| Cloud LLM | Google Gemini 2.5 Flash · OpenAI API |
| Vision | OpenCV |
| Dashboard | Streamlit · Plotly |
| Audit DB | MongoDB · SQLite (fallback) |
| Containerization | Docker Compose |

---

## Quick Start (Local Run)

### Setup Steps
1. **Clone the directory**:
   ```bash
   git clone https://github.com/NCS2005/SecureSphere-AI.git
   cd SecureSphere-AI
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   python -m spacy download en_core_web_sm
   ```

3. **Configure environment variables**:
   ```bash
   cp .env.example .env
   ```

4. **Run the Gateway Server**:
   ```bash
   python -m uvicorn gateway.main:app --host 0.0.0.0 --port 8000
   ```

5. **Run the SOC Dashboard**:
   ```bash
   python -m streamlit run dashboard/app.py
   ```

---

## Run with Docker Compose

```bash
docker compose up --build
```

Access Points:
- **FastAPI Gateway**: `http://localhost:8000`
- **Streamlit Dashboard**: `http://localhost:8501`
- **MongoDB**: `mongodb://localhost:27017`

---

## Authors & Contributors

- **Nagarjuna Chaitanya Sandeep** ([NCS2005](https://github.com/NCS2005))
- **Y. Samuel Dan** ([samdan-honey](https://github.com/samdan-honey))
- **Rithika Chalva**

*B.E. CSE (Data Science) · MVSR Engineering College · Hyderabad*

---

## License

This project is for academic and research purposes.
