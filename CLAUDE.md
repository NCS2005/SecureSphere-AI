# SecureSphere-AI Project
## Project Description
SecureSphere-AI is a privacy-enhancing AI gateway designed to intercept, redact, encrypt, and secure sensitive information before it reaches cloud LLMs. It features an enterprise-grade Streamlit dashboard and a FastAPI backend.

## CKKS Design
The system uses TenSEAL for real Homomorphic Encryption (CKKS). Sensitive numerical data (like currency) is encrypted into `[CKKS_NUM_...]` tokens. The LLM performs operations using functions like `CKKS_SUM(a, b)` which are evaluated on the encrypted data by the backend, ensuring the LLM never sees the plaintext numbers. The LLM must be instructed to return the exact tokens with square brackets.

## Revert Switch / Fallback
If `tenseal` is unavailable, the system silently falls back to Affine numeric masking (a*x + b). The `NUMERIC_PRIVACY_MODE=ckks` environment variable controls this behavior (or affine for testing).

## Rules
- **DO NOT** change the core architecture (FastAPI gateway, Streamlit frontend, CKKS engine) without explicitly asking the user for permission.
- **DO NOT** modify the HE pipeline to leak plaintext data to the cloud.
- Ask for confirmation before implementing large refactors or rewiring vision detection.
