FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download spaCy NLP model
RUN python -m spacy download en_core_web_sm

# Copy the rest of the application
COPY . .

# Expose ports
EXPOSE 8000
EXPOSE 8501
