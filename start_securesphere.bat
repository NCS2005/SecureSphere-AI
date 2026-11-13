@echo off
cd /d "%~dp0"
echo [1/3] Installing dependencies (first time can take a few minutes)...
python -m pip install -r requirements.txt
echo [2/3] Starting gateway on http://localhost:8000 (this PC only) ...
start "SecureSphere Gateway" cmd /k python -m uvicorn gateway.main:app --host 127.0.0.1 --port 8000
echo [3/3] Starting dashboard on http://localhost:8501 (this PC only) ...
start "SecureSphere Dashboard" cmd /k python -m streamlit run dashboard/app.py --server.address 127.0.0.1
echo Done. Close the two new windows to stop SecureSphere-AI.
pause
