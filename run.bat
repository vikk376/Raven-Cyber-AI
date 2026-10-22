@echo off
cd /d "%~dp0"
if not exist .venv py -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install -q -r requirements.txt
python -m streamlit run app.py --server.port 8501
