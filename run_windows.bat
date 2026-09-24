@echo off
cd /d "%~dp0"
if not exist venv\Scripts\python.exe (
  echo Creating virtual environment...
  python -m venv venv
)
call venv\Scripts\activate.bat
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python app.py
pause
