@echo off
setlocal
cd /d "%~dp0"
if exist "%LocalAppData%\Programs\Python\Python314\python.exe" (
  "%LocalAppData%\Programs\Python\Python314\python.exe" app.py
  goto done
)
py -3 --version >nul 2>&1
if not errorlevel 1 (
  py -3 app.py
  goto done
)
python --version >nul 2>&1
if not errorlevel 1 (
  python app.py
  goto done
)
echo Python was not found. Open app.py in VS Code and use Run Python File.
:done
pause
