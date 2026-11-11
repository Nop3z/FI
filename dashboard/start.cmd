@echo off
rem 启动 FI Dashboard 只读看板（双击即可）。已在运行则直接打开浏览器。
setlocal
cd /d "%~dp0\.."

rem 检查 8765 是否已在监听
netstat -ano | findstr /r /c:"127.0.0.1:8765 .*LISTENING" >nul 2>&1
if %errorlevel%==0 (
  echo 看板已在运行，直接打开 http://127.0.0.1:8765
  start "" http://127.0.0.1:8765
  exit /b 0
)

echo 正在启动 FI Dashboard...
start "FI Dashboard" /min cmd /c "python dashboard\app.py"
timeout /t 3 /nobreak >nul
start "" http://127.0.0.1:8765
echo 已打开 http://127.0.0.1:8765
