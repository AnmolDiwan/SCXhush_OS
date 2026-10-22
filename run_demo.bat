@echo off
echo ========================================================
echo   Launching scx_hush Live Interactive Visualizer
echo   Storage Footprint: Less than 1 MB
echo ========================================================
echo.
start "" http://127.0.0.1:8080
python demo\server.py
pause
