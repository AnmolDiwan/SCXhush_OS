#!/usr/bin/env python3
"""
One-command demo launcher for scx_hush.
Automatically opens default web browser and starts the interactive demo server.
"""

import time
import webbrowser
import threading
import uvicorn
from demo.server import app

def open_browser():
    time.sleep(1.2)
    print("[Launcher] Opening http://127.0.0.1:8080 in your default browser...")
    webbrowser.open("http://127.0.0.1:8080")

if __name__ == "__main__":
    t = threading.Thread(target=open_browser)
    t.daemon = True
    t.start()
    
    print("="*60)
    print("  🚀 scx_hush Live Interactive Visualizer is starting...")
    print("  🌐 Dashboard running at: http://127.0.0.1:8080")
    print("  🛑 Press Ctrl+C in terminal to stop anytime")
    print("="*60)
    
    uvicorn.run(app, host="127.0.0.1", port=8080, log_level="warning")
