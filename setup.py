#!/usr/bin/env python3
"""Setup script: downloads vendored assets required by the live demo."""
import shutil
from pathlib import Path

def setup_plotly():
    dest = Path(__file__).parent / "demo" / "static" / "plotly.min.js"
    if dest.exists():
        print(f"[setup] plotly.min.js already present at {dest}")
        return
    try:
        import plotly
        src = Path(plotly.__file__).parent / "package_data" / "plotly.min.js"
        if src.exists():
            shutil.copy2(src, dest)
            print(f"[setup] Copied plotly.min.js ({src.stat().st_size // 1024} KB) -> {dest}")
        else:
            print(f"[setup] ERROR: plotly package found but plotly.min.js not at {src}")
            print("       Try: pip install plotly --force-reinstall")
    except ImportError:
        print("[setup] ERROR: plotly not installed. Run: pip install plotly")

if __name__ == "__main__":
    setup_plotly()
    print("[setup] Done. You can now run: python run_demo.py")
