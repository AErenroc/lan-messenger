#!/usr/bin/env python3
"""
Top-level entry point to run the LAN Messenger server
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server.server import main

if __name__ == "__main__":
    main()