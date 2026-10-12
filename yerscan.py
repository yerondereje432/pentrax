#!/usr/bin/env python3
"""Compatibility shim redirecting to pentrax.py.

Preserves backward compatibility for CLI commands and integrations
while PENTRAX v8.0 serves as the primary offensive security engine.
"""

import sys
from pathlib import Path

# Ensure ROOT_DIR in sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from pentrax import *

if __name__ == "__main__":
    main()
