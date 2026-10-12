#!/usr/bin/env python3
"""Yerscan Web Server Launcher.

Academic / Capstone Graduation Edition.
Starts the Uvicorn ASGI server hosting the Yerscan Web Platform.
"""

import argparse
import os
import sys
import uvicorn
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import yerscan as ys


def print_banner(host: str, port: int):
    is_root = ys.IS_ROOT
    mode_str = "ELEVATED (RAW SOCKET SYN/ACK/FIN UNLOCKED)" if is_root else "UNPRIVILEGED (SAFE TCP CONNECT MODE)"
    mode_color = "\033[92m" if is_root else "\033[96m"
    reset = "\033[0m"
    bold = "\033[1m"
    red = "\033[38;2;255;51;68m"
    white = "\033[97m"

    print(f"""
{red}{bold}
               ⬡
             /   \\
            /  ✔  \\
           /_______\\

       {white}P E N T R A X{red}
   WEB VULNERABILITY ASSESSMENT
{reset}
  {bold}Mode:{reset}           {mode_color}{mode_str}{reset}
  {bold}Engine:{reset}         Asyncio multi-phase scanner + Exploit-DB + MITRE ATT&CK
  {bold}Console URL:{reset}    {red}{bold}http://{host}:{port}{reset}
  {bold}API Docs:{reset}       http://{host}:{port}/api/system/capabilities

{white}Press Ctrl+C to terminate the server.{reset}
""")


def main():
    parser = argparse.ArgumentParser(
        description="Yerscan Web-Based Vulnerability & Network Scanner Platform"
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Host interface to bind to (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=8080, help="Port to bind to (default: 8080)"
    )
    parser.add_argument(
        "--reload", action="store_true", help="Enable automatic reload on code changes"
    )

    args = parser.parse_args()

    print_banner(args.host, args.port)

    uvicorn.run(
        "web.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
        access_log=False,
    )


if __name__ == "__main__":
    main()

