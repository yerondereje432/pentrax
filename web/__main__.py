"""Entry point for `python3 -m web`.

Starts the FastAPI dashboard with uvicorn. The password comes from YERSCAN_WEB_PASSWORD and must be
at least 12 characters, otherwise the server refuses to start (a weak/dummy password would let anyone
on the loopback control the scanner).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.app import Settings, create_app  # noqa: E402


def main():
    settings = Settings.from_env()
    if not settings.password or len(settings.password) < 12:
        sys.stderr.write(
            "YERSCAN_WEB_PASSWORD must be set to a value of at least 12 characters "
            "(the dashboard requires a password).\n"
        )
        sys.exit(2)

    app = create_app(settings)
    import uvicorn

    print(f"  yerscan dashboard  →  http://{settings.host}:{settings.port}")
    print(f"  database: {settings.db_path}")
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
