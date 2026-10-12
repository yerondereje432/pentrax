"""Storage for the dashboard. The implementation lives in yerscan_store.py so the CLI and the
dashboard share one database; this module re-exports it for the web package."""

from yerscan_store import ACTIVE, CapacityError, Database, _host_row  # noqa: F401
