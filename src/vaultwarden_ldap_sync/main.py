"""VaultWarden-LDAP Sync entrypoint.

Currently only sets up logging and exposes an empty ``main`` function.
Further logic will be introduced in subsequent steps.
"""
import os
import logging
import sys
import time

from vaultwarden_ldap_sync.config import Config
from vaultwarden_ldap_sync.sync_engine import run_sync

# Truthy values helper
YES_VALUES = ("1", "TRUE", "YES", "ON", "true", "yes", "on")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging() -> logging.Logger:
    """Configure and return the application logger."""

    debug = os.getenv("DEBUG", "").upper() in YES_VALUES

    # Clear any existing handlers (e.g. those added by libraries) to avoid duplicates
    root_logger = logging.getLogger()
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

    root_logger.setLevel(logging.DEBUG if debug else logging.INFO)

    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S %d.%m.%y",
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Application logger inherits the root handler – return it for convenience
    return logging.getLogger("vaultwarden_ldap_sync")

logger = setup_logging()


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    """Run the VaultWarden-LDAP sync engine once or in a loop."""
    cfg = Config()
    interval = int(os.getenv("SYNC_INTERVAL", "60"))
    max_failures = int(os.getenv("MAX_CONSECUTIVE_FAILURES", "5"))
    run_once = os.getenv("RUN_ONCE", "0").strip().upper() in YES_VALUES

    logger.info("Starting sync (interval=%ss, run_once=%s, max_failures=%s)", interval, run_once, max_failures)

    failures = 0

    while True:
        try:
            run_sync(cfg)
            failures = 0  # reset on success
        except Exception:  # noqa: BLE001
            failures += 1
            logger.exception("Sync cycle failed (consecutive failures: %s)", failures)
            if failures >= max_failures:
                logger.critical("Exceeded MAX_CONSECUTIVE_FAILURES (%s), exiting", max_failures)
                sys.exit(1)
        if run_once:
            break
        time.sleep(interval)

    logger.info("Sync finished, exiting")


if __name__ == "__main__":
    main()
