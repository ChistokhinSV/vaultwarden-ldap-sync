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

import gc
from collections import Counter

# Truthy values helper
YES_VALUES = ("1", "TRUE", "YES", "ON", "true", "yes", "on")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _setup_logging() -> logging.Logger:
    """Configure and return the application logger."""

    debug = os.getenv("DEBUG", "").upper() in YES_VALUES

    # Configure only the application logger, not the root logger
    app_logger = logging.getLogger("vaultwarden_ldap_sync")
    app_logger.setLevel(logging.DEBUG if debug else logging.INFO)
    
    # Prevent propagation to the root logger to avoid affecting other modules
    app_logger.propagate = False
    
    # Clear any existing handlers to avoid duplicate logs
    for h in list(app_logger.handlers):
        app_logger.removeHandler(h)

    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S %d.%m.%y",
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    console_handler.setFormatter(formatter)
    app_logger.addHandler(console_handler)

    return app_logger

logger = _setup_logging()

# ---------------------------------------------------------------------------
# Memory tracking
# ---------------------------------------------------------------------------

class ObjectTracker:
    def __init__(self):
        self.previous_counts = Counter()
    
    def track_growth(self):
        objectcount = gc.get_objects()
        current_counts = Counter(type(obj).__name__ for obj in objectcount)
        objects_of_type = [obj for obj in objectcount if type(obj).__name__ == "list"]
        
        if self.previous_counts:
            growth = {
                obj_type: current_counts[obj_type] - self.previous_counts[obj_type]
                for obj_type in current_counts
                if current_counts[obj_type] > self.previous_counts[obj_type]
            }
            
            # Show objects that grew by more than 100
            significant_growth = {k: v for k, v in growth.items() if v > 100}
            if significant_growth:
                logger.debug(f"Object count: {len(objectcount)}, object growth: {significant_growth}")
        
        self.previous_counts = current_counts

tracker = ObjectTracker()

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
            tracker.track_growth()
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
