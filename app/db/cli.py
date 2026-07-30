import argparse
import logging
import sys
from collections.abc import Sequence

logger = logging.getLogger(__name__)


def configure_logging() -> None:
    root_logger = logging.getLogger()
    if not root_logger.handlers:
        logging.basicConfig(
            level=logging.INFO, format="%(levelname)s %(name)s: %(message)s"
        )
    else:
        root_logger.setLevel(logging.INFO)


def main(argv: Sequence[str] = ()) -> None:
    configure_logging()
    try:
        # Keep imports inside the fatal boundary so configuration, engine, and
        # model import failures are also emitted through the container logger.
        from app.core.config import get_settings
        from app.db.migrations import prepare_database
        from app.db.session import engine
        from app.db.validation import (
            QUICK_CHECK_TIMEOUT_SECONDS,
            validate_sqlite_integrity,
        )

        parser = argparse.ArgumentParser(description="Prepare or diagnose Kaya's database")
        parser.add_argument(
            "--quick-check",
            action="store_true",
            help="run explicit strict SQLite quick_check diagnostics instead of startup preparation",
        )
        parser.add_argument(
            "--quick-check-timeout",
            type=float,
            default=QUICK_CHECK_TIMEOUT_SECONDS,
            metavar="SECONDS",
        )
        arguments = parser.parse_args(argv)
        if arguments.quick_check_timeout <= 0:
            parser.error("--quick-check-timeout must be greater than zero")

        settings = get_settings()
        if arguments.quick_check:
            from app.core.config import sqlite_database_path

            database_path = sqlite_database_path(settings.database_url)
            if database_path is None:
                raise RuntimeError("Strict quick_check requires a file-backed SQLite database")
            logger.info(
                "Running explicit strict SQLite quick_check with timeout %.0fs",
                arguments.quick_check_timeout,
            )
            validate_sqlite_integrity(
                database_path,
                quick_check_timeout_seconds=arguments.quick_check_timeout,
            )
            logger.info("Explicit strict SQLite quick_check completed successfully")
            return

        prepare_database(engine, settings)
    except Exception:
        logger.exception("Fatal database migration failure")
        # The traceback has one owner. Avoid the interpreter printing it again.
        raise SystemExit(1) from None


if __name__ == "__main__":
    main(sys.argv[1:])
