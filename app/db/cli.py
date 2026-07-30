import logging

logger = logging.getLogger(__name__)


def configure_logging() -> None:
    root_logger = logging.getLogger()
    if not root_logger.handlers:
        logging.basicConfig(
            level=logging.INFO, format="%(levelname)s %(name)s: %(message)s"
        )
    else:
        root_logger.setLevel(logging.INFO)


def main() -> None:
    configure_logging()
    try:
        # Keep imports inside the fatal boundary so configuration, engine, and
        # model import failures are also emitted through the container logger.
        from app.core.config import get_settings
        from app.db.migrations import prepare_database
        from app.db.session import engine

        prepare_database(engine, get_settings())
    except Exception:
        logger.exception("Fatal database migration failure")
        # The traceback has one owner. Avoid the interpreter printing it again.
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
