import logging


class SensitiveAuthenticationLogFilter(logging.Filter):
    """Remove OIDC callback query data from Uvicorn access-log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3:
            path = str(args[2])
            if path.startswith("/auth/oidc/callback") and "?" in path:
                clean = list(args)
                clean[2] = path.split("?", 1)[0] + "?[redacted]"
                record.args = tuple(clean)
        return True


def install_sensitive_authentication_log_filter() -> None:
    logger = logging.getLogger("uvicorn.access")
    if not any(isinstance(item, SensitiveAuthenticationLogFilter) for item in logger.filters):
        logger.addFilter(SensitiveAuthenticationLogFilter())
