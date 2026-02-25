"""Logging configuration for MicroPKI."""

import logging
import sys
from pathlib import Path
from typing import Optional


def setup_logger(log_file: Optional[str] = None) -> logging.Logger:
    """
    Configure and return a logger instance.

    Args:
        log_file: Optional path to log file. If None, logs go to stderr.

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger("micropki")
    logger.setLevel(logging.INFO)

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s.%(msecs)03d %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Add handler for stderr or file
    if log_file:
        # Create log directory if it doesn't exist
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        handler = logging.FileHandler(log_file)
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


def get_logger() -> logging.Logger:
    """Get the configured logger instance."""
    return logging.getLogger("micropki")