"""Structured logging setup for SheXzTool without sensitive data leakage."""

from __future__ import annotations
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


def setup_logging(
    log_dir: str = "logs",
    log_filename: str = "shexztool.log",
    level: str = "INFO",
    console_output: bool = False,
) -> logging.Logger:
    """Initialize structured logging.

    Logs to a rotating file in log_dir. Does not log passwords, keys, or raw tokens.
    """
    logger = logging.getLogger("shexztool")
    
    # Avoid duplicate handlers if called multiple times
    if logger.hasHandlers():
        return logger

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    full_log_file = log_path / log_filename

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        file_handler = RotatingFileHandler(
            full_log_file,
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(numeric_level)
        logger.addHandler(file_handler)
    except Exception:
        # Fallback to NullHandler if file cannot be created
        logger.addHandler(logging.NullHandler())

    if console_output:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.WARNING)  # Only warnings/errors to console
        logger.addHandler(console_handler)

    return logger
