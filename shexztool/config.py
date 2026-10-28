"""Configuration management for SheXzTool.

Loads defaults, allows safe overrides, and provides validated paths.
"""

from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG_PATH = Path("config.default.json")
USER_CONFIG_PATH = Path("config.json")

logger = logging.getLogger("shexztool.config")


def get_base_dir() -> Path:
    """Return the absolute path of the SheXzTool workspace directory."""
    return Path(__file__).resolve().parent.parent


def load_config() -> Dict[str, Any]:
    """Load configuration from config.json if present, otherwise config.default.json.

    Falls back to safe built-in defaults if neither exists.
    """
    base = get_base_dir()
    user_file = base / USER_CONFIG_PATH
    default_file = base / DEFAULT_CONFIG_PATH

    config: Dict[str, Any] = {}

    if default_file.exists():
        try:
            with open(default_file, "r", encoding="utf-8") as f:
                config = json.load(f)
        except Exception as e:
            logger.warning("Could not read default config: %s", e)

    if user_file.exists():
        try:
            with open(user_file, "r", encoding="utf-8") as f:
                user_overrides = json.load(f)
                _deep_update(config, user_overrides)
        except Exception as e:
            logger.warning("Could not read user config overrides: %s", e)

    # Ensure required baseline directories exist
    for dir_key, default_folder in [
        ("reporting.output_dir", "reports"),
        ("fim.baseline_dir", "baselines"),
        ("logging.log_dir", "logs"),
    ]:
        folder_path = base / default_folder
        folder_path.mkdir(parents=True, exist_ok=True)

    return config


def save_user_config(config_data: Dict[str, Any]) -> bool:
    """Safely save user configuration overrides to config.json."""
    base = get_base_dir()
    user_file = base / USER_CONFIG_PATH
    try:
        with open(user_file, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)
        return True
    except Exception as e:
        logger.error("Failed to write user config: %s", e)
        return False


def _deep_update(target: Dict[str, Any], source: Dict[str, Any]) -> None:
    """Recursively update nested dictionaries."""
    for key, value in source.items():
        if isinstance(value, dict) and key in target and isinstance(target[key], dict):
            _deep_update(target[key], value)
        else:
            target[key] = value
