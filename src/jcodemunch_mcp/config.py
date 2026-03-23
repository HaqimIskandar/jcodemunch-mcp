"""Centralized JSONC config for jcodemunch-mcp."""

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Global config storage
_GLOBAL_CONFIG: dict[str, Any] = {}
_PROJECT_CONFIGS: dict[str, dict[str, Any]] = {}  # repo -> merged config

DEFAULTS = {
    "use_ai_summaries": True,
    "max_folder_files": 2000,
    "max_index_files": 10000,
    "staleness_days": 7,
    "max_results": 500,
    "extra_ignore_patterns": [],
    "extra_extensions": {},
    "context_providers": True,
    "meta_fields": None,  # None = all fields
    "languages": None,  # None = all languages
    "disabled_tools": [],
    "descriptions": {},
    "transport": "stdio",
    "host": "127.0.0.1",
    "port": 8901,
    "rate_limit": 0,
    "watch": False,
    "watch_debounce_ms": 2000,
    "freshness_mode": "relaxed",
    "claude_poll_interval": 5.0,
    "log_level": "WARNING",
    "log_file": None,
    "redact_source_root": False,
    "stats_file_interval": 3,
    "share_savings": True,
    "summarizer_concurrency": 4,
    "allow_remote_summarizer": False,
}

CONFIG_TYPES = {
    "use_ai_summaries": bool,
    "max_folder_files": int,
    "max_index_files": int,
    "staleness_days": int,
    "max_results": int,
    "extra_ignore_patterns": list,
    "extra_extensions": dict,
    "context_providers": bool,
    "meta_fields": (list, type(None)),
    "languages": (list, type(None)),
    "disabled_tools": list,
    "descriptions": dict,
    "transport": str,
    "host": str,
    "port": int,
    "rate_limit": int,
    "watch": bool,
    "watch_debounce_ms": int,
    "freshness_mode": str,
    "claude_poll_interval": float,
    "log_level": str,
    "log_file": (str, type(None)),
    "redact_source_root": bool,
    "stats_file_interval": int,
    "share_savings": bool,
    "summarizer_concurrency": int,
    "allow_remote_summarizer": bool,
}


def _strip_jsonc(text: str) -> str:
    """Strip // and /* */ comments from JSONC, respecting quoted strings."""
    result, i, n = [], 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            result.append(ch)
            if ch == '\\' and i + 1 < n:
                result.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
        elif ch == '"':
            in_str = True
            result.append(ch)
            i += 1
        elif ch == '/' and i + 1 < n and text[i + 1] == '/':
            # Line comment — skip to end of line
            end = text.find('\n', i)
            i = n if end == -1 else end
        elif ch == '/' and i + 1 < n and text[i + 1] == '*':
            # Block comment — skip to */
            end = text.find('*/', i + 2)
            i = n if end == -1 else end + 2
        else:
            result.append(ch)
            i += 1
    return ''.join(result)


def _validate_type(key: str, value: Any, expected_type: type | tuple) -> bool:
    """Validate value against expected type."""
    if isinstance(expected_type, tuple):
        return isinstance(value, expected_type)
    return isinstance(value, expected_type)


def load_config(storage_path: str | None = None) -> None:
    """Load global config.jsonc. Called once from main()."""
    global _GLOBAL_CONFIG

    # Determine config path
    if storage_path:
        config_path = Path(storage_path) / "config.jsonc"
    else:
        config_path = Path.home() / ".code-index" / "config.jsonc"

    # Load config if exists
    if config_path.exists():
        try:
            content = config_path.read_text(encoding="utf-8")
            stripped = _strip_jsonc(content)
            loaded = json.loads(stripped)

            # Type validation
            for key, value in loaded.items():
                if key in CONFIG_TYPES:
                    if _validate_type(key, value, CONFIG_TYPES[key]):
                        _GLOBAL_CONFIG[key] = value
                    else:
                        logger.warning(
                            f"Config key '{key}' has invalid type. "
                            f"Expected {CONFIG_TYPES[key]}, got {type(value).__name__}. Using default."
                        )
                        _GLOBAL_CONFIG[key] = DEFAULTS.get(key)
                # Ignore unknown keys silently
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse config.jsonc: {e}")
            _GLOBAL_CONFIG = DEFAULTS.copy()
        except Exception as e:
            logger.error(f"Failed to load config.jsonc: {e}")
            _GLOBAL_CONFIG = DEFAULTS.copy()
    else:
        _GLOBAL_CONFIG = DEFAULTS.copy()


def get(key: str, default: Any = None, repo: str | None = None) -> Any:
    """Get config value. If repo is given, uses merged project config."""
    if repo and repo in _PROJECT_CONFIGS:
        return _PROJECT_CONFIGS[repo].get(key, default)
    return _GLOBAL_CONFIG.get(key, default)
