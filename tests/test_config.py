"""Tests for JSONC config parsing."""

import tempfile
from pathlib import Path

import pytest

from src.jcodemunch_mcp.config import _strip_jsonc


class TestJSONCParser:
    """Test JSONC comment stripping."""

    def test_strips_line_comments(self):
        """Should strip // comments to end of line."""
        text = '{"key": "value" // this is a comment\n}'
        result = _strip_jsonc(text)
        assert result == '{"key": "value" \n}'

    def test_strips_line_comment_no_trailing_newline(self):
        """Should strip // comment at end of file."""
        text = '{"key": "value"} // comment'
        result = _strip_jsonc(text)
        assert result == '{"key": "value"} '

    def test_strips_block_comments(self):
        """Should strip /* */ block comments."""
        text = '{"key" /* comment */: "value"}'
        result = _strip_jsonc(text)
        assert result == '{"key" : "value"}'

    def test_strips_multiline_block_comments(self):
        """Should strip multiline /* */ comments."""
        text = '''{
    "key": "value" /* this is
    a multiline
    comment */
}'''
        result = _strip_jsonc(text)
        assert '"key"' in result
        assert 'this is' not in result

    def test_preserves_strings_with_comment_chars(self):
        """Should not strip // or /* inside quoted strings."""
        text = '{"url": "http://example.com", "note": "use /* here*/"}'
        result = _strip_jsonc(text)
        assert result == text  # Should be unchanged


class TestConfigDefaults:
    """Test default config values."""

    def test_default_max_folder_files(self):
        """Should default to 2000 max folder files."""
        from src.jcodemunch_mcp.config import DEFAULTS
        assert DEFAULTS["max_folder_files"] == 2000

    def test_default_max_index_files(self):
        """Should default to 10000 max index files."""
        from src.jcodemunch_mcp.config import DEFAULTS
        assert DEFAULTS["max_index_files"] == 10000

    def test_default_languages_is_none(self):
        """Should default to None (all languages enabled)."""
        from src.jcodemunch_mcp.config import DEFAULTS
        assert DEFAULTS["languages"] is None

    def test_default_disabled_tools_is_empty(self):
        """Should default to empty list (all tools enabled)."""
        from src.jcodemunch_mcp.config import DEFAULTS
        assert DEFAULTS["disabled_tools"] == []


class TestConfigLoading:
    """Test config file loading."""

    def test_missing_file_uses_defaults(self, monkeypatch):
        """Should use defaults when config file doesn't exist."""
        from src.jcodemunch_mcp.config import load_config, get, _GLOBAL_CONFIG

        # Clear any existing config
        _GLOBAL_CONFIG.clear()

        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            non_existent = Path(tmpdir) / "nonexistent" / "config.jsonc"
            monkeypatch.setenv("CODE_INDEX_PATH", str(Path(tmpdir) / "nonexistent"))

            load_config(str(Path(tmpdir) / "nonexistent"))

            assert get("max_folder_files") == 2000
            assert get("use_ai_summaries") is True
