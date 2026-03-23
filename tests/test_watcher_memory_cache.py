"""Tests for WatcherChange NamedTuple and watcher memory cache."""

import pytest
from pathlib import Path

from jcodemunch_mcp.reindex_state import WatcherChange


class TestWatcherChangeFormat:
    def test_watcher_change_properties(self):
        wc = WatcherChange("modified", "/path/to/file.py", "abc123")
        assert wc.change_type == "modified"
        assert wc.path == "/path/to/file.py"
        assert wc.old_hash == "abc123"

    def test_watcher_change_tuple_access(self):
        wc = WatcherChange("added", "/path/to/file.py", "")
        assert wc[0] == "added"
        assert wc[1] == "/path/to/file.py"
        assert wc[2] == ""

    def test_watcher_change_default_old_hash(self):
        wc = WatcherChange("added", "/path/to/file.py")
        assert wc.old_hash == ""


class TestWatcherMemoryCache:
    def test_watcher_change_with_old_hash(self):
        # Verify WatcherChange carries old_hash for memory cache
        wc = WatcherChange("modified", "/path/to/file.py", "old_hash_value")
        assert wc.old_hash == "old_hash_value"
        # The index_folder fast path should use old_hash to skip load_index
        assert wc.change_type == "modified"
        assert wc.path == "/path/to/file.py"
