# jcodemunch-mcp — Comprehensive Action Plan

Generated from a deep adversarial review of v1.4.4.
Each item includes: what is wrong, where it lives, why it matters, and the precise remediation direction.
Items are grouped by phase (urgency). Within each phase they are ranked by severity.

## Completion Status

- **Phase 1 (P1-1 through P1-6):** ALL DONE — shipped in v1.5.0
- **Phase 2 (P2-1 through P2-10):** ALL DONE — shipped in v1.5.0
- **Phase 3 (P3-1 through P3-10):** PENDING — Developer Experience and Trust
- **Phase 4 (P4-1 through P4-6):** PENDING — Excellence
- **Maintenance (M1 through M4):** PENDING — Ongoing process items

### What v1.5.0 shipped (Phase 1 + Phase 2)

| ID | What was done |
|----|---------------|
| P1-1 | ReDoS protection: nested quantifier regex + 200-char length cap in `search_text.py`; 3 tests in `test_hardening.py` |
| P1-2 | `tempfile.mkstemp()` replaces predictable `.json.tmp` in both `save_index` and `incremental_save` |
| P1-3 | `filelock` added to dependencies; `_lock_path()` method; `FileLock` wraps both save paths |
| P1-4 | Docstrings clarified: `follow_symlinks` only affects files, not directories (os.walk limitation) |
| P1-5 | HTTP transport deps (`uvicorn`, `starlette`, `anyio`) moved to `[http]` optional extra; try/except ImportError in server.py |
| P1-6 | `search_columns` and `get_context_bundle` added to README tools table + CLAUDE.md key files |
| P2-1 | Bounded heap search via `heapq` in `CodeIndex.search(limit=N)` — O(n log k) instead of O(n log n) |
| P2-2 | `.meta.json` sidecars for `list_repos`; two-pass listing (sidecar fast path, full JSON fallback) |
| P2-3 | `@functools.lru_cache(maxsize=16)` keyed on `(path, mtime_ns)` for `load_index`; `_invalidate_index_cache()` after saves |
| P2-4 | SSRF prevention: `_is_localhost_url()` check on `OPENAI_API_BASE` and `ANTHROPIC_BASE_URL`; `JCODEMUNCH_ALLOW_REMOTE_SUMMARIZER=1` override |
| P2-5 | Streaming file indexing: hash-only first pass, `_read_file()` re-reads on demand; peak memory ~500KB instead of ~1GB |
| P2-6 | Single source of truth: `_SKIP_DIRECTORY_NAMES`, `_SKIP_DIRECTORY_GLOBS`, `_SKIP_FILE_PATTERNS` derive all three exports |
| P2-7 | 7 tests in `tests/test_search_columns.py`: exact match, partial, model_pattern, multi-provider, no metadata, max_results, helper |
| P2-8 | 6 tests in `tests/test_get_context_bundle.py`: symbol source, imports, invalid ID, meta envelope, Python imports, Go block imports |
| P2-9 | `logger.warning` in all 3 summarizer fallback paths; `logger.debug(exc_info=True)` in index_store + token_tracker silent catches |
| P2-10 | `BaseSummarizer` base class with shared `_build_prompt`, `_parse_response`, `summarize_batch`; `_create_summarizer` returns `Optional[BaseSummarizer]` |

---

## Phase 1 — Stop the Bleeding ~~(Fix Before Next Release)~~ DONE (v1.5.0)

All 6 items completed and shipped.

---

### P1-1: ReDoS in `search_text` — CRITICAL

**File:** `src/jcodemunch_mcp/tools/search_text.py`, line 46

**What is wrong:**
```python
pattern = re.compile(query, re.IGNORECASE)
```
A client that passes `is_regex=True` with a catastrophic backtracking pattern like
`(a+)+b` or `(x+x+)+y` will lock the MCP server process in exponential backtracking
for seconds to minutes. Since the server is single-process and tool calls run in
`asyncio.to_thread`, a hung thread blocks that thread slot indefinitely. No watchdog
exists. There is no regex complexity check, no per-match timeout, and no per-file
match timeout. Python's `re` module does not protect against catastrophic backtracking.

**Why it matters:**
One bad regex (accidental or adversarial) permanently hangs the server until restart.
All other MCP calls queue behind the blocked event loop. This is a denial-of-service
against the MCP process itself.

**Remediation direction:**
1. Add a character-length cap on regex patterns before compiling (e.g., 200 chars).
2. On Python 3.11+, `re.compile` accepts no timeout natively, but you can run each
   `pattern.search(line)` call inside a `concurrent.futures.ThreadPoolExecutor` with
   `future.result(timeout=1.0)` per file, cancelling on timeout.
3. Alternatively, make `re2` an optional dependency and use it for the regex path —
   it provides linear-time guarantees.
4. At minimum, add a hard cap: `if len(query) > 500: return {"error": "Regex too long"}`.

**Test to add:**
`test_search_text_redos_rejected()` — submit `"(a+)+b"` with `is_regex=True`,
assert the call returns within 2 seconds (or returns an error, depending on chosen fix).

---

### P1-2: Predictable Temp File Name (Symlink Attack) — HIGH

**Files:**
- `src/jcodemunch_mcp/storage/index_store.py`, line 335 (in `save_index`)
- `src/jcodemunch_mcp/storage/index_store.py`, line 595 (in `incremental_save`)

**What is wrong:**
```python
tmp_path = index_path.with_suffix(".json.tmp")
with open(tmp_path, "w", encoding="utf-8") as f:
    json.dump(...)
tmp_path.replace(index_path)
```
The temp file is created with a fixed, predictable name in `~/.code-index/`. On POSIX
systems with a world-accessible `~/.code-index/` directory, a local attacker can pre-create
a symlink at that path (e.g., `local-myproject.json.tmp -> /home/victim/.ssh/authorized_keys`)
before the index write occurs. `open(tmp_path, "w")` follows the symlink and overwrites
the target with a JSON blob. The victim loses their SSH authorized_keys.

**Why it matters:**
On shared systems (CI runners, dev VMs, containers with multiple users), this is a credible
local privilege escalation / file destruction attack. The `~/.code-index/` directory is
created with default umask and has no access controls enforced by the server.

**Remediation direction:**
Replace both instances (lines 335-338 and 595-598) with:
```python
import tempfile
# Instead of:
tmp_path = index_path.with_suffix(".json.tmp")
with open(tmp_path, "w", encoding="utf-8") as f:
    json.dump(self._index_to_dict(index), f, indent=2)
tmp_path.replace(index_path)

# Use:
fd, tmp_name = tempfile.mkstemp(dir=index_path.parent, suffix=".json.tmp")
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(self._index_to_dict(index), f, indent=2)
    Path(tmp_name).replace(index_path)
except Exception:
    Path(tmp_name).unlink(missing_ok=True)
    raise
```
`tempfile.mkstemp` uses `O_CREAT | O_EXCL` semantics and an unpredictable suffix,
making symlink pre-creation attacks impossible.

---

### P1-3: Concurrent Index Write Race Condition — HIGH

**Files:**
- `src/jcodemunch_mcp/storage/index_store.py`, lines 501-598 (`incremental_save`)
- `src/jcodemunch_mcp/storage/index_store.py`, lines 280-351 (`save_index`)

**What is wrong:**
Both `save_index` and `incremental_save` follow a read-modify-write pattern with no
cross-process locking:
1. Load current index from disk (`load_index`)
2. Modify in memory
3. Write back atomically

Two concurrent MCP server instances (or two Claude clients running `index_folder` on
the same path simultaneously) will both load the same index, diverge, and then each
atomically overwrite the file. The last writer wins. The first writer's symbol extraction —
potentially hours of AI summarization — is silently discarded. There is no file lock,
no advisory lock, no in-process mutex scoped to the repo slug.

**Why it matters:**
Users who run two Claude instances against the same codebase (common in multi-agent
or split-terminal workflows) will silently corrupt their indexes. This is data loss,
not a crash — it is invisible until the user notices missing symbols.

**Remediation direction:**
Add a per-repo file-based advisory lock around the read-modify-write cycle:
```python
import fcntl  # POSIX; use filelock library for cross-platform

lock_path = index_path.with_suffix(".json.lock")
with open(lock_path, "w") as lock_file:
    fcntl.flock(lock_file, fcntl.LOCK_EX)
    try:
        # load → modify → write (existing code)
    finally:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
```
Or use the `filelock` library (cross-platform, works on Windows too):
```python
from filelock import FileLock
with FileLock(str(index_path.with_suffix(".json.lock"))):
    # load → modify → write
```
Add `filelock` to `pyproject.toml` dependencies.

**Test to add:**
`test_concurrent_save_no_data_loss()` — spin two threads that each call `save_index`
simultaneously on the same repo slug, assert that neither write is silently discarded
(both sets of symbols are present in the final index).

---

### P1-4: `follow_symlinks` Parameter Does Not Follow Directory Symlinks — HIGH

**Files:**
- `src/jcodemunch_mcp/tools/index_folder.py`, line 44
- `src/jcodemunch_mcp/tools/index_folder.py`, line 208
- `src/jcodemunch_mcp/server.py`, line 101-105 (schema description)

**What is wrong:**
The `follow_symlinks` parameter is described in the tool schema as:
> "Whether to follow symlinks. Default false for security."

Users reading this expect that `follow_symlinks=True` will traverse symlinked directories.
It does not. `get_filtered_files` always calls `os.walk(path, followlinks=False)` regardless
of the parameter. The parameter only controls whether individual symlink *files* are skipped
at line 208 (`if not follow_symlinks and file_path.is_symlink(): continue`). Symlinked
*directories* are never followed regardless of this setting.

**Why it matters:**
Users with monorepos using directory symlinks (common in Nx workspaces, pnpm workspaces,
and certain Go module setups) will pass `follow_symlinks=True`, see no error, and silently
miss entire subtrees of their codebase.

**Remediation direction:**
Either:
- Option A (fix): Pass `follow_symlinks` through to `get_filtered_files` and use
  `os.walk(path, followlinks=follow_symlinks)`. This requires also wiring the parameter
  through `discover_local_files` (currently not passed). Add a note that enabling this
  can cause infinite loops on circular symlinks.
- Option B (honest): Rename the parameter to `include_symlink_files` and update the
  schema description to accurately say "Whether to include symlink files (not directories).
  Directory symlinks are never followed." Keep the existing behavior but don't misname it.

---

### P1-5: `uvicorn`, `starlette`, `anyio` Are Undeclared Runtime Dependencies — HIGH

**Files:**
- `src/jcodemunch_mcp/server.py`, lines 632, 668-670 (imports inside `run_sse_server` and `run_streamable_http_server`)
- `pyproject.toml` — these packages are absent from `dependencies`

**What is wrong:**
When a user runs `jcodemunch-mcp --transport sse` or `--transport streamable-http`,
the server imports `uvicorn`, `starlette`, and `anyio` at runtime. None of these are
listed in `pyproject.toml`'s `dependencies`. A user who installed via
`pip install jcodemunch-mcp` and then runs with `--transport sse` gets an `ImportError`
with no guidance. These are v1.3.1 features that have been broken on clean installs
since they shipped.

**Remediation direction:**
Add a new optional extras group to `pyproject.toml`:
```toml
[project.optional-dependencies]
http = ["uvicorn>=0.20.0", "starlette>=0.27.0", "anyio>=4.0.0"]
```
Document the install in README:
```
# For HTTP transport modes:
pip install "jcodemunch-mcp[http]"
```
Also add a helpful `ImportError` message inside the `run_sse_server` and
`run_streamable_http_server` functions that prints the install command when the import fails.

---

### P1-6: Two Production Tools Are Completely Undocumented — HIGH

**Files:**
- `src/jcodemunch_mcp/tools/search_columns.py` — fully functional, ships in binary
- `src/jcodemunch_mcp/tools/get_context_bundle.py` — fully functional, ships in binary
- `src/jcodemunch_mcp/server.py`, lines 371-415 — both registered in `list_tools()`
- README.md — neither tool mentioned
- CLAUDE.md — neither tool mentioned

**What is wrong:**
Both tools are registered with `list_tools()` and callable by any MCP client right now.
`search_columns` has its own undocumented env var (`JCODEMUNCH_MAX_RESULTS`, line 52 of
`search_columns.py`). `get_context_bundle` provides a symbol + imports bundle for AI context.
Neither appears in the README tool reference, version history, or CLAUDE.md key files list.
Users who discover them through MCP tool enumeration have no documentation.

**Why it matters:**
Undocumented shipped tools look like incomplete work to evaluators. They can't be tested
by the community. Any breakage goes unreported because users don't know the tools exist.
They represent hidden capability that reduces adoption.

**Remediation direction:**
For each tool, add to README.md:
- Tool name, one-line description
- Input parameters and types
- Example call and example response
- Prerequisites (e.g., `search_columns` requires a dbt/SQLMesh indexed project)
- Associated env vars

Add both to CLAUDE.md "Key Files" section.
Add both to version history with the version they were introduced.
Add at least one test per tool (see P2-7 and P2-8 below).

---

## Phase 2 — Production Hardening — DONE (v1.5.0)

All 10 items completed and shipped.

---

### P2-1: Unbound O(n log n) Sort on Every Symbol Search — CRITICAL (Performance)

**File:** `src/jcodemunch_mcp/storage/index_store.py`, lines 84-99

**What is wrong:**
```python
def search(self, query: str, kind=None, file_pattern=None) -> list[dict]:
    scored = []
    for sym in self.symbols:          # iterate ALL symbols, no early exit
        score = self._score_symbol(...)
        if score > 0:
            scored.append((score, sym))
    scored.sort(key=lambda x: x[0], reverse=True)  # sort ALL matches
    return [sym for _, sym in scored]               # return ALL matches
```
The tool-layer cap (`max_results=10` or `100`) is applied *after* this returns.
For a 100K-symbol index with a one-letter query matching 60K symbols:
- 100K iterations with scoring
- 60K-entry tuple list built in memory
- O(60K log 60K) sort
- Then truncated to 10 results

At current growth rates (jcodemunch indexes large monorepos), 100K symbols is realistic.

**Why it matters:**
Memory allocation for 60K `(int, dict)` tuples can easily exceed 50-100MB per search call.
Latency scales superlinearly with repo size. This is a performance cliff, not a gradual
degradation — the user experiences sudden, unexplained slowness when indexing a large repo.

**Remediation direction:**
Replace the sort with a bounded heap that caps memory at `max_results` items:
```python
import heapq

def search(self, query: str, kind=None, file_pattern=None, limit: int = 100) -> list[dict]:
    heap = []  # min-heap of (score, counter, sym)
    counter = 0
    for sym in self.symbols:
        if kind and sym.get("kind") != kind:
            continue
        if file_pattern and not self._match_pattern(sym.get("file", ""), file_pattern):
            continue
        score = self._score_symbol(sym, query_lower, query_words)
        if score > 0:
            heapq.heappush(heap, (score, counter, sym))
            counter += 1
            if len(heap) > limit:
                heapq.heappop(heap)  # evict lowest score
    # Sort remaining items descending
    return [sym for _, _, sym in sorted(heap, key=lambda x: x[0], reverse=True)]
```
Pass `limit = max_results * 2` (a small buffer) from the tool layer to `CodeIndex.search()`.

---

### P2-2: `list_repos()` Deserializes Full Index JSON for Summary Data — HIGH (Performance)

**File:** `src/jcodemunch_mcp/storage/index_store.py`, lines 626-657

**What is wrong:**
```python
for index_file in self.base_path.glob("*.json"):
    with open(index_file, "r", encoding="utf-8") as f:
        data = json.load(f)   # loads ENTIRE JSON including symbols array
    symbol_count = len(data.get("symbols", []))  # then discards symbols
```
For a user with 10 indexed repos, each with 20K symbols and 500KB index files,
`list_repos()` deserializes 10 × 500KB = 5MB of JSON just to display a summary table.
The `symbols` array (the bulk of the data) is immediately discarded after `len()`.

**Why it matters:**
`list_repos()` is called frequently (often the first thing an AI agent does). Its latency
scales with the total size of all index files, not the number of repos. This is O(total_data)
for an O(num_repos) operation.

**Remediation direction:**
Write a companion metadata sidecar file (`slug.meta.json`) alongside each index file during
`save_index()` and `incremental_save()` containing only the summary fields:
```json
{
  "repo": "owner/name",
  "indexed_at": "...",
  "symbol_count": 1234,
  "file_count": 56,
  "languages": {"python": 40, "javascript": 16},
  "index_version": 4,
  "display_name": "...",
  "source_root": "..."
}
```
`list_repos()` reads only the `*.meta.json` files. If a `*.meta.json` is missing (old
index), fall back to loading the full JSON for that one file.

---

### P2-3: No Process-Level Index Cache — HIGH (Performance)

**File:** `src/jcodemunch_mcp/storage/index_store.py`, lines 357-406

**What is wrong:**
`load_index()` opens and deserializes the index JSON from disk on every call. There is no
in-memory cache. Every tool call (`search_symbols`, `search_text`, `get_file_outline`,
`find_importers`, etc.) calls `load_index()` at least once, sometimes twice (e.g.,
`get_symbol_content` which calls `load_index` internally if `_index` is not passed).
For a 200KB index file, disk I/O + JSON deserialization adds 10-50ms to every call.

**Why it matters:**
An agent doing 20 sequential tool calls pays 20 × deserialization cost. This is
unnecessary — the index is immutable during a tool call sequence and changes only
when `index_folder`, `index_repo`, or `incremental_save` runs.

**Remediation direction:**
Add a module-level LRU cache keyed on `(slug, mtime)`:
```python
import functools

@functools.lru_cache(maxsize=8)
def _load_index_cached(index_path: str, mtime: float) -> Optional[CodeIndex]:
    ...

def load_index(self, owner: str, name: str) -> Optional[CodeIndex]:
    path = self._index_path(owner, name)
    if not path.exists():
        return None
    mtime = path.stat().st_mtime
    return _load_index_cached(str(path), mtime)
```
The `mtime` key invalidates the cache automatically when the index file changes.
Write operations must call `_load_index_cached.cache_clear()` after saving.

---

### P2-4: `OPENAI_API_BASE` Is an Unchecked SSRF Vector — HIGH (Security)

**File:** `src/jcodemunch_mcp/summarizer/batch_summarize.py`, lines 327-391

**What is wrong:**
```python
self.api_base = os.environ.get("OPENAI_API_BASE")
...
response = self.client.post(f"{self.api_base}/chat/completions", json=payload)
```
The payload sent to `OPENAI_API_BASE` includes `sym.kind`, `sym.signature`, and
`sym.ecosystem_context` for every symbol in each batch. Anyone who can set the
`OPENAI_API_BASE` environment variable (or control a `.env` file sourced into the
process) can point this at any HTTP endpoint and silently receive all code signatures
during indexing. All exceptions are swallowed with `except Exception: pass`, so there
is no user-visible indication that exfiltration is occurring. The `OPENAI_API_KEY`
value (defaulting to `"local-llm"`) is also sent as a Bearer token to this endpoint.

**Why it matters:**
This is a Server-Side Request Forgery (SSRF) vector with data exfiltration. An attacker
with environment access receives code signatures from every indexed file, silently.
Enterprise environments with strict data handling policies will flag this immediately.

**Remediation direction:**
1. At `OpenAIBatchSummarizer.__post_init__`, validate that `OPENAI_API_BASE` is a
   localhost URL (starts with `http://127.0.0.1`, `http://localhost`, or `http://[::1]`).
2. If a non-localhost URL is set, require an explicit override env var:
   `JCODEMUNCH_ALLOW_REMOTE_SUMMARIZER=1`. Without it, log a security warning and skip
   the OpenAI summarizer.
3. Log the resolved endpoint (hostname only, not the full URL) at INFO level on startup
   when the OpenAI summarizer is active.
4. Add similar validation for `ANTHROPIC_BASE_URL` (line 68 of `batch_summarize.py`).

---

### P2-5: Full Index Path Loads All File Contents Into RAM Before Parsing — MEDIUM (Reliability)

**File:** `src/jcodemunch_mcp/tools/index_folder.py`, lines 384-401

**What is wrong:**
```python
current_files: dict[str, str] = {}
for file_path in source_files:
    with open(file_path, ...) as f:
        content = f.read()
    current_files[rel_path] = content  # ALL files in memory at once
# Only then: parse each file
```
For a 2,000-file project with average 100KB files, this allocates ~200MB of in-memory
strings before a single symbol is parsed. The `max_files=2000` cap and `max_file_size=500KB`
cap create a worst-case of 1GB pre-allocated before parsing begins.

**Why it matters:**
Docker containers with 512MB memory limits will OOM silently. CI runners with restricted
RAM will fail. The user sees a generic crash with no explanation.

**Remediation direction:**
Process files in streaming fashion — read, parse, discard source content (keep only symbols
and file hash), then move to the next file:
```python
for file_path in source_files:
    try:
        with open(file_path, ...) as f:
            content = f.read()
    except Exception as e:
        warnings.append(...)
        continue
    rel_path = ...
    symbols = parse_file(content, rel_path, language)
    all_symbols.extend(symbols)
    file_hashes[rel_path] = _file_hash(content)
    raw_files[rel_path] = content  # kept for save_index; could be streamed separately
```
The `raw_files` dict for `save_index` is the binding constraint — consider writing raw
content directly to the content directory during parsing rather than accumulating in RAM.

---

### P2-6: Consolidate Skip Pattern Lists (`SKIP_PATTERNS` vs `SKIP_DIRECTORIES`/`SKIP_FILES`) — MEDIUM

**File:** `src/jcodemunch_mcp/security.py`, lines 136-160

**What is wrong:**
Three separate data structures define what to skip:
- `SKIP_PATTERNS` (frozenset, line 136) — used by `index_repo.py`
- `SKIP_DIRECTORIES` (list of strings/regexes, line 149) — used by `index_folder.py`
- `SKIP_FILES` (list, line 157) — used by `index_folder.py`

These are not aliases. `"migrations/"` appears in `SKIP_PATTERNS` but not `SKIP_DIRECTORIES`,
meaning `index_repo` skips migrations but `index_folder` does not. This behavioral
divergence between local and remote indexing is not documented as intentional.
Updating one requires manually checking and updating the others — which maintainers
demonstrably have not done consistently.

**Remediation direction:**
Define a single canonical structure (e.g., a list of `(name, applies_to_dirs, applies_to_files)`
tuples or a dataclass) that serves as the source of truth. Generate `SKIP_PATTERNS`,
`SKIP_DIRECTORIES`, and `SKIP_FILES` from it programmatically. Add a code comment
documenting any intentional differences between local and remote skipping behavior.

---

### P2-7: No Tests for `search_columns` — HIGH

**What is wrong:**
`search_columns` is a production-shipped tool with no test coverage. It has its own
scoring logic, model pattern filtering, multi-provider dispatch, and token savings
calculation. None of this is tested. Regression risk is high.

**Tests to add in `tests/test_search_columns.py`:**
- `test_search_columns_exact_match()` — query matching exact column name returns score=30
- `test_search_columns_partial_match()` — query substring in column name
- `test_search_columns_model_pattern_filter()` — `model_pattern="fact_*"` filters correctly
- `test_search_columns_multi_provider()` — index with both `dbt_columns` and `sqlmesh_columns`
  keys, verify `source` field appears in results when >1 provider
- `test_search_columns_no_metadata()` — repo with no `context_metadata` returns helpful error
- `test_search_columns_max_results_cap()` — result count respects `max_results`

---

### P2-8: No Tests for `get_context_bundle` — HIGH

**What is wrong:**
`get_context_bundle` is a production-shipped tool with no test coverage. It retrieves
a symbol's full source plus all import statements from the same file — a non-trivial
data assembly operation.

**Tests to add in `tests/test_get_context_bundle.py`:**
- `test_context_bundle_includes_symbol_source()` — returned bundle contains symbol code
- `test_context_bundle_includes_imports()` — returned bundle contains file's import lines
- `test_context_bundle_invalid_symbol_id()` — returns graceful error, not a crash
- `test_context_bundle_meta_envelope()` — `_meta` is present with expected fields

---

### P2-9: Pervasive Exception Swallowing With No Logging — MEDIUM

**Files:**
- `src/jcodemunch_mcp/summarizer/batch_summarize.py`, lines 132, 257, 405
- `src/jcodemunch_mcp/storage/index_store.py`, line 653
- `src/jcodemunch_mcp/storage/token_tracker.py`, line 110

**What is wrong:**
At least 20+ `except Exception: pass` or `except Exception: continue` blocks silently
swallow errors with no log output. Key examples:
- AI summarizer `_summarize_one_batch` at lines 132, 257, 405: API auth failures,
  rate limits, quota exhaustion, network errors → all silent, falls back to signature.
  Users have no visibility into whether AI summarization is actually working.
- `list_repos()` at line 653: corrupted index files silently skipped, repo disappears
  from listing without explanation.
- Token tracker file write at line 110: savings data silently lost if disk is full.

**Why it matters:**
Operators cannot distinguish between "AI summarization working normally" and "AI
summarization has been silently failing for 3 days due to an expired API key."

**Remediation direction:**
Add `logger.debug("...", exc_info=True)` (or `logger.warning` for recoverable errors
like API failures) inside every `except Exception` that currently has no log output.
For the AI summarizer paths specifically, add a `logger.warning("AI summarization
failed, falling back to signature: %s", e)` so the fallback is observable.

---

### P2-10: `_build_prompt` Is Triplicated Across Three Summarizer Classes — MEDIUM

**File:** `src/jcodemunch_mcp/summarizer/batch_summarize.py`

**What is wrong:**
`_build_prompt` (the method that constructs the AI summarization prompt) is copy-pasted
identically across:
- `BatchSummarizer._build_prompt` (lines 138-169)
- `GeminiBatchSummarizer._build_prompt` (lines 262-293)
- `OpenAIBatchSummarizer._build_prompt` (lines 410-441)

`_parse_response` is also copy-pasted across all three classes with a subtle divergence:
- `BatchSummarizer._parse_response` line 127: `if summary: sym.summary = summary`
- `GeminiBatchSummarizer._parse_response` line 309: `summaries[num-1] = parts[1].strip()`
  (no empty-string guard — a divergence that silently assigns empty strings)

The return type annotation of `_create_summarizer` (line 464) is `Optional[BatchSummarizer]`
but the function can return `GeminiBatchSummarizer` or `OpenAIBatchSummarizer` — neither
of which is a subclass of `BatchSummarizer`. This is a type lie.

**Remediation direction:**
Extract an abstract base class or protocol:
```python
class BaseSummarizer:
    def summarize_batch(self, symbols: list[Symbol], batch_size: int = 10) -> list[Symbol]: ...
    def _build_prompt(self, symbols: list[Symbol]) -> str: ...  # shared implementation
    def _parse_response(self, text: str, expected_count: int) -> list[str]: ...  # shared
    def _summarize_one_batch(self, batch: list[Symbol]): ...  # abstract
```
Fix the `GeminiBatchSummarizer._parse_response` to add the empty-string guard.
Fix `_create_summarizer` return type to `Optional[BaseSummarizer]`.

---

## Phase 3 — Developer Experience and Trust

These items eliminate credibility gaps, documentation holes, and platform coverage gaps
that prevent enterprise adoption and community confidence.

---

### P3-1: Benchmark Methodology Is Underspecified — HIGH (Product Credibility)

**File:** `benchmarks/` directory (contents), `README.md`

**What is wrong:**
The README references "Express ~58×, FastAPI ~100×, Gin ~66×" token efficiency numbers.
jMunchWorkbench README mentions "96% retrieval precision." Neither the repo root README
nor the benchmarks directory contains:
- Which version of each framework was benchmarked
- Which specific queries were used
- How "token savings" was computed (the code uses a byte-approximation: `(raw - response) / 4`,
  not actual tokenizer output — this can deviate by 2× for code-heavy content)
- Whether AI summaries were on or off during benchmarking
- How "retrieval precision" was defined and measured
- What dataset or queries were used to arrive at 96%
- A reproducible script to regenerate the numbers

**Why it matters:**
Enterprise procurement reviewers and technical evaluators will immediately ask for
reproducibility. Unsubstantiated benchmark claims actively undermine credibility with
exactly the audience the project is trying to convert.

**Remediation direction:**
Create `benchmarks/METHODOLOGY.md` documenting:
- Exact repos and commits used
- Exact queries run
- Token counting method (byte approximation with `_BYTES_PER_TOKEN = 4`) and its
  limitations vs. actual tokenizer output
- How to reproduce using jMunchWorkbench
- The definition of "retrieval precision" and how it was evaluated
Add a prominent link to jMunchWorkbench in the README for self-service verification.

---

### P3-2: Token Savings Are Estimates Presented as Measurements — MEDIUM (Product Credibility)

**Files:**
- `src/jcodemunch_mcp/storage/token_tracker.py`, line 30: `_BYTES_PER_TOKEN = 4`
- `src/jcodemunch_mcp/tools/search_text.py`, lines 87-120
- README.md and all marketing materials

**What is wrong:**
Every `_meta` envelope returns `tokens_saved` computed as `(raw_bytes - response_bytes) / 4`.
This is explicitly a byte-approximation (`_BYTES_PER_TOKEN = 4` — "rough but consistent").
Real tokenization depends on model family (GPT-4 Turbo vs. Claude 3 Haiku tokenize
code differently) and content type (assembly tokenizes differently than Python prose).
The approximation could be off by 30-50% in either direction for specific languages.

Additionally, `search_text` computes `raw_bytes` from `os.path.getsize()` of every
*searched* file, including files with no matches. A query matching 1 file out of 1,000
claims credit for avoiding 999 files' worth of reads — even though those reads were never
requested. This systematically overstates savings by `files_searched / files_with_matches`.

**Why it matters:**
Presenting estimates as measurements is a credibility risk in technical communities
and a compliance risk in enterprise sales.

**Remediation direction:**
1. Label all savings values in `_meta` as `"tokens_saved_estimate"` (or add an
   `"estimate_method": "byte_approx"` field to `_meta`).
2. Fix `search_text` raw_bytes to count only files that yielded at least one match
   (move `raw_bytes += os.path.getsize(full_path)` to after `if file_matches:`).
3. Consider adding `tiktoken` as an optional dep for actual GPT token counting,
   and the Anthropic SDK's token counting for Claude counts.
4. Add a disclaimer to the README: "Token savings figures are byte-based estimates;
   actual savings vary by model tokenizer and content type."

---

### P3-3: `search_symbols` `kind` Enum Is Incomplete and Not Enforced — MEDIUM (API)

**File:** `src/jcodemunch_mcp/server.py`, line 255

**What is wrong:**
The `kind` parameter enum in the tool schema lists:
```json
["function", "class", "method", "constant", "type"]
```
The parsers emit additional kinds not in this list: `"field"` (struct fields), `"label"`
(assembly labels), `"section"` (assembly sections and CSS), `"macro"` (assembly macros),
`"attribute"`, `"module"`, `"struct"`, `"enum"`, `"interface"`. A client that calls
`search_symbols(kind="module")` receives an empty result set or unexpected behavior
because the schema suggests "module" is not a valid kind. The enum is also not enforced
server-side — invalid kind values are passed through to `CodeIndex.search()` where they
simply match nothing.

**Remediation direction:**
1. Audit all parser outputs for every emitted `kind` value (check `extractor.py`
   and all language-specific parsers).
2. Update the enum in `server.py` to include all actually-emitted kinds.
3. Define a `KindEnum` constant (frozenset or Literal type) in `parser/symbols.py`
   that is the single source of truth.
4. Add server-side validation: if `kind` is provided but not in `KindEnum`, return
   `{"error": "Unknown kind '...'. Valid values: [...]"}`.

---

### P3-4: Add Windows to CI Matrix — MEDIUM (Testing)

**File:** `.github/workflows/test.yml`, line 12

**What is wrong:**
CI runs only `ubuntu-latest`. The project has a documented history of Windows-specific
bugs (issues #68 and #74) that were caught only after production reports. All
Windows-specific fixes (`stdin=subprocess.DEVNULL` for git subprocess, `os.walk(followlinks=False)`
for NTFS junctions, the `follow_symlinks` handling) are untested in CI.

**Remediation direction:**
Add `windows-latest` to the CI matrix:
```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest]
    python-version: ["3.10", "3.11", "3.12"]
runs-on: ${{ matrix.os }}
```
Note: Windows CI requires attention to path separator handling in test fixtures
(use `Path` objects rather than string literals with `/`).

---

### P3-5: Add Python 3.13 to CI Matrix — LOW (Packaging)

**File:** `.github/workflows/test.yml`, line 14

**What is wrong:**
Python 3.13 was released October 2024. The CI matrix covers only 3.10-3.12.
`tree-sitter-language-pack` and `pathspec` may have 3.13 compatibility issues that
would go undetected until users report them.

**Remediation direction:**
Add `"3.13"` to the `python-version` matrix. Run on Ubuntu only initially to
minimize CI time; if green, add to Windows matrix too.

---

### P3-6: Add Incremental Index Upgrade Test — HIGH (Testing)

**What is wrong:**
There are no tests that verify the version upgrade path:
1. Create an index at schema version N-1 (e.g., a v3 index without the `imports` field)
2. Load it with the current server (v4)
3. Verify all symbols, file hashes, and new-version fields are correctly handled

The version upgrade path is entirely untested. Any regression here would cause users
to silently receive incomplete indexes after upgrading the package.

**Test to add in `tests/test_index_store.py`:**
```python
def test_load_v3_index_without_imports():
    """Verify v3 index (no imports field) loads correctly under v4 server."""
    # Create a v3-format JSON fixture (imports field absent)
    # Load via store.load_index()
    # Assert: index.imports is None (not {} or an error)
    # Assert: symbols load correctly
    # Assert: incremental_save works on the loaded v3 index
```

---

### P3-7: Add Troubleshooting Guide — MEDIUM (Documentation)

**What is wrong:**
There is no troubleshooting section in the README or a standalone `TROUBLESHOOTING.md`.
Common failure scenarios have no guidance:
- "No source files found" — how to diagnose which skip reason is triggering
  (check `discovery_skip_counts` in the response)
- AI summarization silently not working (API key set but optional package not installed)
- GitHub rate limit errors during `index_repo` (403 with no guidance to set GITHUB_TOKEN)
- `find_importers`/`find_references` return empty results (requires re-indexing with v1.3.0+)
- `search_columns` returns "No column metadata found" (requires dbt/SQLMesh project)
- Why indexes created on one machine are not portable to another (absolute `source_root`)
- Windows-specific behavior (NTFS junctions, stdin pipe issues)

**Remediation direction:**
Create `TROUBLESHOOTING.md` with a section per failure scenario, including:
- Symptom (what the user sees)
- Cause (why it happens)
- Fix (what to do)
Link from README.

---

### P3-8: `has_source_file` Returns True for Empty `source_files` — LOW (Correctness)

**File:** `src/jcodemunch_mcp/storage/index_store.py`, line 77

**What is wrong:**
```python
def has_source_file(self, file_path: str) -> bool:
    return not self.source_files or file_path in self._source_file_set
```
When `source_files` is empty (corrupted index, freshly-initialized index not yet populated,
or an edge case in index construction), this returns `True` for any `file_path`. Callers
that use this to gate content reads (e.g., `get_file_content`) will proceed even when
the file is not indexed, then fail silently on the content read.

**Remediation direction:**
```python
def has_source_file(self, file_path: str) -> bool:
    return file_path in self._source_file_set
```
If callers need "no files indexed yet" to be treated as "everything is allowed,"
that logic should live in the caller, not in this method. Add a test for the empty
case to prevent regression.

---

### P3-9: HTTP Transport Has No Authentication — HIGH (Security)

**File:** `src/jcodemunch_mcp/server.py`, lines 628-705

**What is wrong:**
The SSE and streamable-http transports bind to `127.0.0.1:8901` with no authentication.
Any process on localhost can call `index_folder(path="/sensitive/dir")` to cache the
full source of any path the server user can read, or `invalidate_cache(repo="...")` to
destroy indexes. On Docker bridge networks, any container on the bridge can reach this.
On development machines with multiple users, any local user can issue arbitrary tool calls.

**Remediation direction:**
Add optional bearer token authentication:
```python
JCODEMUNCH_HTTP_TOKEN = os.environ.get("JCODEMUNCH_HTTP_TOKEN")
# In request handlers: check Authorization header
# If JCODEMUNCH_HTTP_TOKEN is set and header doesn't match, return 401
```
Document: "When using HTTP transport, set JCODEMUNCH_HTTP_TOKEN to a secret value
and configure your MCP client to send that token."
This is opt-in to avoid breaking existing deployments.

---

### P3-10: `source_root` Absolute Path Exposed in MCP Responses — LOW (Security/Privacy)

**Files:**
- `src/jcodemunch_mcp/tools/index_folder.py`, line 580
- `src/jcodemunch_mcp/storage/index_store.py`, lines 648-651

**What is wrong:**
`source_root` stores the absolute local filesystem path (e.g., `/home/alice/projects/myapp`)
in the index. `list_repos()` exposes this in every repo listing. Any MCP client (including
the AI model) can learn the absolute filesystem path of every indexed local folder.
In agentic contexts, this gives the AI model filesystem context it never explicitly requested.

**Remediation direction:**
Add `JCODEMUNCH_REDACT_SOURCE_ROOT=1` env var. When set, replace `source_root` in all
MCP responses with the folder's `display_name` or an empty string. Keep the absolute path
in the stored index (needed for `validate_path` operations) but redact it from serialized
tool responses.

---

## Phase 4 — Excellence and Category Leadership

These items transform the project from "very good" to "definitively best-in-class."

---

### P4-1: Actual Token Counting Instead of Byte Approximation — MEDIUM

**File:** `src/jcodemunch_mcp/storage/token_tracker.py`, line 30

**What is wrong:**
`_BYTES_PER_TOKEN = 4` is a rough constant that doesn't account for tokenizer differences
between models, or for the fact that code (especially with long identifiers, template
literals, or non-ASCII characters) tokenizes very differently than prose.

**Remediation direction:**
Add optional actual token counting via `tiktoken` (for GPT-family models) and
Anthropic's token counting API (for Claude). When these are available, report
`tokens_saved_actual` alongside `tokens_saved_estimate`. Make the actual count
opt-in (adds latency) via `JCODEMUNCH_ACCURATE_TOKEN_COUNTS=1`.

---

### P4-2: Index Integrity Checksums — MEDIUM

**File:** `src/jcodemunch_mcp/storage/index_store.py`

**What is wrong:**
There is no integrity check on index files. A tampered, corrupted, or hand-edited
index is accepted silently. An attacker who can write to `~/.code-index/` can poison
the `file_hashes` dict to make incremental indexing skip re-parsing, or inject malicious
`summary` text that gets served to the AI model.

**Remediation direction:**
On `save_index`, compute a SHA-256 of the serialized JSON and store it in a sidecar
`slug.json.sha256`. On `load_index`, verify the checksum before deserializing.
If the checksum fails, log a warning and return `None` (triggering a full re-index).

---

### P4-3: Schema Validation on Index Load — MEDIUM

**File:** `src/jcodemunch_mcp/storage/index_store.py`, lines 357-406

**What is wrong:**
Index JSON is loaded without schema validation. A corrupt or future-format index can
produce `KeyError` or `TypeError` deep inside tool logic, producing confusing errors
rather than "index is corrupt, please re-index."

**Remediation direction:**
Use `pydantic` (already a transitive dep via `mcp`) or a minimal `jsonschema` validation
at load time. Validate that required top-level fields are present and have correct types
before constructing `CodeIndex`. Return `None` with a clear log message on validation failure.

---

### P4-4: GitHub API Rate Limit Handling — LOW

**File:** `src/jcodemunch_mcp/tools/index_repo.py`, lines 51-73

**What is wrong:**
`fetch_repo_tree` calls `response.raise_for_status()` which on a 403/429 produces an
`httpx.HTTPStatusError` with the message "Client error '403 Forbidden'." There is no
retry logic, no backoff, no parsing of the `Retry-After` header, and no user-friendly
message explaining that this is a GitHub rate limit and the fix is to set `GITHUB_TOKEN`.

**Remediation direction:**
Catch `httpx.HTTPStatusError` in `index_repo`. If status is 403 or 429:
1. Parse the `Retry-After` header if present.
2. Retry with exponential backoff (max 3 attempts).
3. If still failing, return `{"error": "GitHub rate limit exceeded. Set GITHUB_TOKEN env var for 5000 req/hr limit."}`.

---

### P4-5: Resolve `[dev]` / `[test]` Dependency Group Duplication — LOW

**File:** `pyproject.toml`, lines 20 and 40-44

**What is wrong:**
```toml
[project.optional-dependencies]
test = ["pytest", "pytest-asyncio", "pytest-cov"]

[dependency-groups]
dev = [
    "pytest>=9.0.2",
    "pytest-asyncio>=1.3.0",
    "pytest-cov>=7.0.0",
]
```
The same packages appear in both `[project.optional-dependencies] test` and
`[dependency-groups] dev` with different (and potentially conflicting) version pins.
This creates confusion about which group to install and could cause dependency resolution
conflicts.

**Remediation direction:**
Remove `[project.optional-dependencies] test`. Keep only `[dependency-groups] dev`
with pinned versions. Update CI to use `uv sync --group dev` or `pip install -e ".[dev]"`.
The `test` extras group was an older pattern; `dependency-groups` is the uv-native approach.

---

### P4-6: Add `uv.lock` to CI for Reproducible Builds — LOW

**Note:** A `uv.lock` file was observed in the repository root. Ensure CI uses it:

**File:** `.github/workflows/test.yml`

**What is wrong:**
CI installs with `pip install -e ".[dev]"` which resolves live from PyPI. The `uv.lock`
file exists but CI doesn't use it. A dependency that introduces a breaking change will
fail CI with no code change on the project's part.

**Remediation direction:**
Switch CI to use `uv`:
```yaml
- name: Install uv
  uses: astral-sh/setup-uv@v3
- name: Install dependencies
  run: uv sync --group dev
- name: Run tests
  run: uv run pytest tests/ -v --tb=short
```
This uses `uv.lock` for reproducible installs.

---

## Ongoing / Maintenance

These are not one-time fixes but practices to adopt permanently.

---

### M1: Document Every Shipped Tool Before Merging

**Practice:** Any PR that adds a new tool to `server.py` must simultaneously update:
1. README.md (tool reference section)
2. CLAUDE.md (Key Files section)
3. Version history with the version it ships in
4. At least one test covering the happy path

**Rationale:** `search_columns` and `get_context_bundle` shipped without documentation.
This must not happen again.

---

### M2: Version History Must Be in Ascending Order

**File:** `CLAUDE.md`, version history table (lines 143-174)

**What is wrong:**
Version entries are not in ascending chronological order. 1.3.2 appears after 1.4.4,
1.4.3, and 1.4.2. This makes the changelog confusing to read.

**Fix:** Sort the table in ascending version order. Add a note at top: "New versions go
at the bottom." Or reverse to descending (newest first) and be consistent.

---

### M3: Add Debug Logging for Every Silent Exception

**Practice:** Every `except Exception:` block that currently has no logging must emit
at minimum `logger.debug("...", exc_info=True)`. For user-facing fallbacks (AI
summarizer failing, index file unreadable), emit `logger.warning(...)`.

**Rationale:** Silent failures are invisible to operators and make production debugging
impossible. This is the single highest-leverage observability improvement available.

---

### M4: FLUSH_INTERVAL Documentation Fix

**File:** `src/jcodemunch_mcp/storage/token_tracker.py`

**What is wrong:**
- Module docstring (line 16): "every FLUSH_INTERVAL calls (default 3)"
- `record_savings` docstring (line 183): "every 10 calls"
- Actual constant: `_FLUSH_INTERVAL = 3` (line 32)

Two docstrings disagree. One is wrong. Fix the `record_savings` docstring to say
"every FLUSH_INTERVAL calls (currently 3)."

---

## Summary Checklist

| ID | Phase | Severity | Item | Status |
|----|-------|----------|------|--------|
| P1-1 | 1 | CRITICAL | ReDoS in `search_text` | DONE v1.5.0 |
| P1-2 | 1 | HIGH | Predictable temp file (symlink attack) | DONE v1.5.0 |
| P1-3 | 1 | HIGH | Concurrent index write race | DONE v1.5.0 |
| P1-4 | 1 | HIGH | `follow_symlinks` doesn't follow dirs | DONE v1.5.0 |
| P1-5 | 1 | HIGH | uvicorn/starlette/anyio undeclared | DONE v1.5.0 |
| P1-6 | 1 | HIGH | Two tools undocumented (`search_columns`, `get_context_bundle`) | DONE v1.5.0 |
| P2-1 | 2 | CRITICAL | O(n log n) sort on every symbol search | DONE v1.5.0 |
| P2-2 | 2 | HIGH | `list_repos` loads full JSON per repo | DONE v1.5.0 |
| P2-3 | 2 | HIGH | No index cache (deserialize on every call) | DONE v1.5.0 |
| P2-4 | 2 | HIGH | SSRF via `OPENAI_API_BASE` | DONE v1.5.0 |
| P2-5 | 2 | MEDIUM | Full file contents loaded to RAM before parsing | DONE v1.5.0 |
| P2-6 | 2 | MEDIUM | Skip pattern lists are divergent | DONE v1.5.0 |
| P2-7 | 2 | HIGH | No tests for `search_columns` | DONE v1.5.0 |
| P2-8 | 2 | HIGH | No tests for `get_context_bundle` | DONE v1.5.0 |
| P2-9 | 2 | MEDIUM | Exception swallowing without logging | DONE v1.5.0 |
| P2-10 | 2 | MEDIUM | Summarizer code triplicated + type lie | DONE v1.5.0 |
| P3-1 | 3 | HIGH | Benchmark methodology missing | PENDING |
| P3-2 | 3 | MEDIUM | Token savings presented as measurements | PENDING |
| P3-3 | 3 | MEDIUM | `kind` enum incomplete and not enforced | PENDING |
| P3-4 | 3 | MEDIUM | No Windows CI | PENDING |
| P3-5 | 3 | LOW | No Python 3.13 in CI | PENDING |
| P3-6 | 3 | HIGH | No incremental index upgrade test | PENDING |
| P3-7 | 3 | MEDIUM | No troubleshooting guide | PENDING |
| P3-8 | 3 | LOW | `has_source_file` returns True for empty list | PENDING |
| P3-9 | 3 | HIGH | HTTP transport has no authentication | PENDING |
| P3-10 | 3 | LOW | `source_root` exposes absolute paths in responses | PENDING |
| P4-1 | 4 | MEDIUM | Byte approximation for token counting | PENDING |
| P4-2 | 4 | MEDIUM | No index integrity checksums | PENDING |
| P4-3 | 4 | MEDIUM | No schema validation on index load | PENDING |
| P4-4 | 4 | LOW | No GitHub rate limit retry | PENDING |
| P4-5 | 4 | LOW | `[dev]`/`[test]` dep group duplication | PENDING |
| P4-6 | 4 | LOW | CI doesn't use `uv.lock` | PENDING |
| M1 | ongoing | — | Document every tool before shipping | PENDING |
| M2 | ongoing | — | Version history ascending order | PENDING |
| M3 | ongoing | — | Log every silent exception | MOSTLY DONE (P2-9 covered key files; M3 asks for codebase-wide sweep) |
| M4 | ongoing | — | Fix FLUSH_INTERVAL docstring contradiction | PENDING |
