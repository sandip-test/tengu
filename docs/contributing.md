# Contributing to Tengu

Thank you for contributing to Tengu. This guide covers everything needed to get
your development environment set up, understand the code standards, pass the
security review, and submit a pull request.

---

## Development Setup

### 1. Fork and Clone

```bash
git clone https://github.com/YOUR_FORK/tengu.git
cd tengu
git remote add upstream https://github.com/tengu-project/tengu.git
```

### 2. Install Development Dependencies

```bash
# Install Python dependencies including dev extras
make install-dev

# Verify setup
make check  # runs lint + typecheck
make test   # runs unit + security tests
```

### 3. Install External Tools (Optional)

For integration tests or to test tool wrappers locally:

```bash
make install-tools
```

### 4. Configure for Local Development

```bash
# Create a local tengu.toml for development (never commit this)
cp tengu.toml tengu.local.toml
# Edit as needed for your lab environment
```

Set `TENGU_CONFIG_PATH=./tengu.local.toml` in your shell or test environment.

### 5. Verify Everything Works

```bash
make test-all
make check
make doctor
```

---

## Code Standards

### Language

All code, comments, docstrings, variable names, test names, and error messages
must be in **English**. No exceptions.

### File Structure

Every Python file must begin with:

```python
"""Module description."""

from __future__ import annotations
```

The `from __future__ import annotations` import is required in every file. It enables
PEP 604 union type syntax (`X | Y`) on Python 3.12 and prevents evaluation of
annotations at import time.

### Type Annotations

All functions require complete type annotations:

```python
def my_function(name: str, count: int = 0) -> list[str]:
    ...

async def my_async_function(ctx: Context, target: str) -> dict:  # type: ignore[type-arg]
    ...
```

Run `make typecheck` (mypy strict) before submitting. Zero type errors are required.

### Line Length

Maximum 100 characters. Enforced by ruff.

### Logging

```python
# Correct — structlog with keyword arguments
logger = structlog.get_logger(__name__)
logger.info("Scan started", target=target, tool="nmap")

# Wrong — standard logging or print
logging.info(f"Scan started for {target}")
print(f"Scan started for {target}")
```

### Pydantic v2

```python
# Correct
obj = MyModel.model_validate({"key": "value"})
data = obj.model_dump()

# Wrong (Pydantic v1 API)
obj = MyModel.parse_obj({"key": "value"})
data = obj.dict()
```

### Async

```python
# Correct
proc = await asyncio.create_subprocess_exec(*args, ...)

# Wrong
proc = subprocess.run(cmd, shell=True, ...)
proc = subprocess.Popen(cmd, shell=True, ...)
```

### Imports

Organize imports in this order (ruff enforces this):
1. `from __future__ import annotations`
2. Standard library imports
3. Third-party imports
4. Local imports

```python
from __future__ import annotations

import json
import re
from pathlib import Path

import structlog
from fastmcp import Context
from pydantic import BaseModel

from tengu.config import get_config
from tengu.security.sanitizer import sanitize_target
```

---

## Security Review Checklist

Every PR that adds or modifies tool code must pass this checklist before review.
The PR author is responsible for verifying each item.

### Input Handling
- [ ] All string parameters are passed through the appropriate `sanitize_*` function
      from `security/sanitizer.py` before use
- [ ] No raw user input is concatenated into command strings
- [ ] Integer and boolean parameters do not require sanitization (handled by Pydantic)
- [ ] Enum-like string parameters use `sanitize_scan_type(value, allowed=[...])` or
      Pydantic `Literal` types

### Target Validation
- [ ] All tools accepting a scan target call `allowlist.check(target)` before execution
- [ ] Blocked target attempts are logged: `await audit.log_target_blocked(...)`
- [ ] Tools that don't make network connections (analysis tools) document why no
      allowlist check is needed

### Subprocess Execution
- [ ] External processes use `run_command()` or `stream_command()` from
      `tengu.executor.process` — never `subprocess.run`, `os.system`, or `shell=True`
- [ ] Arguments are built as `list[str]` with separate elements per flag/value
- [ ] Tool path uses `resolve_tool_path(name, configured_path)` from the registry
- [ ] Timeout is respected: `effective_timeout = timeout or cfg.tools.defaults.scan_timeout`

### Audit Logging
- [ ] `await audit.log_tool_call(tool, target, params, result="started")` before run
- [ ] `await audit.log_tool_call(tool, target, params, result="completed", duration_seconds=...)` after success
- [ ] `await audit.log_tool_call(tool, target, params, result="failed", error=str(exc))` on exception
- [ ] Any new sensitive parameter names are added to `_SENSITIVE_KEYS` in `audit.py`

### Rate Limiting
- [ ] Active scan tools wrap subprocess execution in `async with rate_limited("tool_name")`
- [ ] Pure analysis tools (no network calls) are exempt and documented as such

### Progress Reporting
- [ ] `await ctx.report_progress(0, 100, "Starting...")` before long operations
- [ ] `await ctx.report_progress(100, 100, "Complete")` after completion
- [ ] Meaningful progress messages at key milestones

### Return Values
- [ ] Return type is `dict` (not Pydantic model — FastMCP cannot serialize those)
- [ ] Pydantic models are serialized with `.model_dump(mode="json")`
- [ ] Return dict includes `"tool"`, `"target"`, `"duration_seconds"` at minimum

### Tests
- [ ] New tool has unit tests in `tests/unit/test_<toolname>.py`
- [ ] New tool has security tests in `tests/security/test_command_injection.py`
- [ ] Parser function has tests for empty output, malformed output, and valid output
- [ ] Sanitizer is tested with at least a sample of `SHELL_INJECTION_PAYLOADS`
- [ ] `make test` passes with 0 failures
- [ ] `make lint` passes with 0 errors
- [ ] `make typecheck` passes with 0 errors

---

## Testing Requirements

### Test Structure

```
tests/
├── unit/
│   ├── __init__.py
│   ├── test_sanitizer.py    # sanitizer function tests
│   ├── test_allowlist.py    # allowlist matching tests
│   ├── test_rate_limiter.py # rate limiter tests
│   ├── test_config.py       # configuration tests
│   ├── test_analysis.py     # correlate/score tests
│   └── test_<toolname>.py   # your new tool tests
├── security/
│   ├── __init__.py
│   └── test_command_injection.py  # injection tests for ALL tools
└── integration/
    ├── __init__.py
    └── test_<toolname>_integration.py  # optional, requires tool installed
```

### Minimum Test Requirements Per Tool

1. **Parse function tests** — test with empty, valid, and malformed output
2. **Sanitization rejection test** — verify injection payloads are rejected
3. **Allowlist rejection test** — verify blocked targets are rejected
4. **Happy path test** (mocked) — verify the return dict structure

### Running Tests

```bash
make test           # unit + security (fast, no external tools)
make test-all       # all tests including integration
make test-security  # security/injection tests only
make coverage       # with HTML coverage report
```

### Test Configuration

Tests that need a specific config can use:

```python
import os
from tengu.config import reset_config

def setup_function():
    os.environ["TENGU_CONFIG_PATH"] = "/dev/null"  # force empty config
    reset_config()

def teardown_function():
    os.environ.pop("TENGU_CONFIG_PATH", None)
    reset_config()
```

---

## Pull Request Process

### Before Opening a PR

1. Sync with upstream:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. Verify all checks pass:
   ```bash
   make check    # lint + typecheck
   make test     # unit + security
   ```

3. Review the security checklist above and confirm each item.

### PR Title Format

Follow the Conventional Commits specification:

```
<type>(<scope>): <short description>

Types:
  feat      — new feature (new tool, resource, prompt)
  fix       — bug fix
  security  — security improvement (sanitizer, allowlist, audit)
  refactor  — code restructure without behavior change
  test      — new or improved tests
  docs      — documentation only
  chore     — build system, dependencies, tooling

Examples:
  feat(recon): add gobuster_fuzz directory scanning tool
  fix(allowlist): handle IPv6 addresses in CIDR matching
  security(sanitizer): add null byte to shell metacharacters regex
  test(nmap): add integration test for SYN scan
  docs(api-reference): document cve_search parameters
```

### PR Description Template

```markdown
## Summary

Brief description of what this PR changes and why.

## Changes

- Added `my_tool` in `src/tengu/tools/category/my_tool.py`
- Registered in `server.py`
- Added unit tests in `tests/unit/test_my_tool.py`
- Added injection tests in `tests/security/test_command_injection.py`

## Security Checklist

- [x] All inputs sanitized
- [x] Allowlist check before execution
- [x] No shell=True
- [x] Audit log entries: started, completed/failed
- [x] Rate limiting applied
- [x] Tests pass: make test
- [x] Lint passes: make lint
- [x] Types pass: make typecheck

## Testing Notes

How to test this change manually:
1. ...
2. ...
```

### Review Process

1. Automated checks must pass (lint, typecheck, tests).
2. At least one maintainer reviews the code for security concerns.
3. Security-sensitive changes (sanitizer, allowlist, audit, executor) require
   two maintainer reviews.
4. All review comments must be addressed before merge.

---

## Conventional Commits

Tengu follows the [Conventional Commits](https://www.conventionalcommits.org/) format.

```
<type>[optional scope]: <description>

[optional body]

[optional footer]
```

### Commit Examples

```bash
# New tool
git commit -m "feat(recon): add gobuster_fuzz directory scanning tool"

# Bug fix with details
git commit -m "fix(rate_limiter): release slot correctly when command raises exception

The rate_limited context manager was not releasing the concurrent slot
on exception because the release call was inside the try block rather
than in the __aexit__ method."

# Security improvement
git commit -m "security(sanitizer): add \\x00 null byte to shell metacharacters

Null bytes can be used to truncate strings in some contexts. Added to
_SHELL_METACHARACTERS regex and updated test_command_injection.py."

# Documentation
git commit -m "docs(api-reference): add complete parameter tables for all web tools"
```

---

## Getting Help

- **Bug reports**: Open a GitHub issue with the bug template.
- **Feature requests**: Open a GitHub issue with the feature template.
- **Security vulnerabilities**: Report privately via GitHub Security Advisories.
  Do not open public issues for security vulnerabilities.
- **Questions**: Open a GitHub Discussion.

---

## Code of Conduct

Tengu is a tool designed for **authorized** penetration testing only. Contributors
must not:
- Use Tengu or knowledge gained from the codebase for unauthorized scanning
- Add features designed to facilitate attacks on unauthorized targets
- Bypass or weaken the security controls (sanitizer, allowlist, audit, rate limiter)

Any contribution that weakens security controls will be rejected regardless of
other qualities.
