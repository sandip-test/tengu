# Changelog

All notable changes to Tengu are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Tengu uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] — v0.2.0

### Planned
- SSE transport support for remote MCP connections (macOS → Kali VM)
- PDF report generation via WeasyPrint
- Stealth mode configuration (randomized timing, decoy IPs)
- Plugin system for custom tool wrappers
- Web UI dashboard for audit log visualization
- Async CVE cache with NVD API v2 rate limit handling
- Docker image with all tools pre-installed
- GitHub Actions CI/CD pipeline

---

## [0.1.0] — 2026-02-28

Initial release of Tengu — a FastMCP-based MCP server providing an intelligent
abstraction layer over industry-standard pentesting tools.

### Added

#### Core Infrastructure
- FastMCP 2.0+ server instance (`FastMCP("Tengu")`) registered in `src/tengu/server.py`
- Pydantic v2 configuration model (`TenguConfig`) with `tengu.toml` parsing and
  environment variable overrides (`TENGU_CONFIG_PATH`, `TENGU_LOG_LEVEL`, `NVD_API_KEY`)
- Structured logging via `structlog` with JSON output and ISO timestamps
- Custom exception hierarchy: `TenguError`, `TargetNotAllowedError`, `ToolNotFoundError`,
  `ToolExecutionError`, `ScanTimeoutError`, `RateLimitError`, `InvalidInputError`,
  `ConfigError`, `MetasploitConnectionError`, `ZAPConnectionError`
- Shared Pydantic models in `types.py`: `Port`, `Host`, `ScanResult`, `SubdomainResult`,
  `DNSRecord`, `DNSResult`, `WhoisResult`, `SecurityHeader`, `HeaderAnalysisResult`,
  `CORSResult`, `SSLResult`, `Evidence`, `Finding`, `PentestReport`, `RiskMatrix`,
  `CVSSMetrics`, `CVERecord`, `ToolStatus`, `ToolsCheckResult`

#### Security Layer (5 layers)
- **Sanitizer** (`security/sanitizer.py`): `sanitize_target`, `sanitize_url`,
  `sanitize_domain`, `sanitize_cidr`, `sanitize_port_spec`, `sanitize_wordlist_path`,
  `sanitize_hash`, `sanitize_cve_id`, `sanitize_free_text`, `sanitize_scan_type`,
  `sanitize_severity`. Shell metacharacter regex: `[;&|` + "`$<>(){}[]!\\'\"\\r\\n]`
- **Allowlist** (`security/allowlist.py`): `TargetAllowlist` with CIDR, wildcard,
  and exact hostname matching. Default blocked hosts: localhost, metadata endpoints,
  `*.gov`, `*.mil`, `*.edu`
- **Rate limiter** (`security/rate_limiter.py`): `SlidingWindowRateLimiter` with
  per-tool sliding window and concurrent slot tracking. `rate_limited` async context manager
- **Audit logger** (`security/audit.py`): `AuditLogger` writes append-only JSONL audit
  records. Sensitive parameter redaction for: password, passwd, secret, token, key,
  api_key, passlist, credentials
- **Executor** (`executor/process.py`): `run_command()` and `stream_command()` using
  `asyncio.create_subprocess_exec` exclusively. Absolute path resolution via `shutil.which`

#### 29 MCP Tools

**Utility (2)**
- `check_tools` — catalog of all supported external tools with install status and versions
- `validate_target` — validate a target against sanitizer and allowlist rules

**Reconnaissance (5)**
- `nmap_scan` — port scan with service/version detection, OS fingerprinting, NSE scripts;
  XML output parsing into structured `Host` and `Port` objects
- `masscan_scan` — high-speed SYN port scanning for large CIDR ranges
- `subfinder_enum` — passive subdomain enumeration via subfinder
- `dns_enumerate` — DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA) via dnspython
- `whois_lookup` — WHOIS registration data including registrar, dates, nameservers

**Web Scanning (6)**
- `nuclei_scan` — template-based vulnerability scanning with JSONL output parsing;
  supports severity filters, template paths, and tag filters
- `nikto_scan` — web server vulnerability and misconfiguration scanning
- `ffuf_fuzz` — directory and endpoint fuzzing with wordlist support
- `analyze_headers` — HTTP security header analysis with A+/F grading
- `test_cors` — CORS misconfiguration detection (origin reflection, credential leakage)
- `ssl_tls_check` — SSL/TLS configuration analysis via sslyze; detects weak protocols
  and cipher suites

**Injection (2)**
- `sqlmap_scan` — automated SQL injection detection (level 1-5, risk 1-3, DBMS auto-detect)
- `xss_scan` — Cross-Site Scripting detection via dalfox

**Exploitation (5)**
- `msf_search` — search Metasploit module database via RPC
- `msf_module_info` — get detailed module information and options
- `msf_run_module` — execute a Metasploit module (requires explicit human authorization)
- `msf_sessions_list` — list active Metasploit sessions
- `searchsploit_query` — query Exploit-DB offline mirror via searchsploit

**Bruteforce (3)**
- `hydra_attack` — network authentication brute force via Hydra
- `hash_crack` — offline hash cracking via John the Ripper or Hashcat
- `hash_identify` — identify hash type from format patterns

**Proxy (3)**
- `zap_spider` — OWASP ZAP passive spider for web application mapping
- `zap_active_scan` — OWASP ZAP active vulnerability scanning
- `zap_get_alerts` — retrieve ZAP scan alerts with risk levels

**Analysis (4)**
- `correlate_findings` — cross-tool finding correlation; identifies attack chains
  (SQLi→Data Exfiltration, BAC→Privilege Escalation, XSS→Session Hijacking, etc.)
- `score_risk` — CVSS-weighted risk scoring with context multipliers (external/internal)
- `cve_lookup` — look up a specific CVE by ID via NVD API with local SQLite cache
- `cve_search` — search CVEs by keyword with severity filtering

**Reporting (1)**
- `generate_report` — generate professional pentest reports in Markdown, HTML, or PDF
  using Jinja2 templates; supports full, executive, technical, finding, and risk_matrix
  report types

#### 11 MCP Resources
- `owasp://top10/2025` — OWASP Top 10:2025 full category list
- `owasp://top10/2025/{category_id}` — category details (A01–A10)
- `owasp://top10/2025/{category_id}/checklist` — testing checklist per category
- `ptes://phases` — PTES methodology all 7 phases overview
- `ptes://phase/{phase_number}` — PTES phase details (objectives, activities, tools)
- `checklist://web-application` — OWASP Testing Guide web app checklist
- `checklist://api` — OWASP API Security Top 10 checklist
- `checklist://network` — network infrastructure pentest checklist
- `tools://catalog` — live catalog of all tools with install status
- `tools://{tool_name}/usage` — usage guide for nmap, nuclei, sqlmap, metasploit

#### 14 MCP Prompts

**Workflow (3)**
- `full_pentest` — complete PTES-guided 7-phase penetration test workflow
- `quick_recon` — rapid 7-step reconnaissance assessment
- `web_app_assessment` — OWASP Testing Guide web application assessment workflow

**Vulnerability Assessment (4)**
- `assess_injection` — focused injection testing (SQL, XSS, command, SSTI)
- `assess_access_control` — broken access control and IDOR testing
- `assess_crypto` — cryptographic failures and SSL/TLS assessment
- `assess_misconfig` — security misconfiguration testing

**Reporting (7)**
- `executive_report` — C-level executive summary prompt
- `technical_report` — detailed technical findings documentation
- `full_pentest_report` — complete report generation workflow
- `remediation_plan` — prioritized remediation roadmap (by risk, effort, or quick-wins)
- `finding_detail` — individual vulnerability documentation
- `risk_matrix` — 5x5 risk matrix visualization prompt
- `retest_report` — remediation verification report

#### Testing
- 141 tests across unit, security, and integration suites
- 74 command injection tests covering SHELL_INJECTION_PAYLOADS and PATH_TRAVERSAL_PAYLOADS
  across all sanitizer functions
- 0 lint errors (ruff)
- 0 type errors (mypy strict)

#### Tooling
- `Makefile` with targets: install, install-dev, install-tools, setup, lint, format,
  typecheck, check, test, test-unit, test-security, test-integration, test-all,
  coverage, run, run-sse, run-dev, inspect, doctor, clean
- `scripts/install-tools.sh` for automated external tool installation
- `uv` as the package manager with `uv.lock` for reproducible installs

---

[Unreleased]: https://github.com/tengu-project/tengu/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tengu-project/tengu/releases/tag/v0.1.0
