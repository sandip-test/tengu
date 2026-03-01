# Tengu — Pentesting MCP Server

<p align="center">
  <img src="assets/Tengu.png" alt="Tengu" width="480"/>
</p>

<p align="center">
  <strong>From recon to report — AI-assisted pentesting in one command.</strong>
</p>

<p align="center">
  <a href="https://asciinema.org/a/ZdvkN5ZHOynmfjTO">
    <img src="https://asciinema.org/a/ZdvkN5ZHOynmfjTO.svg" alt="Tengu demo" width="800"/>
  </a>
</p>

<p align="center">
  <a href="https://github.com/rfunix/tengu/actions/workflows/ci.yml"><img src="https://github.com/rfunix/tengu/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.12+-blue.svg" alt="Python"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-compatible-green.svg" alt="MCP"></a>
  <img src="https://img.shields.io/badge/tools-57-orange.svg" alt="Tools">
  <img src="https://img.shields.io/badge/version-0.2.1-brightgreen.svg" alt="Version">
</p>

---

**Tengu** is an MCP server that turns Claude into a penetration testing copilot. It orchestrates 57 security tools — from Nmap to Metasploit — with built-in safety controls, audit logging, and professional reporting.

- **What is it?** An MCP server that connects Claude to industry-standard pentest tools
- **Why use it?** Automates recon and scanning while keeping the human in control of exploits
- **Who is it for?** Pentesters, red teamers, security students, and consulting firms

### Key Features

- **57 Tools** — Nmap, Metasploit, SQLMap, Nuclei, Hydra, Burp-compatible ZAP, and more
- **AI-Orchestrated** — Claude decides the next tool based on previous findings
- **Safety First** — Allowlist, rate limiting, audit logs, and human-in-the-loop for destructive actions
- **Auto Reports** — Correlate findings and generate professional pentest reports (MD/HTML/PDF)
- **32 Workflows** — Pre-built prompts for full pentest, web app, AD, cloud, and more
- **19 Resources** — Built-in OWASP Top 10, MITRE ATT&CK, PTES, and pentest checklists
- **Stealth Layer** — Optional Tor/SOCKS5 proxy routing, UA rotation, and timing jitter

---

## Quick Start

### Docker Quickstart (Recommended)

The fastest way to get Tengu running — no manual tool installation required.

```bash
git clone https://github.com/rfunix/tengu.git && cd tengu
docker compose up -d
```

Connect Claude Code to the running server:

```bash
claude mcp add --transport sse tengu http://localhost:8000/sse
```

**With lab targets (Juice Shop + DVWA):**

```bash
docker compose --profile lab up -d
```

**With Metasploit + ZAP + labs:**

```bash
docker compose --profile exploit --profile proxy --profile lab up -d
```

**Image tiers** — choose the right size for your use case:

| Tier | Size | MCP Tools | Use case |
|------|------|-----------|----------|
| `minimal` | ~480MB | 17 | Lightweight analysis, CVE research, reporting |
| `core` | ~7GB | 47 | Full pentest toolkit (default) |
| `full` | ~8GB | 57 | Everything + AD, wireless, stealth/OPSEC |

```bash
TENGU_TIER=minimal docker compose build   # lightweight
TENGU_TIER=core    docker compose build   # default
TENGU_TIER=full    docker compose build   # everything
```

**Scan custom targets** without editing files:

```bash
TENGU_ALLOWED_HOSTS="192.168.1.0/24,10.0.0.0/8" docker compose up -d
```

> **All tiers include all 34 prompts and 19 resources** — only the binary tools differ.
> See [Docker Image Tiers](#docker-image-tiers) for the full breakdown.

---

### Manual Install & Run

### Prerequisites

- Python 3.12+
- [`uv`](https://github.com/astral-sh/uv) package manager
- Kali Linux (recommended) or any Linux with security tools

### Install & Run

```bash
git clone https://github.com/rfunix/tengu.git
cd tengu

# Install Python dependencies
uv sync

# Install external pentesting tools (Kali/Debian)
make install-tools

# Run the MCP server (stdio transport)
uv run tengu
```

### Connect to Claude Code

```bash
claude mcp add --scope user tengu -- uv run --directory /path/to/tengu tengu
```

Or add manually to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "tengu": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/tengu", "tengu"]
    }
  }
}
```

### Connect to Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tengu": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/tengu", "tengu"]
    }
  }
}
```

### Remote / VM Setup (SSE Transport)

Run Tengu on a remote machine (e.g. Kali Linux in a VM):

```bash
uv run tengu --transport sse --host 0.0.0.0 --port 8000
```

Then connect from your host:

```json
{
  "mcpServers": {
    "tengu": {
      "url": "http://<kali-ip>:8000/sse"
    }
  }
}
```

### Configure Targets

Edit `tengu.toml` before running any scan — only listed targets will be accepted:

```toml
[targets]
allowed_hosts = ["192.168.1.0/24", "example.com"]
```

---

## Docker Image Tiers

> **Prompts (34) and Resources (19) are identical across all tiers** — only binary tools differ.

### Tier Comparison

| | `minimal` (~480MB) | `core` (~7GB) | `full` (~8GB) |
|---|:---:|:---:|:---:|
| **MCP Tools** | 17 | 47 | 57 |
| Utility & validation | ✓ | ✓ | ✓ |
| HTTP analysis (headers, CORS) | ✓ | ✓ | ✓ |
| SSL/TLS (sslyze) | ✓ | ✓ | ✓ |
| DNS enumeration (dnspython) | ✓ | ✓ | ✓ |
| WHOIS (python-whois) | ✓ | ✓ | ✓ |
| CVE lookup (NVD API) | ✓ | ✓ | ✓ |
| GraphQL security checks | ✓ | ✓ | ✓ |
| Hash identification | ✓ | ✓ | ✓ |
| Finding correlation & risk scoring | ✓ | ✓ | ✓ |
| Report generation | ✓ | ✓ | ✓ |
| Shodan (API key required) | ✓ | ✓ | ✓ |
| Metasploit (via RPC profile) | ✓ | ✓ | ✓ |
| Anonymity & proxy checks | ✓ | ✓ | ✓ |
| **Recon** (nmap, masscan, amass) | — | ✓ | ✓ |
| **Recon Go** (subfinder, gowitness, subjack) | — | ✓ | ✓ |
| **Web scanning** (nuclei, nikto, ffuf, gobuster) | — | ✓ | ✓ |
| **Web scanning** (wpscan, testssl.sh) | — | ✓ | ✓ |
| **OSINT** (theHarvester, whatweb) | — | ✓ | ✓ |
| **Injection** (sqlmap, dalfox) | — | ✓ | ✓ |
| **ExploitDB** (searchsploit) | — | ✓ | ✓ |
| **Brute force** (hydra, john, hashcat, cewl) | — | ✓ | ✓ |
| **Secrets** (gitleaks, trufflehog) | — | ✓ | ✓ |
| **Container** (trivy) | — | ✓ | ✓ |
| **Recon** (dnsrecon, httrack) | — | ✓ | ✓ |
| **Active Directory** (enum4linux-ng, nxc, impacket) | — | — | ✓ |
| **Wireless** (aircrack-ng) | — | — | ✓ |
| **Stealth/OPSEC** (tor, torsocks, proxychains4) | — | — | ✓ |
| **API** (arjun) | — | — | ✓ |

### `minimal` — 17 MCP Tools

Pure Python tools. No external binaries required.

| Tool | MCP function | Requires |
|------|-------------|---------|
| Target validation | `validate_target` | — |
| Tool inventory | `check_tools` | — |
| HTTP headers analysis | `analyze_headers` | httpx |
| CORS misconfiguration | `test_cors` | httpx |
| SSL/TLS analysis | `ssl_tls_check` | sslyze |
| DNS enumeration | `dns_enumerate` | dnspython |
| WHOIS lookup | `whois_lookup` | python-whois |
| Hash identification | `hash_identify` | — |
| CVE lookup | `cve_lookup`, `cve_search` | NVD API |
| GraphQL checks | `graphql_security_check` | httpx |
| Finding correlation | `correlate_findings` | — |
| Risk scoring | `score_risk` | — |
| Report generation | `generate_report` | — |
| Shodan | `shodan_lookup` | API key |
| Anonymity check | `check_anonymity` | — |
| Proxy validation | `proxy_check` | — |
| Metasploit (4 tools) | `msf_search/module_info/run/sessions` | profile: exploit |

### `core` — 47 MCP Tools (default)

Adds all essential pentest binaries via apt + Go toolchain.

**Reconnaissance (+10)**

| Tool | Binary | MCP function |
|------|--------|-------------|
| Port scanner | nmap | `nmap_scan` |
| Fast port scanner | masscan | `masscan_scan` |
| Subdomain enum | subfinder | `subfinder_enum` |
| Subdomain enum | amass | `amass_enum` |
| DNS recon | dnsrecon | `dnsrecon_scan` |
| Subdomain takeover | subjack | `subjack_check` |
| Web screenshots | gowitness | `gowitness_screenshot` |
| Site mirroring | httrack | `httrack_mirror` |

**Web Scanning (+9)**

| Tool | Binary | MCP function |
|------|--------|-------------|
| Vuln templates | nuclei | `nuclei_scan` |
| Web server scanner | nikto | `nikto_scan` |
| Directory fuzzer | ffuf | `ffuf_fuzz` |
| Directory brute | gobuster | `gobuster_scan` |
| WordPress scanner | wpscan | `wpscan_scan` |
| TLS deep scan | testssl.sh | `testssl_check` |

**OSINT (+2)**

| Tool | Binary | MCP function |
|------|--------|-------------|
| Email/domain recon | theHarvester | `theharvester_scan` |
| Tech fingerprint | whatweb | `whatweb_scan` |

**Injection (+2)**

| Tool | Binary | MCP function |
|------|--------|-------------|
| SQL injection | sqlmap | `sqlmap_scan` |
| XSS scanner | dalfox | `xss_scan` |

**Exploitation (+1)**

| Tool | Binary | MCP function |
|------|--------|-------------|
| Exploit search | searchsploit | `searchsploit_query` |

**Brute Force (+4)**

| Tool | Binary | MCP function |
|------|--------|-------------|
| Credential attack | hydra | `hydra_attack` |
| Hash cracker | john + hashcat | `hash_crack` |
| Wordlist generator | cewl | `cewl_generate` |

**Secrets (+2)**

| Tool | Binary | MCP function |
|------|--------|-------------|
| Git secret scan | gitleaks | `gitleaks_scan` |
| Secret scanner | trufflehog | `trufflehog_scan` |

**Container (+1)**

| Tool | Binary | MCP function |
|------|--------|-------------|
| Container vuln scan | trivy | `trivy_scan` |

### `full` — 57 MCP Tools

Adds Active Directory, wireless, stealth, and API testing on top of `core`.

**Active Directory (+3)**

| Tool | Binary | MCP function |
|------|--------|-------------|
| SMB/AD enum | enum4linux-ng | `enum4linux_scan` |
| Network exec | nxc (NetExec) | `nxc_enum` |
| Kerberoasting | impacket (GetUserSPNs.py) | `impacket_kerberoast` |

**Wireless (+1)**

| Tool | Binary | MCP function |
|------|--------|-------------|
| WiFi scanning | aircrack-ng / airodump-ng | `aircrack_scan` |

**Stealth / OPSEC (+3)**

| Tool | Binary | MCP function |
|------|--------|-------------|
| Tor circuit check | tor | `tor_check` |
| Tor identity rotate | tor | `tor_new_identity` |
| Full identity rotate | tor + torsocks | `rotate_identity` |

Also includes: `proxychains4`, `torsocks`, `socat` — used transparently by the stealth layer.

**API (+1)**

| Tool | Binary | MCP function |
|------|--------|-------------|
| Hidden param discovery | arjun | `arjun_discover` |

---

### Prompts — 34 (all tiers)

Pre-built workflow templates that guide Claude through complete engagements.

| Category | Prompts |
|----------|---------|
| **Pentest workflows** | `full_pentest`, `quick_recon`, `web_app_assessment` |
| **Vulnerability assessment** | `assess_injection`, `assess_access_control`, `assess_crypto`, `assess_misconfig` |
| **OSINT** | `osint_investigation` |
| **Reports** | `executive_report`, `technical_report`, `full_pentest_report`, `finding_detail`, `risk_matrix`, `remediation_plan`, `retest_report` |
| **Stealth/OPSEC** | `stealth_assessment`, `opsec_checklist` |
| **Specialized** | `ad_assessment`, `api_security_assessment`, `container_assessment`, `cloud_assessment`, `wireless_assessment`, `bug_bounty_workflow`, `compliance_assessment` |
| **Quick actions** | `explore_url`, `map_network`, `hunt_subdomains`, `find_vulns`, `find_secrets`, `go_stealth`, `crack_wifi`, `pwn_target` |

---

### Resources — 19 (all tiers)

Static reference data loaded by Claude during engagements.

| URI | Content |
|-----|---------|
| `owasp://top10/2025` | OWASP Top 10:2025 full list |
| `owasp://top10/2025/{A01..A10}` | Per-category details + testing checklist |
| `owasp://api-security/top10` | OWASP API Security Top 10 (2023) |
| `owasp://api-security/top10/{API1..API10}` | Per-category details |
| `ptes://phases` | PTES 7-phase methodology overview |
| `ptes://phase/{1..7}` | Phase details (objectives, tools, deliverables) |
| `checklist://web-application` | Web app pentest checklist (OWASP Testing Guide) |
| `checklist://api` | API pentest checklist |
| `checklist://network` | Network infrastructure checklist |
| `mitre://attack/tactics` | MITRE ATT&CK Enterprise tactics + techniques |
| `mitre://attack/technique/{T1xxx}` | Technique detail by ID |
| `creds://defaults/{product}` | Default credentials database |
| `tools://catalog` | Live tool availability status |
| `tools://{tool}/usage` | Usage guide for nmap, nuclei, sqlmap, metasploit, trivy, amass |

---

## Tool Catalog

| Category | Tools | Count |
|----------|-------|-------|
| Reconnaissance | Nmap, Masscan, Amass, Subfinder, theHarvester, WhatWeb, Gowitness, HTTrack | 8 |
| Web Scanning | Nikto, Nuclei, FFUF, Gobuster, WPScan, Arjun, OWASP ZAP | 7 |
| SSL / TLS | sslyze, testssl.sh, HTTP headers analysis, CORS tester | 4 |
| DNS | DNS Enumerate, DNSRecon, Subjack, WHOIS | 4 |
| Injection Testing | SQLMap, Dalfox (XSS), GraphQL Security Check | 3 |
| Brute Force | Hydra, John the Ripper, Hashcat, CeWL | 4 |
| Exploitation | Metasploit (search, info, run, sessions), SearchSploit | 5 |
| OSINT | theHarvester, Shodan, WHOIS | 3 |
| Secrets & Code | TruffleHog, Gitleaks | 2 |
| Container & Cloud | Trivy, Checkov, ScoutSuite | 3 |
| Active Directory | NetExec, Enum4linux, Impacket Kerberoast | 3 |
| Wireless | aircrack-ng / airodump-ng | 1 |
| Anonymity & Stealth | Tor check/rotate, proxy check, identity rotation | 5 |
| Analysis & Reporting | Finding correlation, CVSS risk scoring, report generation | 3 |
| CVE Intelligence | CVE lookup (NVD), CVE search by keyword/product/severity | 2 |
| Utility | Tool checker, target validator | 2 |

<details>
<summary>Full tool list (57 tools)</summary>

### Reconnaissance
| Tool | Description |
|------|-------------|
| `nmap_scan` | Port scanning and service/OS detection |
| `masscan_scan` | High-speed port scanner for large networks |
| `subfinder_enum` | Passive subdomain enumeration |
| `amass_enum` | Attack surface mapping and DNS brute-force |
| `dnsrecon_scan` | DNS recon (zone transfer, brute-force, PTR) |
| `dns_enumerate` | DNS record enumeration (A, MX, NS, TXT, SOA…) |
| `whois_lookup` | WHOIS domain and IP lookup |
| `subjack_check` | Subdomain takeover detection |
| `gowitness_screenshot` | Web screenshot capture for documentation |
| `httrack_mirror` | Full website mirror for offline analysis and forensics |

### Web Scanning
| Tool | Description |
|------|-------------|
| `nuclei_scan` | Template-based vulnerability scanner (CVEs, misconfigs) |
| `nikto_scan` | Web server misconfiguration and outdated software scanner |
| `ffuf_fuzz` | Directory, parameter, and vhost fuzzing |
| `gobuster_scan` | Directory, DNS, and vhost brute-force |
| `wpscan_scan` | WordPress vulnerability scanner |
| `testssl_check` | Comprehensive SSL/TLS configuration analysis |
| `analyze_headers` | HTTP security headers analysis and grading |
| `test_cors` | CORS misconfiguration detection |
| `ssl_tls_check` | SSL/TLS certificate and cipher check (sslyze) |

### OSINT
| Tool | Description |
|------|-------------|
| `theharvester_scan` | Email, subdomain, and host enumeration from public sources |
| `shodan_lookup` | Shodan host and asset search |
| `whatweb_scan` | Web technology fingerprinting (CMS, WAF, frameworks) |

### Injection Testing
| Tool | Description |
|------|-------------|
| `sqlmap_scan` | Automated SQL injection detection and exploitation |
| `xss_scan` | XSS detection via Dalfox |
| `graphql_security_check` | GraphQL introspection, batching, depth limit, field suggestions |
| `arjun_discover` | Hidden HTTP parameter discovery |

### Exploitation
| Tool | Description |
|------|-------------|
| `msf_search` | Search Metasploit modules |
| `msf_module_info` | Get detailed Metasploit module information |
| `msf_run_module` | Execute a Metasploit module (requires explicit confirmation) |
| `msf_sessions_list` | List active Metasploit sessions |
| `searchsploit_query` | Search Exploit-DB offline database |

### Brute Force
| Tool | Description |
|------|-------------|
| `hydra_attack` | Network login brute-force (SSH, FTP, HTTP, SMB…) |
| `hash_crack` | Dictionary hash cracking (Hashcat / John the Ripper) |
| `hash_identify` | Hash type identification |
| `cewl_generate` | Custom wordlist generation from a target website |

### Proxy / DAST
| Tool | Description |
|------|-------------|
| `zap_spider` | OWASP ZAP web spider |
| `zap_active_scan` | OWASP ZAP active vulnerability scan |
| `zap_get_alerts` | Retrieve ZAP scan findings |

### Secrets & Code Analysis
| Tool | Description |
|------|-------------|
| `trufflehog_scan` | Leaked secrets detection in git repositories |
| `gitleaks_scan` | Credential scanning in git history |

### Container Security
| Tool | Description |
|------|-------------|
| `trivy_scan` | Vulnerability scanning for Docker images, IaC, and SBOM |

### Cloud Security
| Tool | Description |
|------|-------------|
| `scoutsuite_scan` | Cloud security audit (AWS, Azure, GCP) |

### Active Directory
| Tool | Description |
|------|-------------|
| `enum4linux_scan` | SMB/NetBIOS enumeration |
| `nxc_enum` | Active Directory enumeration via NetExec |
| `impacket_kerberoast` | Kerberoasting with Impacket GetUserSPNs |

### Wireless
| Tool | Description |
|------|-------------|
| `aircrack_scan` | Passive wireless network scan (airodump-ng) |

### IaC Security
| Tool | Description |
|------|-------------|
| `checkov_scan` | IaC misconfiguration scan (Terraform, K8s, Dockerfile) |

### Stealth / OPSEC
| Tool | Description |
|------|-------------|
| `tor_check` | Verify Tor connectivity and exit node IP |
| `tor_new_identity` | Request new Tor circuit (NEWNYM) |
| `check_anonymity` | Check exposed IP, DNS leaks, and anonymity level |
| `proxy_check` | Validate proxy latency, exit IP, and anonymity type |
| `rotate_identity` | Rotate Tor circuit and User-Agent simultaneously |

### Analysis & Utility
| Tool | Description |
|------|-------------|
| `check_tools` | Verify which external tools are installed |
| `validate_target` | Validate target against allowlist |
| `correlate_findings` | Correlate findings across multiple scans |
| `score_risk` | CVSS-based risk scoring |
| `cve_lookup` | CVE details from NVD (CVSS, CWE, affected products) |
| `cve_search` | Search CVEs by keyword, product, or severity |
| `generate_report` | Generate Markdown/HTML/PDF pentest report |

</details>

---

## Pre-built Workflows (32 Prompts)

Tengu includes guided workflows that automatically chain multiple tools:

| Workflow | Description |
|----------|-------------|
| `full_pentest` | Complete engagement: recon → scanning → exploitation → reporting |
| `quick_recon` | Fast passive reconnaissance and asset discovery |
| `web_app_assessment` | OWASP Top 10 focused web application testing |
| `api_security_assessment` | REST and GraphQL API security review |
| `active_directory_audit` | AD enumeration, Kerberoasting, lateral movement paths |
| `cloud_security_review` | AWS/Azure/GCP misconfiguration audit |
| `container_assessment` | Docker image, IaC, and registry security review |
| `osint_investigation` | Passive OSINT from public sources |
| `stealth_assessment` | Anonymized testing via Tor + jitter |
| `bug_bounty_workflow` | Optimized workflow for bug bounty programs |
| `compliance_assessment` | Compliance-focused security review |
| `wireless_assessment` | Wireless network security testing |
| `find_secrets` | Detect leaked credentials in repos and code |
| `hunt_subdomains` | Comprehensive subdomain discovery |
| … and 12 more | Reporting, remediation, individual finding workflows |

---

## Knowledge Resources (19)

Built-in reference data available to Claude during testing:

| Resource | Description |
|----------|-------------|
| OWASP Top 10 (2021) | Full category descriptions and testing checklists |
| OWASP API Top 10 | API-specific vulnerability reference |
| MITRE ATT&CK | Adversary tactics, techniques, and procedures |
| PTES Methodology | Penetration Testing Execution Standard phases |
| Web App Checklist | Comprehensive web application test checklist |
| API Checklist | REST/GraphQL security checklist |
| Network Checklist | Network penetration testing checklist |
| CWE Top 25 | Most dangerous software weaknesses |
| Default Credentials | Common default credentials database |
| Payloads | Common payloads for injection testing |
| Stealth Techniques | OPSEC and evasion reference |

---

## Architecture

```
┌─────────────┐     MCP      ┌─────────────────┐    subprocess    ┌─────────────────┐
│   Claude    │◄────────────►│     Tengu        │─────────────────►│  Nmap, SQLMap,  │
│  (Desktop / │  stdio/SSE   │   MCP Server     │  (never shell=T) │  Metasploit...  │
│   Code)     │              │                  │                  └─────────────────┘
└─────────────┘              └────────┬─────────┘
                                      │
                               Every tool call passes through:
                                      │
                             ┌────────▼─────────┐
                             │  Safety Pipeline  │
                             │                  │
                             │  1. sanitizer    │  ← strip metacharacters, validate format
                             │  2. allowlist    │  ← check target against tengu.toml
                             │  3. rate_limiter │  ← sliding window + concurrent slots
                             │  4. audit logger │  ← JSON log to ./logs/tengu-audit.log
                             └──────────────────┘
```

---

## Safety by Design

Tengu is built as a **force multiplier for human pentesters**, not an autonomous attack tool.

| Control | Description |
|---------|-------------|
| **Target Allowlist** | Only pre-approved targets in `tengu.toml` are ever scanned |
| **Input Sanitization** | All inputs are validated against strict patterns before reaching any tool |
| **Rate Limiting** | Sliding window + concurrent slot limits prevent accidental DoS |
| **Audit Logging** | Every tool invocation logged to `./logs/tengu-audit.log` in JSON format |
| **Human-in-the-Loop** | `msf_run_module`, `hydra_attack`, and `impacket_kerberoast` require explicit confirmation |
| **No shell=True — ever** | All subprocess calls use `asyncio.create_subprocess_exec` |

---

## Practice Lab

Set up isolated vulnerable targets for safe, legal testing. The recommended topology is:

- **Host machine** (Mac/Windows/Linux) — runs Docker with the vulnerable apps
- **Kali Linux VM** — runs Tengu MCP server, has all pentesting tools installed
- **Claude Code** — runs on the host, connects to Tengu via SSE over the LAN

```
┌─────────────────────┐         LAN          ┌──────────────────────┐
│  Host (Mac/Windows) │◄────────────────────►│  Kali Linux VM       │
│                     │  Claude → SSE :8000  │                      │
│  Docker containers  │                      │  Tengu MCP Server    │
│  :3000  Juice Shop  │◄────────────────────►│  nmap, sqlmap,       │
│  :80    DVWA        │  Tengu scans targets │  nuclei, hydra...    │
│  :5013  DVGA        │                      │                      │
└─────────────────────┘                      └──────────────────────┘
         ▲
         │ Claude Code (MCP client)
```

---

### Step 1 — Get Kali Linux

Download the **Kali Linux VM** image for your hypervisor:

- **VirtualBox / VMware:** https://www.kali.org/get-kali/#kali-virtual-machines
- **UTM (Apple Silicon):** https://www.kali.org/get-kali/#kali-arm

Default credentials: `kali` / `kali`. Change the password on first login:

```bash
passwd
```

Update the system and install `git` and `uv`:

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y git curl

# Install uv (Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.local/bin/env
```

---

### Step 2 — Install Tengu on Kali

```bash
git clone https://github.com/rfunix/tengu.git ~/tengu
cd ~/tengu

# Install Python dependencies
uv sync

# Install all external pentesting tools (Kali/Debian)
make install-tools

# Verify tools are available
make doctor
```

---

### Step 3 — Configure Targets

Edit `~/tengu/tengu.toml` to allow the IP range where your Docker containers will run.

**If Docker runs on your host machine** (typical setup — find the host IP first):

```bash
# macOS
ipconfig getifaddr en0      # e.g. 192.168.86.30

# Linux / WSL
ip -4 addr show | grep inet
```

Then set the subnet in `tengu.toml`:

```toml
[targets]
allowed_hosts = ["192.168.86.0/24"]
```

**If Docker runs on the same Kali machine as Tengu:**

```toml
[targets]
allowed_hosts = ["127.0.0.1", "localhost"]
```

> Since Tengu 0.2.1, hosts explicitly listed in `allowed_hosts` are removed from the
> built-in blocklist, so loopback targets are permitted when intentionally whitelisted.

---

### Step 4 — Start Tengu on Kali (SSE transport)

Use `tmux` so the server keeps running after you close the SSH session:

```bash
# Create a persistent session
tmux new -s tengu

# Start the MCP server (SSE, accessible from the network)
cd ~/tengu
make run-sse
# Equivalent: uv run tengu --transport sse --host 0.0.0.0
# Server listens on: 0.0.0.0:8000
```

To reconnect to the session later: `tmux attach -t tengu`

To restart the server without leaving tmux:
```bash
# From the host via SSH
tmux send-keys -t tengu C-c ""
tmux send-keys -t tengu "cd ~/tengu && make run-sse" Enter
```

---

### Step 5 — Start the Vulnerable Containers

Run these on your **host machine** (where Docker is installed):

```bash
# OWASP Juice Shop — OWASP Top 10 web vulnerabilities
docker run -d -p 3000:3000 bkimminich/juice-shop

# DVWA — classic web vulnerabilities (SQLi, XSS, CSRF, File Upload...)
docker run -d -p 80:80 vulnerables/web-dvwa

# DVGA — deliberately vulnerable GraphQL API
docker run -d -p 5013:5013 dolevf/dvga

# Metasploitable 2 — vulnerable network services
docker run -d -p 2121:21 -p 2222:22 -p 8180:8080 tleemcjr/metasploitable2

# Verify containers are running
docker ps
```

---

### Step 6 — Connect Claude Code to Tengu

Add the Tengu server to Claude Code on your **host machine**.

**Via CLI:**

```bash
claude mcp add --scope user tengu-kali --transport sse http://<kali-ip>:8000/sse
```

**Or manually** in `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "tengu": {
      "url": "http://<kali-ip>:8000/sse"
    }
  }
}
```

Replace `<kali-ip>` with the Kali VM's IP (find it with `ip a` on Kali).

Verify the connection inside Claude Code:

```
/mcp
```

---

### Step 7 — Run the Pentest

Open Claude Code and ask it to attack the containers. Tengu orchestrates all tools automatically:

```
Do a full pentest on http://192.168.86.30:3000
```

Claude will chain: `validate_target` → `whatweb` → `nmap` → `analyze_headers` →
`nikto` → `nuclei` → `sqlmap` → `dalfox` → `graphql_security_check` →
`correlate_findings` → `generate_report`

**Real findings from a Juice Shop black-box assessment:**

| Severity | Finding | Endpoint |
|----------|---------|----------|
| Critical (9.8) | SQL Injection — boolean + time-blind, SQLite | `/rest/products/search?q=` |
| High (7.4) | Reflected XSS | `/rest/products/search?q=` |
| High (6.5) | Security headers absent — Grade F (25/100) | `/` |
| Medium (5.3) | CORS wildcard `Access-Control-Allow-Origin: *` | `/` |
| Medium (5.3) | `/ftp/` directory publicly accessible | `/ftp/` |
| Medium (6.1) | jQuery 2.2.4 — CVE-2019-11358, CVE-2020-11022 | `/` |
| Low (3.1) | `X-Recruiting` header — information disclosure | `/` |

Generate the final report in Markdown or HTML:

```
Generate a full HTML pentest report for the Juice Shop assessment
```

---

## Configuration Reference

```toml
[targets]
# REQUIRED: Only these hosts will be scanned
allowed_hosts = ["192.168.1.0/24", "example.com"]
blocked_hosts = []  # Always blocked, even if in allowed_hosts

[stealth]
enabled = false  # Route traffic through Tor/proxy

[stealth.proxy]
enabled = false
url = "socks5h://127.0.0.1:9050"

[osint]
shodan_api_key = ""  # Required for shodan_lookup

[tools.defaults]
scan_timeout = 300   # seconds
```

---

## Development

```bash
make install-dev    # Install Python deps + dev extras
make test           # Run unit + security tests
make lint           # ruff check
make typecheck      # mypy strict
make check          # lint + typecheck
make coverage       # pytest --cov
make inspect        # Open MCP Inspector
make doctor         # Check which pentest tools are installed
```

Tengu has 1931+ tests covering unit logic, security (command injection, input validation), and integration scenarios. See [CLAUDE.md](CLAUDE.md) for the full contributor guide.

---

## Legal Notice

Tengu is designed for **authorized security testing only**. Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions. The authors accept no liability for misuse.
