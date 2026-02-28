# Deployment Guide

This guide covers installation, configuration, and integration of Tengu with
MCP clients (Claude Code, Claude Desktop) and the MCP Inspector.

---

## Prerequisites

### Python Environment

| Requirement | Minimum Version | Notes |
|------------|----------------|-------|
| Python | 3.12+ | Required for `tomllib` (stdlib) and PEP 604 union types |
| uv | Latest | Package manager. Install: `curl -LsSf https://astral.sh/uv/install.sh \| sh` |

### External Pentesting Tools

Tools are optional at install time — Tengu starts without them and reports missing
tools via `check_tools`. Install only what you need for your engagement type.

| Tool | Category | Required By |
|------|----------|------------|
| nmap | recon | `nmap_scan` |
| masscan | recon | `masscan_scan` |
| subfinder | recon | `subfinder_enum` |
| nuclei | web | `nuclei_scan` |
| nikto | web | `nikto_scan` |
| ffuf | web | `ffuf_fuzz` |
| sqlmap | injection | `sqlmap_scan` |
| dalfox | injection | `xss_scan` |
| hydra | bruteforce | `hydra_attack` |
| john | bruteforce | `hash_crack` |
| hashcat | bruteforce | `hash_crack` |
| searchsploit | exploit | `searchsploit_query` |
| msfconsole / msfvenom | exploit | `msf_*` tools |
| zaproxy / zap.sh | proxy | `zap_*` tools |

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/tengu-project/tengu.git
cd tengu
```

### 2. Install Python Dependencies

```bash
# Install runtime dependencies only
uv sync

# Install runtime + development dependencies (tests, lint, types)
uv sync --extra dev

# Install all extras (reporting = Jinja2+WeasyPrint, metasploit = pymetasploit3)
uv sync --all-extras
```

### 3. Install External Tools

```bash
# Install all supported external tools
make install-tools

# Or install by category
make install-tools-recon    # nmap, masscan, subfinder
make install-tools-web      # nuclei, nikto, ffuf, sslyze
```

### 4. Configure Tengu

Copy and edit the default configuration:

```bash
cp tengu.toml tengu.toml.bak   # keep a backup
```

At minimum, configure `allowed_hosts` with your engagement scope:

```toml
[targets]
allowed_hosts = ["192.168.1.0/24", "*.example.com"]
```

### 5. Verify the Installation

```bash
# Check Python dependencies and tool availability
make doctor

# Run the test suite
make test
```

---

## Claude Code Configuration

Claude Code reads MCP server configuration from `~/.claude/settings.json`.

### Basic Configuration (stdio transport)

```json
{
  "mcpServers": {
    "tengu": {
      "command": "uv",
      "args": [
        "run",
        "--directory", "/absolute/path/to/tengu",
        "tengu"
      ],
      "env": {
        "TENGU_CONFIG_PATH": "/absolute/path/to/tengu/tengu.toml"
      }
    }
  }
}
```

Replace `/absolute/path/to/tengu` with the actual absolute path to your clone.

### With NVD API Key

```json
{
  "mcpServers": {
    "tengu": {
      "command": "uv",
      "args": [
        "run",
        "--directory", "/absolute/path/to/tengu",
        "tengu"
      ],
      "env": {
        "TENGU_CONFIG_PATH": "/absolute/path/to/tengu/tengu.toml",
        "NVD_API_KEY": "your-nvd-api-key-here"
      }
    }
  }
}
```

### With Debug Logging

```json
{
  "mcpServers": {
    "tengu": {
      "command": "uv",
      "args": [
        "run",
        "--directory", "/absolute/path/to/tengu",
        "tengu"
      ],
      "env": {
        "TENGU_CONFIG_PATH": "/absolute/path/to/tengu/tengu.toml",
        "TENGU_LOG_LEVEL": "DEBUG"
      }
    }
  }
}
```

After editing `settings.json`, restart Claude Code or run `/mcp` to reload servers.

---

## Claude Desktop Configuration

Claude Desktop reads MCP configuration from:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "tengu": {
      "command": "uv",
      "args": [
        "run",
        "--directory", "/absolute/path/to/tengu",
        "tengu"
      ],
      "env": {
        "TENGU_CONFIG_PATH": "/absolute/path/to/tengu/tengu.toml"
      }
    }
  }
}
```

Restart Claude Desktop after editing the config file.

---

## MCP Inspector

The MCP Inspector provides an interactive web UI for testing tools, resources,
and prompts without needing an AI client.

```bash
make inspect
# equivalent to:
npx @modelcontextprotocol/inspector uv run tengu
```

The inspector opens at `http://localhost:5173`. You can:
- Browse all registered tools, resources, and prompts
- Call tools with custom parameters and inspect the JSON response
- Read resources and see their content
- Expand prompts with test arguments

---

## SSE Transport (Remote Connections)

The SSE (Server-Sent Events) transport allows the MCP server to run on a different
host than the client. This is useful for running Tengu on a Kali Linux VM while
Claude Code runs on a macOS host.

### Start Tengu in SSE Mode

On the Kali VM:

```bash
make run-sse
# equivalent to:
uv run tengu --transport sse
# default: http://0.0.0.0:8000
```

### Configure Claude Code for SSE

On the macOS host, in `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "tengu-kali": {
      "url": "http://KALI_VM_IP:8000/sse",
      "transport": "sse"
    }
  }
}
```

Replace `KALI_VM_IP` with the actual IP of your Kali VM (e.g., `192.168.56.101`
for a VirtualBox host-only network).

---

## Example Workflows

After connecting Claude Code to Tengu, use these prompts to start an engagement.

### Quick Recon

```
Use the quick_recon prompt with target="192.168.1.1"
```

This triggers a 7-step workflow: validate_target → whois_lookup → dns_enumerate →
subfinder_enum → nmap_scan → analyze_headers → ssl_tls_check

### Web Application Assessment

```
Use the web_app_assessment prompt with url="https://example.com"
```

This triggers: analyze_headers → test_cors → ssl_tls_check → ffuf_fuzz →
nuclei_scan → nikto_scan → sqlmap_scan → xss_scan → correlate_findings → score_risk

### Full Penetration Test

```
Use the full_pentest prompt with target="example.com", scope="full", engagement_type="blackbox"
```

This triggers the complete 7-phase PTES workflow.

---

## Kali Linux Quickstart

Kali Linux is the recommended platform for running Tengu in a penetration testing lab.

### Install uv on Kali

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc   # or source ~/.zshrc
uv --version
```

### Clone and Setup Tengu

```bash
sudo mkdir -p /opt/tengu
sudo chown $USER:$USER /opt/tengu
git clone https://github.com/tengu-project/tengu.git /opt/tengu
cd /opt/tengu
make setup          # installs Python dependencies
make install-tools  # installs any missing pentesting tools
```

### Configure for Kali

```bash
cat > /opt/tengu/tengu.toml << 'EOF'
[server]
log_level = "INFO"
audit_log_path = "/opt/tengu/logs/tengu-audit.log"

[targets]
# Configure your lab network
allowed_hosts = ["192.168.56.0/24"]

[tools.defaults]
scan_timeout = 1800
wordlist_path = "/usr/share/wordlists/dirb/common.txt"
EOF
```

### Verify Tool Availability

```bash
make doctor
```

### Tools Pre-Installed on Kali

The following tools are included in Kali Linux by default and require no additional
installation:

| Tool | Package | Tengu Usage |
|------|---------|------------|
| nmap | `nmap` | `nmap_scan` |
| masscan | `masscan` | `masscan_scan` |
| sqlmap | `sqlmap` | `sqlmap_scan` |
| nikto | `nikto` | `nikto_scan` |
| hydra | `hydra` | `hydra_attack` |
| john | `john` | `hash_crack` |
| hashcat | `hashcat` | `hash_crack` |
| msfconsole | `metasploit-framework` | `msf_*` tools |
| aircrack-ng | `aircrack-ng` | (wireless, future) |
| searchsploit | `exploitdb` | `searchsploit_query` |
| theHarvester | `theharvester` | (future integration) |
| amass | `amass` | (future integration) |
| dnsrecon | `dnsrecon` | (future integration) |
| gobuster | `gobuster` | (future integration) |
| wpscan | `wpscan` | (future integration) |
| tor | `tor` | (future stealth mode) |
| proxychains4 | `proxychains4` | (future stealth mode) |
| enum4linux-ng | `enum4linux-ng` | (future integration) |
| impacket | `python3-impacket` | (future integration) |

### Tools That Need Special Installation on Kali

**OWASP ZAP** (for `zap_*` tools):
```bash
sudo apt install -y zaproxy
# Or download the latest stable release:
# https://www.zaproxy.org/download/
```

**Go-based tools** (subfinder, nuclei, ffuf, dalfox):
```bash
# Install Go first
sudo apt install -y golang-go

# subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ffuf
go install github.com/ffuf/ffuf/v2@latest

# dalfox (XSS scanner used by xss_scan)
go install github.com/hahwul/dalfox/v2@latest

# Add Go bin to PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

**WeasyPrint** (for PDF report generation):
```bash
sudo apt install -y python3-weasyprint libpango-1.0-0 libpangocairo-1.0-0
# Then install the Python extra:
uv sync --extra reporting
```

### SSE Mode: macOS Host → Kali VM

This setup lets Claude Code on your macOS machine use Tengu running on Kali.

**On Kali VM:**

```bash
# Configure the allowed hosts for your lab network
# (edit /opt/tengu/tengu.toml first)

# Start Tengu in SSE mode
cd /opt/tengu
uv run tengu --transport sse --host 0.0.0.0 --port 8000
```

**On macOS host**, edit `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "tengu-kali": {
      "url": "http://192.168.56.101:8000/sse",
      "transport": "sse"
    }
  }
}
```

**VirtualBox network setup** (host-only adapter):
1. Go to VirtualBox → File → Host Network Manager
2. Create a host-only network (e.g., `192.168.56.0/24`)
3. Add a host-only adapter to your Kali VM
4. Configure Kali's `/etc/network/interfaces` or use NetworkManager:
   ```bash
   sudo dhclient eth1   # adjust interface name as needed
   ```

**VMware Fusion network setup**:
1. Use VMnet1 (Host-Only) or VMnet8 (NAT)
2. Note the VM's IP from `ip addr show`
3. Use that IP in the `url` field above

---

## Troubleshooting

### "Tool not found" errors

```bash
# Check which tools are missing
make doctor

# Install missing tools
make install-tools

# Or install manually and verify PATH
which nmap nuclei ffuf sqlmap

# If tool is in a non-standard location, set path in tengu.toml:
# [tools.paths]
# nmap = "/usr/local/bin/nmap"
```

### "Target not in allowlist" errors

```bash
# Check your tengu.toml configuration
grep -A5 "\[targets\]" tengu.toml

# Add the target to allowed_hosts in tengu.toml
# Example:
# [targets]
# allowed_hosts = ["192.168.1.0/24"]

# Then restart the MCP server (restart Claude Code or run /mcp reload)
```

### Rate limit errors

```bash
# Check current rate limiting config
grep -A3 "\[rate_limiting\]" tengu.toml

# Increase limits for intensive testing (use responsibly):
# [rate_limiting]
# max_scans_per_minute = 20
# max_concurrent_scans = 5
```

### MCP server not appearing in Claude Code

1. Verify `~/.claude/settings.json` is valid JSON: `python3 -m json.tool ~/.claude/settings.json`
2. Verify the path in `--directory` exists: `ls /absolute/path/to/tengu`
3. Test Tengu starts manually: `cd /path/to/tengu && uv run tengu`
4. Check for errors: `TENGU_LOG_LEVEL=DEBUG uv run tengu`
5. In Claude Code, run `/mcp` to see server status and error messages

### Metasploit RPC connection failures

```bash
# Start Metasploit RPC daemon
msfrpcd -P your_password -a 127.0.0.1 -p 55553 -S

# Verify it is running
netstat -tlnp | grep 55553

# Set the password in environment (Tengu reads MSF_RPC_PASSWORD)
export MSF_RPC_PASSWORD="your_password"
```

### OWASP ZAP connection failures

```bash
# Start ZAP in daemon mode
zaproxy -daemon -host 127.0.0.1 -port 8080 -config api.key=your_api_key

# Verify ZAP is running
curl http://127.0.0.1:8080/JSON/core/view/version/?apikey=your_api_key

# Set the API key in tengu.toml (future config option) or environment
```

### Audit log growing too large

```bash
# Rotate the audit log manually (safe — Tengu appends, so the new file is used)
mv logs/tengu-audit.log logs/tengu-audit-$(date +%Y%m%d).log

# Or set up logrotate
cat > /etc/logrotate.d/tengu << 'EOF'
/opt/tengu/logs/tengu-audit.log {
    weekly
    rotate 52
    compress
    missingok
    notifempty
    copytruncate
}
EOF
```

### Scan timeouts

```bash
# Increase the global timeout in tengu.toml
# [tools.defaults]
# scan_timeout = 1800   # 30 minutes

# Or pass timeout explicitly in the tool call:
# nmap_scan(target="...", timeout=3600)
```
