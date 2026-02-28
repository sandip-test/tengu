#!/usr/bin/env bash
# Tengu — External Pentesting Tools Installer
# Usage: ./scripts/install-tools.sh [--all|--recon|--web|--inject|--exploit|--brute|--proxy]
#
# Supports: macOS (Homebrew), Debian/Ubuntu (apt), Arch (pacman), Fedora (dnf)

set -euo pipefail

# ── Colors ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ── Logging ────────────────────────────────────────────────────────────────────
log_info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
log_section() { echo -e "\n${BLUE}━━━ $* ━━━${NC}"; }

# ── OS Detection ───────────────────────────────────────────────────────────────
OS=""
PKG_MGR=""

detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PKG_MGR="brew"
        log_info "Detected: macOS"
        if ! command -v brew &>/dev/null; then
            log_error "Homebrew not found. Install from https://brew.sh"
            exit 1
        fi
    elif command -v apt-get &>/dev/null; then
        OS="debian"
        PKG_MGR="apt"
        log_info "Detected: Debian/Ubuntu"
    elif command -v pacman &>/dev/null; then
        OS="arch"
        PKG_MGR="pacman"
        log_info "Detected: Arch Linux"
    elif command -v dnf &>/dev/null; then
        OS="fedora"
        PKG_MGR="dnf"
        log_info "Detected: Fedora/RHEL"
    else
        log_error "Unsupported OS. Please install tools manually."
        exit 1
    fi
}

# ── Package Installation Helpers ───────────────────────────────────────────────
pkg_install() {
    local pkg="$1"
    case "$PKG_MGR" in
        brew)   brew install "$pkg" 2>/dev/null || brew upgrade "$pkg" 2>/dev/null || true ;;
        apt)    sudo apt-get install -y "$pkg" 2>/dev/null || true ;;
        pacman) sudo pacman -S --noconfirm "$pkg" 2>/dev/null || true ;;
        dnf)    sudo dnf install -y "$pkg" 2>/dev/null || true ;;
    esac
}

is_installed() {
    command -v "$1" &>/dev/null
}

# ── Go Installation ─────────────────────────────────────────────────────────────
install_go() {
    if is_installed go; then
        log_ok "Go already installed: $(go version)"
        return
    fi

    log_info "Installing Go..."
    if [[ "$OS" == "macos" ]]; then
        pkg_install go
    else
        GO_VERSION="1.22.0"
        ARCH=$(uname -m)
        [[ "$ARCH" == "aarch64" ]] && ARCH="arm64" || ARCH="amd64"
        wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -O /tmp/go.tar.gz
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
        rm /tmp/go.tar.gz
    fi
    log_ok "Go installed"
}

go_install() {
    local pkg="$1"
    local name="$2"

    if is_installed "$name"; then
        log_ok "$name already installed"
        return
    fi

    log_info "Installing $name via go install..."
    install_go
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    go install "$pkg" && log_ok "$name installed" || log_warn "Failed to install $name"
}

# ── RECON TOOLS ────────────────────────────────────────────────────────────────
install_nmap() {
    if is_installed nmap; then log_ok "nmap already installed"; return; fi
    log_info "Installing nmap..."
    if [[ "$OS" == "macos" ]]; then
        pkg_install nmap
    else
        pkg_install nmap
    fi
    is_installed nmap && log_ok "nmap installed" || log_warn "nmap installation may have failed"
}

install_masscan() {
    if is_installed masscan; then log_ok "masscan already installed"; return; fi
    log_info "Installing masscan..."
    if [[ "$OS" == "macos" ]]; then
        pkg_install masscan
    elif [[ "$OS" == "debian" ]]; then
        sudo apt-get install -y masscan
    else
        pkg_install masscan
    fi
    is_installed masscan && log_ok "masscan installed" || log_warn "masscan not found — may need manual install"
}

install_subfinder() {
    go_install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" "subfinder"
}

install_amass() {
    go_install "github.com/owasp-amass/amass/v4/...@master" "amass"
}

# ── WEB SCANNING TOOLS ─────────────────────────────────────────────────────────
install_nuclei() {
    if is_installed nuclei; then
        log_ok "nuclei already installed"
        # Update templates
        log_info "Updating Nuclei templates..."
        nuclei -update-templates -silent 2>/dev/null || true
        return
    fi
    go_install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" "nuclei"
    if is_installed nuclei; then
        log_info "Installing Nuclei templates..."
        nuclei -update-templates -silent 2>/dev/null || true
    fi
}

install_nikto() {
    if is_installed nikto; then log_ok "nikto already installed"; return; fi
    log_info "Installing nikto..."
    if [[ "$OS" == "macos" ]]; then
        pkg_install nikto
    else
        pkg_install nikto
    fi
    is_installed nikto && log_ok "nikto installed" || log_warn "nikto not found"
}

install_ffuf() {
    go_install "github.com/ffuf/ffuf/v2@latest" "ffuf"
}

install_sslyze() {
    if python3 -m pip show sslyze &>/dev/null 2>&1; then
        log_ok "sslyze already installed"
        return
    fi
    log_info "Installing sslyze..."
    if command -v uv &>/dev/null; then
        uv pip install sslyze && log_ok "sslyze installed (uv)" || log_warn "sslyze install failed"
    else
        python3 -m pip install sslyze && log_ok "sslyze installed (pip)" || log_warn "sslyze install failed"
    fi
}

# ── INJECTION TOOLS ─────────────────────────────────────────────────────────────
install_sqlmap() {
    if is_installed sqlmap; then log_ok "sqlmap already installed"; return; fi
    log_info "Installing sqlmap..."
    if [[ "$OS" == "macos" ]]; then
        pkg_install sqlmap
    else
        pkg_install sqlmap
    fi
    is_installed sqlmap && log_ok "sqlmap installed" || {
        # Fallback: pip install
        python3 -m pip install sqlmap 2>/dev/null && log_ok "sqlmap installed via pip" || log_warn "sqlmap not found"
    }
}

install_dalfox() {
    go_install "github.com/hahwul/dalfox/v2@latest" "dalfox"
}

# ── EXPLOITATION TOOLS ─────────────────────────────────────────────────────────
install_metasploit() {
    if is_installed msfconsole; then log_ok "Metasploit already installed"; return; fi

    log_info "Installing Metasploit Framework..."
    if [[ "$OS" == "macos" ]]; then
        log_warn "On macOS, install Metasploit manually from: https://www.metasploit.com/download"
        log_warn "Or via: brew install --cask metasploit"
        brew install --cask metasploit 2>/dev/null || log_warn "Manual install required"
    else
        # Official Rapid7 installer
        curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
            > /tmp/msfinstall
        chmod 755 /tmp/msfinstall
        sudo /tmp/msfinstall
        rm -f /tmp/msfinstall
    fi
    is_installed msfconsole && log_ok "Metasploit installed" || log_warn "Metasploit installation may need manual steps"
}

install_exploitdb() {
    if is_installed searchsploit; then log_ok "searchsploit already installed"; return; fi
    log_info "Installing ExploitDB (searchsploit)..."
    if [[ "$OS" == "macos" ]]; then
        pkg_install exploitdb
    elif [[ "$OS" == "debian" ]]; then
        pkg_install exploitdb
    else
        # Manual install
        EXPLOITDB_DIR="$HOME/.local/share/exploitdb"
        if [[ ! -d "$EXPLOITDB_DIR" ]]; then
            git clone https://gitlab.com/exploit-database/exploitdb.git "$EXPLOITDB_DIR"
            ln -sf "$EXPLOITDB_DIR/searchsploit" /usr/local/bin/searchsploit
        fi
    fi
    is_installed searchsploit && log_ok "searchsploit installed" || log_warn "searchsploit not found"
}

# ── BRUTE FORCE TOOLS ──────────────────────────────────────────────────────────
install_hydra() {
    if is_installed hydra; then log_ok "hydra already installed"; return; fi
    log_info "Installing hydra..."
    if [[ "$OS" == "macos" ]]; then
        pkg_install hydra
    else
        pkg_install hydra
    fi
    is_installed hydra && log_ok "hydra installed" || log_warn "hydra not found"
}

install_john() {
    if is_installed john; then log_ok "John the Ripper already installed"; return; fi
    log_info "Installing John the Ripper..."
    if [[ "$OS" == "macos" ]]; then
        pkg_install john-jumbo
    else
        pkg_install john
    fi
    is_installed john && log_ok "John installed" || log_warn "John not found"
}

install_hashcat() {
    if is_installed hashcat; then log_ok "hashcat already installed"; return; fi
    log_info "Installing hashcat..."
    pkg_install hashcat
    is_installed hashcat && log_ok "hashcat installed" || log_warn "hashcat not found"
}

# ── PROXY TOOLS ────────────────────────────────────────────────────────────────
install_zap() {
    if is_installed zaproxy || is_installed zap.sh; then log_ok "OWASP ZAP already installed"; return; fi
    log_info "Installing OWASP ZAP..."
    if [[ "$OS" == "macos" ]]; then
        brew install --cask zap && log_ok "ZAP installed" || log_warn "ZAP install failed — install manually from https://www.zaproxy.org/"
    elif command -v snap &>/dev/null; then
        sudo snap install zaproxy --classic && log_ok "ZAP installed via snap" || log_warn "ZAP install failed"
    else
        log_warn "Install ZAP manually from: https://www.zaproxy.org/download/"
    fi
}

# ── WORDLISTS ─────────────────────────────────────────────────────────────────
install_wordlists() {
    SECLISTS_DIR="/usr/share/seclists"
    if [[ -d "$SECLISTS_DIR" ]]; then
        log_ok "SecLists already installed at $SECLISTS_DIR"
        return
    fi

    ALT_DIR="$HOME/.local/share/seclists"
    if [[ -d "$ALT_DIR" ]]; then
        log_ok "SecLists already installed at $ALT_DIR"
        return
    fi

    log_info "Installing SecLists..."
    if [[ "$OS" == "macos" ]]; then
        pkg_install seclists 2>/dev/null || {
            mkdir -p "$ALT_DIR"
            git clone --depth=1 https://github.com/danielmiessler/SecLists.git "$ALT_DIR"
        }
    elif [[ "$OS" == "debian" ]]; then
        pkg_install seclists 2>/dev/null || {
            sudo mkdir -p "$SECLISTS_DIR"
            sudo git clone --depth=1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR"
        }
    else
        mkdir -p "$ALT_DIR"
        git clone --depth=1 https://github.com/danielmiessler/SecLists.git "$ALT_DIR"
        log_ok "SecLists installed at $ALT_DIR"
    fi
}

# ── OSINT TOOLS ────────────────────────────────────────────────────────────────
install_theharvester() {
    if is_installed theHarvester; then log_ok "theHarvester already installed"; return; fi
    log_info "Installing theHarvester..."
    if [[ "$OS" == "macos" ]]; then
        pkg_install theharvester
    else
        pkg_install theharvester || (
            sudo pip3 install theHarvester 2>/dev/null && log_ok "theHarvester installed via pip"
        )
    fi
}

install_whatweb() {
    if is_installed whatweb; then log_ok "whatweb already installed"; return; fi
    log_info "Installing whatweb..."
    if [[ "$OS" == "macos" ]]; then
        pkg_install whatweb
    else
        pkg_install whatweb || log_warn "whatweb not found in repos, try: gem install whatweb"
    fi
}

# ── SECRETS TOOLS ──────────────────────────────────────────────────────────────
install_trufflehog() {
    if is_installed trufflehog; then log_ok "trufflehog already installed"; return; fi
    log_info "Installing trufflehog..."
    if [[ "$OS" == "macos" ]]; then
        brew install trufflesecurity/trufflehog/trufflehog
    else
        go_install github.com/trufflesecurity/trufflehog/v3@latest trufflehog
    fi
}

install_gitleaks() {
    if is_installed gitleaks; then log_ok "gitleaks already installed"; return; fi
    log_info "Installing gitleaks..."
    if [[ "$OS" == "macos" ]]; then
        pkg_install gitleaks
    else
        go_install github.com/gitleaks/gitleaks/v8@latest gitleaks
    fi
}

# ── CONTAINER TOOLS ────────────────────────────────────────────────────────────
install_trivy() {
    if is_installed trivy; then log_ok "trivy already installed"; return; fi
    log_info "Installing trivy..."
    if [[ "$OS" == "macos" ]]; then
        pkg_install trivy
    elif [[ "$OS" == "debian" ]]; then
        sudo apt-get install -y wget apt-transport-https gnupg lsb-release
        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
        echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee /etc/apt/sources.list.d/trivy.list
        sudo apt-get update && sudo apt-get install -y trivy
    else
        pkg_install trivy || log_warn "Install trivy manually from https://github.com/aquasecurity/trivy"
    fi
}

# ── CLOUD + IaC TOOLS ──────────────────────────────────────────────────────────
install_scoutsuite() {
    if is_installed scout; then log_ok "ScoutSuite already installed"; return; fi
    log_info "Installing ScoutSuite..."
    sudo pip3 install scoutsuite 2>/dev/null && log_ok "ScoutSuite installed" || log_warn "ScoutSuite install failed"
}

install_checkov() {
    if is_installed checkov; then log_ok "checkov already installed"; return; fi
    log_info "Installing checkov..."
    if [[ "$OS" == "macos" ]]; then
        pkg_install checkov
    else
        sudo pip3 install checkov 2>/dev/null && log_ok "checkov installed" || log_warn "checkov install failed"
    fi
}

# ── API TOOLS ──────────────────────────────────────────────────────────────────
install_arjun() {
    if is_installed arjun; then log_ok "arjun already installed"; return; fi
    log_info "Installing arjun..."
    sudo pip3 install arjun 2>/dev/null && log_ok "arjun installed" || log_warn "arjun install failed"
}

# ── ACTIVE DIRECTORY TOOLS ─────────────────────────────────────────────────────
install_enum4linux_ng() {
    if is_installed enum4linux-ng; then log_ok "enum4linux-ng already installed"; return; fi
    log_info "Installing enum4linux-ng..."
    if [[ "$OS" == "debian" ]]; then
        sudo apt-get install -y enum4linux-ng 2>/dev/null || (
            sudo pip3 install enum4linux-ng && log_ok "enum4linux-ng installed via pip"
        )
    else
        sudo pip3 install enum4linux-ng 2>/dev/null && log_ok "enum4linux-ng installed" || log_warn "enum4linux-ng install failed"
    fi
}

install_netexec() {
    if is_installed nxc; then log_ok "NetExec (nxc) already installed"; return; fi
    log_info "Installing NetExec..."
    if [[ "$OS" == "debian" ]]; then
        sudo apt-get install -y nxc 2>/dev/null || (
            sudo pip3 install netexec && log_ok "NetExec installed via pip"
        )
    else
        sudo pip3 install netexec 2>/dev/null && log_ok "NetExec installed" || log_warn "NetExec install failed"
    fi
}

install_impacket() {
    if python3 -c "import impacket" 2>/dev/null; then log_ok "impacket already installed"; return; fi
    log_info "Installing impacket..."
    if [[ "$OS" == "debian" ]]; then
        sudo apt-get install -y impacket-scripts 2>/dev/null || (
            sudo pip3 install impacket && log_ok "impacket installed via pip"
        )
    else
        sudo pip3 install impacket 2>/dev/null && log_ok "impacket installed" || log_warn "impacket install failed"
    fi
}

# ── WIRELESS TOOLS ─────────────────────────────────────────────────────────────
install_aircrack_ng() {
    if is_installed aircrack-ng; then log_ok "aircrack-ng already installed"; return; fi
    log_info "Installing aircrack-ng..."
    if [[ "$OS" == "macos" ]]; then
        pkg_install aircrack-ng
    else
        pkg_install aircrack-ng
    fi
}

# ── STEALTH TOOLS ──────────────────────────────────────────────────────────────
install_tor_stealth() {
    # Detect Kali — most stealth tools pre-installed
    if grep -q "Kali" /etc/os-release 2>/dev/null; then
        log_info "Kali Linux detected — tor, proxychains4, torsocks should be pre-installed"
    fi

    # Tor
    if is_installed tor; then
        log_ok "tor already installed"
    else
        log_info "Installing tor..."
        pkg_install tor
    fi

    # torsocks
    if is_installed torsocks; then
        log_ok "torsocks already installed"
    else
        log_info "Installing torsocks..."
        if [[ "$OS" == "macos" ]]; then
            pkg_install torsocks
        else
            pkg_install torsocks
        fi
    fi

    # proxychains
    if is_installed proxychains4; then
        log_ok "proxychains4 already installed"
    else
        log_info "Installing proxychains-ng..."
        if [[ "$OS" == "macos" ]]; then
            pkg_install proxychains-ng
        else
            pkg_install proxychains4 2>/dev/null || pkg_install proxychains
        fi
    fi

    # socat
    if is_installed socat; then
        log_ok "socat already installed"
    else
        log_info "Installing socat..."
        pkg_install socat
    fi

    log_ok "Stealth tools installed. Start Tor: sudo systemctl start tor"
    log_info "Verify Tor: curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip"
}

# ── STATUS TABLE ───────────────────────────────────────────────────────────────
print_status() {
    log_section "Tool Installation Status"

    declare -A TOOLS=(
        ["nmap"]="Reconnaissance"
        ["masscan"]="Reconnaissance"
        ["subfinder"]="Reconnaissance"
        ["nuclei"]="Web Scanning"
        ["nikto"]="Web Scanning"
        ["ffuf"]="Web Scanning"
        ["sqlmap"]="Injection"
        ["dalfox"]="Injection"
        ["msfconsole"]="Exploitation"
        ["searchsploit"]="Exploitation"
        ["hydra"]="Brute Force"
        ["john"]="Brute Force"
        ["hashcat"]="Brute Force"
    )

    printf "\n%-20s %-20s %s\n" "Tool" "Category" "Status"
    printf "%-20s %-20s %s\n" "────────────────────" "────────────────────" "──────────"

    for tool in "${!TOOLS[@]}"; do
        if is_installed "$tool"; then
            printf "%-20s %-20s ${GREEN}✓ installed${NC}\n" "$tool" "${TOOLS[$tool]}"
        else
            printf "%-20s %-20s ${RED}✗ not found${NC}\n" "$tool" "${TOOLS[$tool]}"
        fi
    done

    # Check ZAP separately
    if is_installed zaproxy || is_installed zap.sh; then
        printf "%-20s %-20s ${GREEN}✓ installed${NC}\n" "zaproxy" "Proxy"
    else
        printf "%-20s %-20s ${RED}✗ not found${NC}\n" "zaproxy" "Proxy"
    fi

    echo ""
}

# ── MAIN ───────────────────────────────────────────────────────────────────────
main() {
    local mode="${1:---all}"

    echo -e "${BLUE}"
    echo "  ████████╗███████╗███╗   ██╗ ██████╗ ██╗   ██╗"
    echo "     ██╔══╝██╔════╝████╗  ██║██╔════╝ ██║   ██║"
    echo "     ██║   █████╗  ██╔██╗ ██║██║  ███╗██║   ██║"
    echo "     ██║   ██╔══╝  ██║╚██╗██║██║   ██║██║   ██║"
    echo "     ██║   ███████╗██║ ╚████║╚██████╔╝╚██████╔╝"
    echo "     ╚═╝   ╚══════╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝"
    echo "  Pentesting Tool Installer"
    echo -e "${NC}"

    detect_os

    case "$mode" in
        --all)
            log_section "Installing All Tools"
            install_go
            install_nmap
            install_masscan
            install_subfinder
            install_amass
            install_nuclei
            install_nikto
            install_ffuf
            install_sslyze
            install_sqlmap
            install_dalfox
            install_metasploit
            install_exploitdb
            install_hydra
            install_john
            install_hashcat
            install_zap
            install_wordlists
            ;;
        --recon)
            log_section "Installing Reconnaissance Tools"
            install_go
            install_nmap
            install_masscan
            install_subfinder
            install_amass
            ;;
        --web)
            log_section "Installing Web Scanning Tools"
            install_go
            install_nuclei
            install_nikto
            install_ffuf
            install_sslyze
            ;;
        --inject)
            log_section "Installing Injection Tools"
            install_sqlmap
            install_go
            install_dalfox
            ;;
        --exploit)
            log_section "Installing Exploitation Tools"
            install_metasploit
            install_exploitdb
            ;;
        --brute)
            log_section "Installing Brute Force Tools"
            install_hydra
            install_john
            install_hashcat
            ;;
        --proxy)
            log_section "Installing Proxy Tools"
            install_zap
            ;;
        --wordlists)
            log_section "Installing Wordlists"
            install_wordlists
            ;;
        --osint)
            log_section "Installing OSINT Tools"
            install_theharvester
            install_whatweb
            ;;
        --secrets)
            log_section "Installing Secret Scanning Tools"
            install_trufflehog
            install_gitleaks
            ;;
        --container)
            log_section "Installing Container Security Tools"
            install_trivy
            ;;
        --cloud)
            log_section "Installing Cloud Security Tools"
            install_scoutsuite
            install_checkov
            ;;
        --api)
            log_section "Installing API Testing Tools"
            install_arjun
            ;;
        --ad)
            log_section "Installing Active Directory Tools"
            install_enum4linux_ng
            install_netexec
            install_impacket
            ;;
        --wireless)
            log_section "Installing Wireless Tools"
            install_aircrack_ng
            ;;
        --stealth)
            log_section "Installing Stealth/OPSEC Tools"
            install_tor_stealth
            ;;
        --status)
            print_status
            exit 0
            ;;
        *)
            echo "Usage: $0 [--all|--recon|--web|--inject|--exploit|--brute|--proxy|--wordlists|--osint|--secrets|--container|--cloud|--api|--ad|--wireless|--stealth|--status]"
            exit 1
            ;;
    esac

    print_status
    log_ok "Installation complete! Run 'make doctor' to verify tool availability."
}

main "$@"
