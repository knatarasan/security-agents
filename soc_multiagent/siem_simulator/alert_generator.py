"""
Alert generator for the SIEM simulator.

Produces realistic security alerts with statistically correct distributions:
  - Severity:  HIGH 30% | MEDIUM 40% | LOW 30%
  - Positivity: FP 90%  | TP 10%
  - TP breakdown: routine 70% | severe 30%

Each alert template is carefully crafted so that a competent LLM triage agent
can distinguish FP from TP based on linguistic cues in rule_name and raw_log.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional


# ─── Distribution constants ──────────────────────────────────────────────────

SEVERITY_WEIGHTS: dict[str, float] = {"HIGH": 0.30, "MEDIUM": 0.40, "LOW": 0.30}
FP_RATE: float = 0.90          # probability that an alert is a false positive
TP_ROUTINE_RATE: float = 0.70  # probability that a TP is routine (vs severe)

CATEGORIES = [
    "brute_force",
    "malware",
    "data_exfil",
    "lateral_movement",
    "phishing",
    "policy_violation",
    "recon",
    "privilege_escalation",
]

USERNAMES = [
    "jsmith", "adavis", "mwilson", "tjohnson", "rbrown",
    "slee", "kmartinez", "pthompson", "cwang", "agarcia",
    "svc_backup", "svc_nessus", "svc_deploy", "admin", "root",
    "it_support", "helpdesk01", "ops_user", "devops_svc", "api_svc",
]

HOSTNAMES = [
    "ws-001.corp.local", "ws-042.corp.local", "srv-dc01.corp.local",
    "srv-file01.corp.local", "srv-web01.corp.local", "srv-db01.corp.local",
    "laptop-exec-01.corp.local", "kiosk-lobby.corp.local",
    "srv-backup01.corp.local", "srv-vpn01.corp.local",
    "workstation-hr-12.corp.local", "dev-build-01.corp.local",
    "jumphost-01.corp.local", "dmz-proxy-01.corp.local",
    "cloud-connector-01.corp.local",
]


# ─── IP helpers ──────────────────────────────────────────────────────────────

def _rfc1918() -> str:
    """Return a random RFC-1918 private IP address."""
    family = random.randint(0, 2)
    if family == 0:
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    if family == 1:
        return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _external() -> str:
    """Return a routable (non-RFC-1918) IP address."""
    _reserved = {10, 100, 127, 169, 172, 192, 198, 203}
    while True:
        a = random.randint(1, 223)
        if a not in _reserved:
            return f"{a}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _src_ip() -> str:
    """70 % internal, 30 % external for alert sources."""
    return _rfc1918() if random.random() < 0.70 else _external()


def _dst_ip() -> str:
    """50 % internal, 50 % external for alert destinations."""
    return _rfc1918() if random.random() < 0.50 else _external()


# ─── Timestamp helpers ───────────────────────────────────────────────────────

def _log_ts(offset_hours: int = 0) -> str:
    """Return a syslog-style timestamp, optionally offset from now."""
    dt = datetime.now(timezone.utc) - timedelta(hours=offset_hours)
    return dt.strftime("%b %d %H:%M:%S")


# ─── Template bank ───────────────────────────────────────────────────────────
# Each entry: list of (rule_name, raw_log_template)
# Templates use {host}, {user}, {src}, {dst} placeholders.

FP_TEMPLATES: dict[str, list[tuple[str, str]]] = {
    "brute_force": [
        (
            "Multiple Failed Logins – Likely Expired Password",
            "{ts} {host} sshd[12345]: Failed password for {user} from {src} port 54321 ssh2 (3 of 5 attempts)",
        ),
        (
            "Auth Failure Threshold – User Lockout Pattern (IT Service Account)",
            "{ts} {host} auth: pam_unix(sshd:auth): authentication failure; logname={user} rhost={src} (svc account rotation)",
        ),
        (
            "RDP Failed Login – Automated Logon Script Misconfiguration",
            "{ts} {host} security: EventID=4625 Account={user} FailureReason=UnknownUserNameOrBadPassword Src={src} (scheduled task cred mismatch)",
        ),
    ],
    "malware": [
        (
            "AV Detection – PUA Low Confidence (Admin Tool False Match)",
            "{ts} {host} defender: THREAT_DETECTED PUA:Win32/PCOptimizer confidence=LOW user={user} file=ccleaner.exe",
        ),
        (
            "Heuristic Alert – IT Deployment Script (Authorised)",
            "{ts} {host} crowdstrike: DETECTION type=PotentiallyUnwanted score=38 process=pstools.exe user={user} (IT approved)",
        ),
        (
            "Suspicious Script – Legitimate SysAdmin PowerShell Task",
            "{ts} {host} sentinelone: ALERT severity=LOW threat=Generic.Script.Suspicious file=backup_cleanup.ps1 user={user}",
        ),
    ],
    "data_exfil": [
        (
            "Large Outbound Transfer – Authorised Nightly Backup Job",
            "{ts} firewall: ALLOW TCP {src}:45678 -> {dst}:443 bytes=524288000 duration=3600 app=s3_backup proto=HTTPS",
        ),
        (
            "Outbound Traffic Spike – CDN Content Delivery (Akamai)",
            "{ts} proxy: ALLOWED {user} GET https://assets.akamai.com/bundle.js bytes=256MB referer=corp-intranet",
        ),
        (
            "Cloud Sync – Authorised SharePoint Migration Script",
            "{ts} dlp: MONITOR user={user} dst={dst} bytes=512MB classification=UNCLASSIFIED action=ALLOW job=sharepoint_migration",
        ),
    ],
    "lateral_movement": [
        (
            "Admin Share Access – Authorised IT Patch Deployment",
            "{ts} {host} security: EventID=5140 ShareName=\\\\{host}\\C$ SubjectUserName={user} IpAddress={src} AccessMask=0x12019f (SCCM deployment)",
        ),
        (
            "Remote WMI Call – Endpoint Management System (Authorised)",
            "{ts} {host} wmiprvse: Remote WMI query IpAddress={src} UserName={user} Namespace=root\\cimv2 Class=Win32_Process (MECM)",
        ),
        (
            "PSExec Detection – IT Helpdesk Remote Support Session",
            "{ts} {host} sysmon: EventID=1 Image=psexec.exe CmdLine=-s -d \\\\{host} cmd.exe User={user} TicketID=INC0042311",
        ),
    ],
    "phishing": [
        (
            "Suspicious Email – Newsletter URL Pattern (Legit Vendor)",
            "{ts} mailgw: QUARANTINE from=noreply@techcrunch.com to={user}@corp.local subj=Weekly_Tech_Digest url_category=news",
        ),
        (
            "Blocked Extension in Email – PDF Attachment False Match",
            "{ts} exchange: MessageBlocked sender=invoices@vendor.com recipient={user}@corp.local reason=BlockedExt(.pdf) override_available=yes",
        ),
        (
            "External Email Flagged – Legitimate Marketing Domain",
            "{ts} proofpoint: VERDICT=SUSPICIOUS_LINK score=40 url=https://cdn.mailchimp.com/track user={user} campaign=quarterly_newsletter",
        ),
    ],
    "policy_violation": [
        (
            "USB Mass Storage Connected – Standard Employee Workstation",
            "{ts} {host} kernel: usb 1-1: new high-speed USB device number 4 registered by xhci_hcd (user={user} device=SanDisk_Cruzer)",
        ),
        (
            "Personal Cloud Storage Access – Policy Reminder Triggered",
            "{ts} proxy: WARN {user} GET https://www.dropbox.com/home category=personal_cloud action=ALLOW_WITH_WARNING",
        ),
        (
            "Non-Approved Software Execution – Low Risk Utility",
            "{ts} {host} dlp: user={user} executed vlc.exe not in approved software list (low risk, submit exception request)",
        ),
    ],
    "recon": [
        (
            "Internal Network Scan – Authorised IT Asset Discovery (Nessus)",
            "{ts} {host} snort: ICMP sweep src={src} classification=AUTHORISED_SCAN scanner=nessus job_id=weekly_vuln_scan",
        ),
        (
            "Port Scan – Vulnerability Assessment System (Scheduled)",
            "{ts} firewall: ACCEPT TCP {src} -> {dst} MULTIPORT flags=SYN app=vuln_scanner schedule=0200_daily",
        ),
        (
            "LDAP Enumeration – HR System Sync Service",
            "{ts} dc01 security: EventID=4662 SubjectUserName={user} ObjectType=user Op=ReadProperty count=220 (HRIS sync)",
        ),
    ],
    "privilege_escalation": [
        (
            "sudo Usage – Authorised Linux System Administrator",
            "{ts} {host} sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt-get upgrade",
        ),
        (
            "Service Account Privilege Change – Approved IT Change Request",
            "{ts} {host} security: EventID=4672 AccountName={user} PrivilegeList=SeDebugPrivilege ChangeTicket=CHG0012345",
        ),
        (
            "Token Privilege Enabled – Expected Domain Admin Activity",
            "{ts} {host} security: EventID=4703 AccountName={user} EnabledPrivileges=SeTakeOwnershipPrivilege Task=quarterly_audit",
        ),
    ],
}

TP_ROUTINE_TEMPLATES: dict[str, list[tuple[str, str]]] = {
    "brute_force": [
        (
            "Brute Force Detected – 55+ Failed Logins in 10 Minutes",
            "{ts} {host} sshd: Failed password for {user} from {src} port 22 ssh2 – attempt 55 of ongoing campaign",
        ),
        (
            "SSH Brute Force – Multiple Coordinated Source IPs (No Success)",
            "{ts} fail2ban: NOTICE [sshd] Ban {src} after 50 failures in 600s targeting {user}@{host}",
        ),
        (
            "RDP Authentication Storm – Dictionary Attack (Blocked)",
            "{ts} {host} security: EventID=4625 Account={user} FailureReason=WrongPassword IpAddress={src} (75 attempts, account locked)",
        ),
    ],
    "policy_violation": [
        (
            "Unauthorised VPN Client Installation – Shadow IT",
            "{ts} {host} auditd: EXECVE user={user} exe=tailscale.exe ppid=explorer.exe (not in approved software list)",
        ),
        (
            "Data Classification Breach – Internal Sensitive File to Personal Email",
            "{ts} dlp: BLOCK user={user} attempted upload to gmail.com file=Q4_financial_forecast.xlsx classification=CONFIDENTIAL",
        ),
        (
            "Unapproved SaaS Application – Credential Sharing Detected",
            "{ts} proxy: BLOCKED {user} -> notion.so category=shadow_it bytes=45MB (bulk data export pattern)",
        ),
    ],
    "recon": [
        (
            "SMB Share Enumeration – Non-Admin Account (Suspicious Timing)",
            "{ts} {host} snort: SMB_SHARE_ENUM src={src} dst={dst} attempts=85 user={user} (outside business hours)",
        ),
        (
            "AD Enumeration – Excess LDAP Queries from Workstation",
            "{ts} dc01 security: EventID=4662 SubjectUserName={user} ObjectType=groupPolicyContainer count=450/hr WorkStation={host}",
        ),
        (
            "Internal Network Sweep – Unregistered Source (Possible Compromised Host)",
            "{ts} firewall: ALERT ICMP_SWEEP src={src} dst=10.0.0.0/8 ttl=64 count=300 (src not in authorised scanner list)",
        ),
    ],
}

TP_SEVERE_TEMPLATES: dict[str, list[tuple[str, str]]] = {
    "malware": [
        (
            "Ransomware IOC – VSS Deletion + Mass File Encryption Detected",
            "{ts} {host} crowdstrike: CRITICAL process=vssadmin.exe CmdLine='delete shadows /all /quiet' parent=powershell.exe user={user} files_encrypted=1500",
        ),
        (
            "CobaltStrike Beacon – C2 Heartbeat to External IP",
            "{ts} {host} crowdstrike: C2_BEACON dst={dst}:443 process=svchost.exe interval=60s jitter=15s user=SYSTEM beacon_config=detected",
        ),
        (
            "LockBit Ransomware Variant – Confirmed IOC Match",
            "{ts} {host} defender: THREAT Ransom:Win32/LockBit.B!MTB confidence=HIGH action=BLOCKED user={user} dropper=update.exe",
        ),
    ],
    "lateral_movement": [
        (
            "Pass-the-Hash – NTLM Lateral Movement to Domain Controller",
            "{ts} {host} security: EventID=4624 LogonType=3 AuthPackage=NTLM SubjectUserName={user} WorkstationName=ATTACKER IpAddress={src}",
        ),
        (
            "Kerberoasting – TGS Requests for High-Value Service Accounts",
            "{ts} dc01 security: EventID=4769 ServiceName=krbtgt SubjectUserName={user} IpAddress={src} TicketOptions=0x40800000 EncryptionType=0x17 (RC4 – downgrade)",
        ),
        (
            "WMI Lateral Movement – Remote Command Execution via Compromised Account",
            "{ts} {host} sysmon: EventID=20 WmiEventConsumer ConsumerName=evil_consumer process=cmd.exe cmdline='net user backdoor P@ss! /add /domain' user={user}",
        ),
    ],
    "data_exfil": [
        (
            "Mass Exfiltration – 10GB PII Transfer to External IP (Non-Business Hours)",
            "{ts} firewall: ALERT TCP {src}:51234 -> {dst}:443 bytes=10737418240 duration=1800 classification=data_theft user={user}",
        ),
        (
            "DNS Tunnelling – Data Exfiltration via Encoded TXT Records",
            "{ts} dns: ALERT dns_tunnel queries=5000/hr src={src} avglen=220 encoding=base32 dst={dst} user={user} (iodine signature)",
        ),
        (
            "DLP Critical – Bulk PII/Financial Records Uploaded to Attacker Infrastructure",
            "{ts} dlp: CRITICAL user={user} dst={dst} bytes=10GB filetype=CSV classification=PII_FINANCIAL time=02:47 (after-hours, anomaly_score=99)",
        ),
    ],
    "privilege_escalation": [
        (
            "PrintNightmare Exploitation – Malicious DLL Dropped by Spooler",
            "{ts} {host} sysmon: EventID=11 Image=spoolsv.exe TargetFilename=C:\\Windows\\System32\\drivers\\nc64.dll user={user} (PrintNightmare CVE-2021-34527)",
        ),
        (
            "Local Privilege Escalation – SYSTEM Token Obtained via CVE Exploit",
            "{ts} {host} crowdstrike: CRITICAL technique=T1068 process=exploit.exe parent=chrome.exe user={user} privilege_gain=SYSTEM cve=CVE-2023-21752",
        ),
        (
            "Malicious Service Installation – Persistence via SYSTEM Service",
            "{ts} {host} security: EventID=4697 ServiceName=SvcHost32 ImagePath=C:\\Temp\\reverse_shell.exe AccountName={user} ServiceType=Win32OwnProcess",
        ),
    ],
    "phishing": [
        (
            "Spearphishing Click – Credential Harvesting Page Visited",
            "{ts} proxy: CRITICAL user={user} GET https://corp-login.evil-domain.xyz/o365_auth src={src} category=credential_phishing",
        ),
        (
            "BEC Attack – CFO Impersonation Wire Transfer Request",
            "{ts} exchange: ALERT BEC from=cfo-impersonation@evil.com to=accounts-payable@corp.local subj='Urgent Wire – Q4 Settlement' amount=$245000 external_domain=new",
        ),
        (
            "Malicious Office Macro – Meterpreter Shellcode Execution",
            "{ts} {host} defender: MACRO_EXEC doc=Invoice_Nov.docm spawned=powershell.exe cmdline='-enc SQBFAFgA...' user={user} (Meterpreter stager pattern)",
        ),
    ],
}


# ─── Core generator ──────────────────────────────────────────────────────────

def generate_alert() -> dict:
    """
    Generate a single realistic security alert.

    Applies the configured statistical distributions and returns a dict
    matching the SIEM alert schema.  The `ground_truth` and (if TP)
    `severity_class` fields are included for offline evaluation purposes.
    """
    # Determine ground truth and severity class
    is_fp = random.random() < FP_RATE
    ground_truth = "FP" if is_fp else "TP"
    severity_class: Optional[str] = None

    if not is_fp:
        severity_class = "routine" if random.random() < TP_ROUTINE_RATE else "severe"

    # Severity draw — severe TPs are biased toward HIGH/MEDIUM
    severity = random.choices(
        list(SEVERITY_WEIGHTS.keys()),
        weights=list(SEVERITY_WEIGHTS.values()),
    )[0]
    if severity_class == "severe" and severity == "LOW":
        severity = random.choice(["HIGH", "MEDIUM"])

    # Category selection constrained to what each alert-type bank has
    if ground_truth == "FP":
        category = random.choice(list(FP_TEMPLATES.keys()))
        pool = FP_TEMPLATES[category]
    elif severity_class == "routine":
        category = random.choice(list(TP_ROUTINE_TEMPLATES.keys()))
        pool = TP_ROUTINE_TEMPLATES[category]
    else:  # severe TP
        category = random.choice(list(TP_SEVERE_TEMPLATES.keys()))
        pool = TP_SEVERE_TEMPLATES[category]

    rule_name, raw_log_tpl = random.choice(pool)

    # Randomise identifiers
    src = _src_ip()
    dst = _dst_ip()
    host = random.choice(HOSTNAMES)
    user = random.choice(USERNAMES)
    short_host = host.split(".")[0]

    # Log timestamp slightly in the past so it looks realistic
    ts = _log_ts(offset_hours=random.randint(0, 6))

    raw_log = raw_log_tpl.format(ts=ts, host=short_host, user=user, src=src, dst=dst)

    alert: dict = {
        "alert_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "category": category,
        "source_ip": src,
        "destination_ip": dst,
        "hostname": host,
        "user": user,
        "rule_name": rule_name,
        "raw_log": raw_log,
        "ground_truth": ground_truth,  # hidden; for offline evaluation only
    }

    if severity_class is not None:
        alert["severity_class"] = severity_class  # hidden; only present when TP

    return alert
