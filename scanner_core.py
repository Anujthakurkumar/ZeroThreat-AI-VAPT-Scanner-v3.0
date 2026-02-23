"""
ZeroThreat AI VAPT Scanner v3.0 - Core Engine
Advanced Vulnerability Assessment & Penetration Testing Scanner

NEW in v3.0:
  - Scope allowlist + CIDR safety guardrails
  - Scan profiles: light / normal / deep
  - Rate limiter (requests/sec)
  - Enhanced service fingerprinting + confidence scores
  - Web crawler (spider) with form + param discovery
  - Plugin architecture: checks/network/*.py, checks/web/*.py
  - Evidence model: request/response snippets per finding
  - CVSS-ish severity engine with environment modifiers
  - Tech stack detection (WordPress, Django, Nginx, Cloudflare, etc.)
  - Auth support: cookie / custom header injection
  - Passive recon mode: DNS, TLS cert, headers only
  - SARIF 2.1.0 export

For educational and authorized testing only.
"""

import socket, threading, json, time, re, ssl, ipaddress
import hashlib, importlib, importlib.util, os, sys
import urllib.request, urllib.parse, urllib.error
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional, List
from pathlib import Path


# ─────────────────────────────────────────
#  SCAN PROFILES
# ─────────────────────────────────────────

SCAN_PROFILES = {
    "light": {
        "threads": 50, "timeout": 0.5,
        "port_range": (1, 1024),
        "extra_ports": [3306, 3389, 5432, 6379, 8080, 8443, 27017],
        "rate_limit": 200, "crawl_depth": 1, "crawl_pages": 10,
        "aggressive": False,
        "description": "Fast, low-noise. Common ports only.",
    },
    "normal": {
        "threads": 120, "timeout": 0.8,
        "port_range": (1, 1024),
        "extra_ports": [1433,1521,2049,3306,3389,4444,5432,5900,6379,8080,8443,8888,9200,27017],
        "rate_limit": 500, "crawl_depth": 2, "crawl_pages": 30,
        "aggressive": False,
        "description": "Balanced coverage and speed.",
    },
    "deep": {
        "threads": 200, "timeout": 1.2,
        "port_range": (1, 10000),
        "extra_ports": [10000,10443,11211,15672,27017,28017,50000,50070,61616],
        "rate_limit": 1000, "crawl_depth": 4, "crawl_pages": 100,
        "aggressive": True,
        "description": "Thorough scan. Slower, more detections.",
    },
}


# ─────────────────────────────────────────
#  SCOPE + SAFETY
# ─────────────────────────────────────────

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

class ScopeEngine:
    def __init__(self, allowlist=None, owner_confirmed=False):
        self.allowlist = allowlist or []
        self.owner_confirmed = owner_confirmed

    def is_allowed(self, target):
        if self.allowlist:
            for a in self.allowlist:
                if target == a or target.endswith("." + a):
                    return True, "In allowlist"
            return False, f"Not in scope allowlist: {self.allowlist}"
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(target))
            if any(ip in net for net in PRIVATE_RANGES):
                return True, "Private/local IP"
        except: pass
        if target in ("localhost","127.0.0.1","::1"):
            return True, "Localhost"
        if not self.owner_confirmed:
            return False, ("External target detected. Set owner_confirmed=True to confirm authorization.")
        return True, "Owner confirmed"


# ─────────────────────────────────────────
#  RATE LIMITER
# ─────────────────────────────────────────

class RateLimiter:
    def __init__(self, max_per_sec=500):
        self.max_per_sec = max_per_sec
        self._lock = threading.Lock()
        self._count = 0
        self._window = time.time()

    def acquire(self):
        with self._lock:
            now = time.time()
            if now - self._window >= 1.0:
                self._count = 0
                self._window = now
            if self._count >= self.max_per_sec:
                sleep = 1.0 - (now - self._window)
                if sleep > 0: time.sleep(sleep)
                self._count = 0
                self._window = time.time()
            self._count += 1


# ─────────────────────────────────────────
#  DATA MODELS
# ─────────────────────────────────────────

@dataclass
class OpenPort:
    port: int
    protocol: str
    service: str
    banner: str = ""
    version: str = ""
    confidence: str = "MEDIUM"
    tls: bool = False
    fingerprint: str = ""

@dataclass
class TechStack:
    framework: str = ""
    server: str = ""
    language: str = ""
    cms: str = ""
    cdn: str = ""
    waf: str = ""
    extras: list = field(default_factory=list)

@dataclass
class CrawlResult:
    urls: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    params: list = field(default_factory=list)
    emails: list = field(default_factory=list)

@dataclass
class PassiveInfo:
    dns_records: dict = field(default_factory=dict)
    tls_info: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)

@dataclass
class ScanResult:
    target: str
    scan_type: str
    profile: str
    started_at: str
    finished_at: str = ""
    open_ports: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)
    web_findings: list = field(default_factory=list)
    host_status: str = "unknown"
    summary: dict = field(default_factory=dict)
    ai_analysis: str = ""
    risk_score: float = 0.0
    risk_label: str = ""
    tech_stack: dict = field(default_factory=dict)
    crawl_result: dict = field(default_factory=dict)
    passive_info: dict = field(default_factory=dict)
    scope_status: str = ""
    scan_id: str = ""


# ─────────────────────────────────────────
#  SERVICE DB
# ─────────────────────────────────────────

SERVICE_DB = {
    21:("FTP","File Transfer Protocol"), 22:("SSH","Secure Shell"),
    23:("Telnet","Cleartext Remote Shell"), 25:("SMTP","Mail Transfer"),
    53:("DNS","Domain Name System"), 80:("HTTP","Web Server"),
    110:("POP3","Mail Retrieval"), 111:("RPC","Remote Procedure Call"),
    135:("MSRPC","MS RPC"), 139:("NetBIOS","NetBIOS"), 143:("IMAP","Mail Access"),
    161:("SNMP","Simple Network Management"), 389:("LDAP","Directory Services"),
    443:("HTTPS","Encrypted Web"), 445:("SMB","Server Message Block"),
    512:("rexec","Remote Exec"), 513:("rlogin","Remote Login"),
    514:("rsh","Remote Shell"), 631:("IPP","Printing Protocol"),
    993:("IMAPS","Encrypted Mail"), 995:("POP3S","Encrypted Mail"),
    1080:("SOCKS","Proxy"), 1433:("MSSQL","MS SQL Server"),
    1521:("Oracle","Oracle DB"), 2049:("NFS","Network File System"),
    3306:("MySQL","MySQL Database"), 3389:("RDP","Remote Desktop"),
    4444:("Backdoor","Meterpreter Indicator"), 5432:("PostgreSQL","PostgreSQL"),
    5900:("VNC","Virtual Network Computing"), 6379:("Redis","Redis Key-Value"),
    8080:("HTTP-Alt","Alternate Web"), 8443:("HTTPS-Alt","Alternate HTTPS"),
    8888:("Jupyter","Jupyter Notebook"), 9200:("Elasticsearch","Elasticsearch API"),
    10000:("Webmin","Webmin Admin"), 11211:("Memcached","Memcached"),
    15672:("RabbitMQ","RabbitMQ Management"), 27017:("MongoDB","MongoDB"),
    28017:("MongoDB-Web","MongoDB Web UI"),
}
TLS_PORTS = {443, 8443, 993, 995, 465, 636}


# ─────────────────────────────────────────
#  VULNERABILITY DATABASES
# ─────────────────────────────────────────

def _v(**kw):
    return {
        "id":kw["id"],"title":kw["title"],"severity":kw["sev"],"cvss_score":kw["cvss"],
        "description":kw["desc"],"affected":kw["aff"],"recommendation":kw["rec"],
        "cve_ids":kw.get("cves",[]),"cwe_ids":kw.get("cwes",[]),
        "references":kw.get("refs",[]),"confidence":kw.get("conf","HIGH"),
        "evidence":"","evidence_detail":{},"adjusted_score":0.0,
        "internet_exposed":False,"auth_required":False,"pii_involved":False,
    }

NET_VULN_DB = {
    "TELNET":_v(id="NET-001",title="Telnet Service Exposed",sev="CRITICAL",cvss=9.8,
        desc="Telnet transmits all data including credentials in cleartext over the network.",
        aff="Telnet (Port 23)",rec="Disable Telnet. Replace with SSH.",
        cves=["CVE-1999-0619"],cwes=["CWE-319"]),
    "FTP_ANON":_v(id="NET-002",title="Anonymous FTP Login Enabled",sev="HIGH",cvss=7.5,
        desc="FTP server allows unauthenticated 'anonymous' access to files.",
        aff="FTP (Port 21)",rec="Disable anonymous FTP. Use SFTP with key-based auth.",
        cves=["CVE-1999-0497"],cwes=["CWE-306"]),
    "FTP_PLAIN":_v(id="NET-003",title="FTP Service Exposed (Cleartext)",sev="MEDIUM",cvss=5.0,
        desc="FTP transmits credentials in cleartext. Susceptible to interception.",
        aff="FTP (Port 21)",rec="Replace FTP with SFTP or FTPS.",cwes=["CWE-319"],conf="MEDIUM"),
    "SMB":_v(id="NET-004",title="SMB Service Exposed",sev="HIGH",cvss=8.1,
        desc="SMB exposed — potentially vulnerable to EternalBlue (MS17-010), WannaCry, NotPetya chains.",
        aff="SMB (Port 445)",rec="Apply MS17-010 patch. Disable SMBv1. Firewall port 445.",
        cves=["CVE-2017-0144","CVE-2017-0145"],cwes=["CWE-119"]),
    "RDP":_v(id="NET-005",title="RDP Exposed to Network",sev="HIGH",cvss=8.8,
        desc="RDP exposed publicly. Vulnerable to BlueKeep (unauthenticated RCE) and brute-force.",
        aff="RDP (Port 3389)",rec="Restrict RDP behind VPN. Enable NLA. Patch BlueKeep.",
        cves=["CVE-2019-0708","CVE-2019-1182"],cwes=["CWE-287"]),
    "REDIS":_v(id="NET-006",title="Redis Exposed Without Authentication",sev="CRITICAL",cvss=9.8,
        desc="Redis accessible without auth. Full read/write access + potential RCE via CONFIG SET.",
        aff="Redis (Port 6379)",rec="Set requirepass in redis.conf. Bind to 127.0.0.1.",
        cves=["CVE-2022-0543"],cwes=["CWE-306"]),
    "MONGODB":_v(id="NET-007",title="MongoDB Exposed Without Authentication",sev="CRITICAL",cvss=9.8,
        desc="MongoDB accessible without credentials — full database read/write.",
        aff="MongoDB (Port 27017)",rec="Enable authentication. Bind to localhost.",
        cves=["CVE-2015-7882"],cwes=["CWE-306"]),
    "ELASTICSEARCH":_v(id="NET-008",title="Elasticsearch Exposed Without Auth",sev="CRITICAL",cvss=9.8,
        desc="Elasticsearch REST API accessible without auth — all indexed data exposed.",
        aff="Elasticsearch (Port 9200)",rec="Enable X-Pack security. Firewall port 9200.",
        cves=["CVE-2014-3120"],cwes=["CWE-306"]),
    "SNMP":_v(id="NET-009",title="SNMP Service Exposed",sev="HIGH",cvss=7.5,
        desc="SNMP exposed. Default 'public' community strings enable device enumeration.",
        aff="SNMP (Port 161)",rec="Change community strings. Use SNMPv3 with auth+encryption.",
        cves=["CVE-1999-0517"],cwes=["CWE-1188"]),
    "BACKDOOR":_v(id="NET-010",title="Potential Backdoor / Reverse Shell",sev="CRITICAL",cvss=10.0,
        desc="Port 4444 is the default Metasploit Meterpreter port. Possible active compromise.",
        aff="Port 4444",rec="ISOLATE HOST IMMEDIATELY. Begin incident response.",cwes=["CWE-506"]),
    "VNC":_v(id="NET-011",title="VNC Remote Desktop Exposed",sev="HIGH",cvss=7.2,
        desc="VNC exposed — frequently weak or no authentication.",
        aff="VNC (Port 5900)",rec="Tunnel VNC through SSH. Enable strong password.",
        cves=["CVE-2006-2369"],cwes=["CWE-287"]),
    "NFS":_v(id="NET-012",title="NFS Share Potentially Accessible",sev="HIGH",cvss=7.5,
        desc="NFS exposed may allow unauthorized filesystem access.",
        aff="NFS (Port 2049)",rec="Restrict NFS exports. Use Kerberos auth.",cwes=["CWE-284"]),
    "JUPYTER":_v(id="NET-013",title="Jupyter Notebook Exposed",sev="CRITICAL",cvss=9.0,
        desc="Jupyter Notebook without token auth = arbitrary OS code execution by any visitor.",
        aff="Jupyter (Port 8888)",rec="Require token/password. Bind to localhost. Use reverse proxy.",
        cves=["CVE-2022-21699"],cwes=["CWE-306"]),
    "MEMCACHED":_v(id="NET-014",title="Memcached Exposed Without Auth",sev="HIGH",cvss=7.5,
        desc="Memcached accessible without auth. Cache poisoning, data theft, DDoS amplification risk.",
        aff="Memcached (Port 11211)",rec="Bind to localhost. Enable SASL. Firewall UDP 11211.",
        cves=["CVE-2018-1000115"],cwes=["CWE-306"]),
    "WEBMIN":_v(id="NET-015",title="Webmin Admin Panel Exposed",sev="HIGH",cvss=8.0,
        desc="Webmin exposed. Historically vulnerable to unauthenticated RCE (CVE-2019-15107).",
        aff="Webmin (Port 10000)",rec="Restrict to VPN/management VLAN. Keep updated.",
        cves=["CVE-2019-15107"],cwes=["CWE-284"]),
    "RABBITMQ":_v(id="NET-016",title="RabbitMQ Management UI Exposed",sev="HIGH",cvss=7.5,
        desc="RabbitMQ management interface exposed. Default guest:guest credentials often unchanged.",
        aff="RabbitMQ (Port 15672)",rec="Restrict access. Change default credentials.",cwes=["CWE-1188"]),
}

WEB_VULN_DB = {
    "XSS":_v(id="WEB-001",title="Reflected Cross-Site Scripting (XSS)",sev="HIGH",cvss=7.4,
        desc="User input reflected unescaped in response — enables script injection, session hijacking.",
        aff="Web Application Input Parameters",
        rec="Implement output encoding. Add Content-Security-Policy. Sanitize all inputs.",
        cwes=["CWE-79"],refs=["https://owasp.org/www-community/attacks/xss/"]),
    "SQLI":_v(id="WEB-002",title="SQL Injection",sev="CRITICAL",cvss=9.8,
        desc="SQL error signatures triggered by metacharacters — possible data exfiltration or auth bypass.",
        aff="Database Query Parameters",
        rec="Use parameterized queries. Never concatenate user input into SQL.",
        cwes=["CWE-89"],refs=["https://owasp.org/www-community/attacks/SQL_Injection"]),
    "OPEN_REDIRECT":_v(id="WEB-003",title="Open Redirect",sev="MEDIUM",cvss=6.1,
        desc="Application follows unvalidated redirect parameter to external URL. Enables phishing.",
        aff="Redirect Parameters",rec="Whitelist allowed redirect destinations.",cwes=["CWE-601"]),
    "SENSITIVE_FILES":_v(id="WEB-004",title="Sensitive File Disclosure",sev="HIGH",cvss=7.5,
        desc="Sensitive config, credential, or backup files publicly accessible via HTTP.",
        aff="Web Server File System",rec="Remove sensitive files from web root. Deny via server config.",
        cwes=["CWE-538"]),
    "MISSING_HEADERS":_v(id="WEB-005",title="Missing Security Headers",sev="MEDIUM",cvss=5.3,
        desc="Multiple critical HTTP security headers absent — exposes users to various client-side attacks.",
        aff="HTTP Response Headers",
        rec="Add: X-Frame-Options, X-Content-Type-Options, HSTS, CSP, Referrer-Policy.",cwes=["CWE-693"]),
    "SSL_WEAK":_v(id="WEB-006",title="Weak TLS Configuration",sev="HIGH",cvss=7.4,
        desc="Server accepts deprecated TLS 1.0/1.1. Vulnerable to POODLE, BEAST downgrade attacks.",
        aff="TLS/SSL Configuration",rec="Disable TLS 1.0/1.1. Use TLS 1.3. Configure strong ciphers.",
        cves=["CVE-2014-3566"],cwes=["CWE-326"]),
    "DIR_LISTING":_v(id="WEB-007",title="Directory Listing Enabled",sev="MEDIUM",cvss=5.3,
        desc="Web server returns directory contents — reveals application structure and sensitive files.",
        aff="Web Server Config",rec="Disable directory listing (Options -Indexes / autoindex off).",cwes=["CWE-548"]),
    "CORS_WILDCARD":_v(id="WEB-008",title="Overly Permissive CORS Policy",sev="MEDIUM",cvss=6.5,
        desc="Access-Control-Allow-Origin: * permits any origin cross-origin requests.",
        aff="CORS Configuration",rec="Restrict CORS to specific trusted origins.",cwes=["CWE-942"]),
    "ADMIN_EXPOSED":_v(id="WEB-009",title="Admin Panel Publicly Accessible",sev="HIGH",cvss=8.0,
        desc="Administrative interface accessible without network-level restriction.",
        aff="Admin Endpoints",rec="Restrict to VPN/specific IPs. Add MFA.",cwes=["CWE-284"]),
    "INFO_DISCLOSURE":_v(id="WEB-010",title="Server Information Disclosure",sev="LOW",cvss=3.7,
        desc="HTTP headers reveal technology stack and version numbers, aiding reconnaissance.",
        aff="HTTP Response Headers",rec="Remove Server and X-Powered-By headers.",cwes=["CWE-200"]),
    "CSP_MISSING":_v(id="WEB-011",title="Content Security Policy Missing",sev="MEDIUM",cvss=5.0,
        desc="No CSP header — browser has no restrictions on script/resource loading.",
        aff="HTTP Response Headers",
        rec="Implement: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
        cwes=["CWE-693"]),
    "HSTS_MISSING":_v(id="WEB-012",title="HSTS Not Configured",sev="MEDIUM",cvss=4.8,
        desc="Strict-Transport-Security header absent. Allows SSL stripping and downgrade attacks.",
        aff="HTTPS Configuration",
        rec="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",cwes=["CWE-319"]),
    "CLICKJACKING":_v(id="WEB-013",title="Clickjacking Vulnerability",sev="MEDIUM",cvss=4.3,
        desc="X-Frame-Options not set. Page can be framed in malicious iframes.",
        aff="HTTP Response Headers",rec="Add X-Frame-Options: DENY",cwes=["CWE-1021"]),
    "COOKIE_FLAGS":_v(id="WEB-014",title="Session Cookie Missing Security Flags",sev="HIGH",cvss=7.5,
        desc="Session cookies lack HttpOnly/Secure/SameSite flags — vulnerable to XSS theft.",
        aff="Session Management",
        rec="Set HttpOnly, Secure, SameSite=Strict on all session cookies.",cwes=["CWE-614"]),
}


# ─────────────────────────────────────────
#  TECH DETECTOR
# ─────────────────────────────────────────

TECH_SIGS = {
    "WordPress":["wp-content","wp-includes","WordPress"],
    "Joomla":["Joomla!","/components/com_"],
    "Drupal":["Drupal.settings","/sites/default/"],
    "Django":["csrfmiddlewaretoken","django"],
    "Laravel":["laravel_session","Laravel"],
    "ASP.NET":["__VIEWSTATE","X-AspNet","ASP.NET"],
    "Spring":["JSESSIONID","spring"],
    "Flask":["Werkzeug","Flask"],
    "Express":["X-Powered-By: Express"],
    "Angular":["ng-version","angular"],
    "React":["__REACT","react-root","data-reactroot"],
    "Vue.js":["__vue__","v-app"],
    "Apache":["Apache/"],
    "Nginx":["nginx/"],
    "IIS":["Microsoft-IIS"],
    "Tomcat":["Apache Tomcat"],
    "Cloudflare":["cf-ray","cloudflare","__cfduid"],
    "Fastly":["fastly","x-served-by"],
    "AWS CloudFront":["CloudFront","x-amz-cf"],
    "ModSecurity":["Mod_Security","NOYB"],
    "PHP":["X-Powered-By: PHP","PHPSESSID"],
}

class TechDetector:
    def detect(self, headers, body):
        stack = TechStack()
        combined = " ".join(str(v) for v in headers.values()) + " " + (body or "")[:5000]
        for tech, pats in TECH_SIGS.items():
            for p in pats:
                if re.search(re.escape(p), combined, re.IGNORECASE):
                    self._assign(stack, tech); break
        return stack

    def _assign(self, s, t):
        cms = {"WordPress","Joomla","Drupal"}
        srv = {"Apache","Nginx","IIS","Tomcat"}
        cdn = {"Cloudflare","Fastly","AWS CloudFront"}
        waf = {"ModSecurity"}
        frm = {"Django","Laravel","ASP.NET","Spring","Flask","Express"}
        if t in cms: s.cms = t
        elif t in srv: s.server = t
        elif t in cdn: s.cdn = t
        elif t in waf: s.waf = t
        elif t in frm: s.framework = t
        elif t not in s.extras: s.extras.append(t)


# ─────────────────────────────────────────
#  PORT SCANNER
# ─────────────────────────────────────────

class PortScanner:
    def __init__(self, target, profile, rate_limiter=None):
        self.target = target
        self.profile = profile
        self.rl = rate_limiter or RateLimiter(profile["rate_limit"])

    def _resolve(self):
        try: return socket.gethostbyname(self.target)
        except: return None

    def _try_tls(self, port, ip):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=2) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.target) as s:
                    return s.version()
        except: return None

    def _banner(self, port, ip):
        try:
            s = socket.socket(); s.settimeout(self.profile["timeout"]+1)
            s.connect((ip, port)); s.settimeout(1.5)
            try: data = s.recv(1024).decode("utf-8","ignore").strip(); s.close(); return data[:300]
            except: s.close(); return ""
        except: return ""

    def _fingerprint(self, port, ip, banner):
        # HTTP probe
        for p in [80,8080,8000,8888,port]:
            if p == port:
                try:
                    s = socket.socket(); s.settimeout(self.profile["timeout"]+1)
                    s.connect((ip,port))
                    s.send(b"HEAD / HTTP/1.0\r\nHost: "+self.target.encode()+b"\r\n\r\n")
                    r = s.recv(1024).decode("utf-8","ignore"); s.close()
                    if "HTTP/" in r:
                        m = re.search(r"Server: ([^\r\n]+)", r)
                        ver = m.group(1).strip() if m else ""
                        return "HTTP", ver, "HIGH"
                except: pass
                break

        # Protocol signatures
        if banner.startswith("SSH-"):
            m = re.match(r"SSH-[\d.]+-(\S+)", banner)
            return "SSH", m.group(1) if m else "", "HIGH"
        if banner.startswith("220 ") and ("ftp" in banner.lower() or port==21):
            return "FTP", banner[4:60].strip(), "HIGH"

        # Redis probe
        try:
            s = socket.socket(); s.settimeout(2)
            s.connect((ip,port)); s.send(b"*1\r\n$4\r\nPING\r\n")
            r = s.recv(64).decode("utf-8","ignore"); s.close()
            if "PONG" in r: return "Redis","","HIGH"
        except: pass

        svc = SERVICE_DB.get(port, ("Unknown",""))
        ver = ""
        for pat in [r"(OpenSSH[\S]+)",r"(Apache/\S+)",r"(nginx/\S+)",r"(\d+\.\d+[\.\d]*)"]:
            m = re.search(pat, banner, re.IGNORECASE)
            if m: ver = m.group(1); break
        conf = "MEDIUM" if svc[0] != "Unknown" else "LOW"
        return svc[0], ver, conf

    def _scan_port(self, port, ip):
        self.rl.acquire()
        try:
            s = socket.socket(); s.settimeout(self.profile["timeout"])
            if s.connect_ex((ip,port)) != 0: s.close(); return None
            s.close()
            tls_ver = self._try_tls(port,ip) if port in TLS_PORTS else None
            banner  = self._banner(port,ip)
            svc, ver, conf = self._fingerprint(port,ip,banner)
            return OpenPort(port=port,protocol="TCP",service=svc,banner=banner[:200],
                           version=ver or (tls_ver or ""),confidence=conf,
                           tls=bool(tls_ver),fingerprint=f"{svc}/{ver}" if ver else svc)
        except: return None

    def scan(self, port_range=None, extra_ports=None):
        ip = self._resolve()
        if not ip: return [], "unresolvable"
        pr = port_range or self.profile["port_range"]
        ports = list(set(range(pr[0],pr[1]+1)) | set(extra_ports or self.profile.get("extra_ports",[])))
        results = []
        with ThreadPoolExecutor(max_workers=self.profile["threads"]) as ex:
            for f in as_completed({ex.submit(self._scan_port,p,ip):p for p in ports}):
                r = f.result()
                if r: results.append(r)
        return sorted(results, key=lambda x: x.port), ip


# ─────────────────────────────────────────
#  PASSIVE RECON
# ─────────────────────────────────────────

class PassiveRecon:
    def __init__(self, target, timeout=6):
        self.target  = target
        self.host    = re.sub(r'^https?://', '', target).split('/')[0]
        self.timeout = timeout

    def dns_records(self):
        records = {}
        try:
            import subprocess
            for rtype in ["A","AAAA","MX","NS","TXT"]:
                r = subprocess.run(["nslookup",f"-type={rtype}",self.host],
                    capture_output=True, text=True, timeout=5)
                if r.returncode == 0: records[rtype] = r.stdout[:400]
        except:
            try: records["A"] = socket.gethostbyname(self.host)
            except: pass
        return records

    def tls_info(self):
        info = {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host,443),timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw,server_hostname=self.host) as s:
                    cert = s.getpeercert()
                    info["version"] = s.version()
                    info["cipher"]  = s.cipher()
                    info["subject"] = dict(x[0] for x in cert.get("subject",[]))
                    info["issuer"]  = dict(x[0] for x in cert.get("issuer",[]))
                    info["not_after"]  = cert.get("notAfter","")
                    info["san"]     = [v for _,v in cert.get("subjectAltName",[])]
                    try:
                        exp = datetime.strptime(info["not_after"],"%b %d %H:%M:%S %Y %Z")
                        days = (exp - datetime.utcnow()).days
                        info["days_until_expiry"] = days
                        if days < 30: info["expiry_warning"] = f"Expires in {days} days!"
                    except: pass
        except Exception as e: info["error"] = str(e)
        return info

    def http_headers(self):
        for scheme in ("https","http"):
            try:
                url = f"{scheme}://{self.host}/"
                ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, headers={"User-Agent":"ZeroThreat/3.0"})
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                    return dict(r.headers)
            except: pass
        return {}

    def run(self):
        return PassiveInfo(dns_records=self.dns_records(), tls_info=self.tls_info(),
                           headers=self.http_headers())


# ─────────────────────────────────────────
#  NETWORK VULN ANALYZER
# ─────────────────────────────────────────

class VulnAnalyzer:
    def __init__(self, open_ports, internet_exposed=False):
        self.ports = open_ports
        self.pmap  = {p.port: p for p in open_ports}
        self.inet  = internet_exposed

    def analyze(self):
        import copy
        findings = []
        for po in self.ports:
            p = po.port; key = None; ev = ""
            if p==23:    key="TELNET"
            elif p==445: key="SMB"
            elif p==3389:key="RDP"
            elif p==6379:key="REDIS"
            elif p==27017:key="MONGODB"
            elif p==9200:key="ELASTICSEARCH"
            elif p==161: key="SNMP"
            elif p==4444:key="BACKDOOR"
            elif p==5900:key="VNC"
            elif p==2049:key="NFS"
            elif p==8888:key="JUPYTER"
            elif p==11211:key="MEMCACHED"
            elif p==10000:key="WEBMIN"
            elif p==15672:key="RABBITMQ"
            elif p==21:
                b=po.banner.lower()
                if "230" in po.banner or "anonymous" in b:
                    key="FTP_ANON"; ev=f"Anonymous login accepted: {po.banner[:100]}"
                else: key="FTP_PLAIN"

            if not key: continue
            v = copy.deepcopy(NET_VULN_DB[key])
            v["evidence"] = ev or f"Port {p} open | Service: {po.service} | Confidence: {po.confidence}"
            v["evidence_detail"] = {
                "check_id":po.port,"endpoint":f"{po.service}:{p}",
                "triggered_by":"Port open + service identified",
                "confidence":po.confidence,"banner_snippet":po.banner[:150],
            }
            v["internet_exposed"] = self.inet
            v["adjusted_score"]   = self._adj(v)
            findings.append(v)

        findings += self._plugins()
        return findings

    def _adj(self, v):
        s = v["cvss_score"]
        if v.get("internet_exposed"): s = min(10, s+0.5)
        if v.get("auth_required"):    s = max(0,  s-1.0)
        c = v.get("confidence","MEDIUM")
        if c=="LOW":  s = max(0, s-1.5)
        if c=="HIGH": s = min(10, s+0.2)
        return round(s, 1)

    def _plugins(self):
        results = []
        d = Path(__file__).parent/"checks"/"network"
        if not d.exists(): return results
        for f in d.glob("*.py"):
            if f.name.startswith("_"): continue
            try:
                spec = importlib.util.spec_from_file_location(f.stem, f)
                mod  = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod,"run"):
                    r = mod.run(self.ports, self.pmap)
                    if r: results.extend(r if isinstance(r,list) else [r])
            except: pass
        return results


# ─────────────────────────────────────────
#  WEB CRAWLER
# ─────────────────────────────────────────

class WebCrawler:
    def __init__(self, base_url, max_depth=2, max_pages=30, timeout=6, auth_cookies=""):
        self.base  = base_url.rstrip("/")
        self.host  = urllib.parse.urlparse(base_url).netloc
        self.depth = max_depth
        self.pages = max_pages
        self.tout  = timeout
        self.cook  = auth_cookies
        self.seen  = set()
        self.urls  = []
        self.forms = []
        self.params= set()
        self.emails= set()

    def _get(self, url):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            hdrs={"User-Agent":"Mozilla/5.0 ZeroThreat/3.0","Accept":"text/html,*/*"}
            if self.cook: hdrs["Cookie"]=self.cook
            req=urllib.request.Request(url,headers=hdrs)
            with urllib.request.urlopen(req,timeout=self.tout,context=ctx) as r:
                return r.status, r.read(32768).decode("utf-8","ignore")
        except: return 0,""

    def _links(self, base, html):
        links=[]
        for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            h=m.group(1).strip()
            if h.startswith(("#","mailto:","javascript:")): continue
            full=urllib.parse.urljoin(base,h).split("#")[0]
            if urllib.parse.urlparse(full).netloc==self.host: links.append(full)
        return links

    def _forms(self, base, html):
        forms=[]
        for m in re.finditer(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE|re.DOTALL):
            fh=m.group(0)
            a=re.search(r'action=["\']([^"\']*)["\']',fh,re.IGNORECASE)
            mt=re.search(r'method=["\']([^"\']*)["\']',fh,re.IGNORECASE)
            fields=re.findall(r'name=["\']([^"\']+)["\']',fh,re.IGNORECASE)
            action=urllib.parse.urljoin(base,a.group(1)) if a else base
            method=(mt.group(1) if mt else "GET").upper()
            if fields: forms.append({"action":action,"method":method,"fields":list(set(fields))})
        return forms

    def _crawl(self, url, d):
        if d>self.depth or len(self.seen)>=self.pages or url in self.seen: return
        self.seen.add(url)
        status,html=self._get(url)
        if status not in (200,301,302) or not html: return
        self.urls.append(url)
        q=urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        for p in q: self.params.add(p)
        for em in re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', html):
            self.emails.add(em)
        self.forms.extend(self._forms(url,html))
        for link in self._links(url,html): self._crawl(link,d+1)

    def crawl(self):
        self._crawl(self.base,0)
        seen_f=set(); uf=[]
        for f in self.forms:
            k=f["action"]+str(sorted(f["fields"]))
            if k not in seen_f: seen_f.add(k); uf.append(f)
        return CrawlResult(urls=self.urls[:self.pages],forms=uf,
                           params=sorted(self.params),emails=sorted(self.emails))


# ─────────────────────────────────────────
#  WEB SCANNER
# ─────────────────────────────────────────

SENSITIVE_PATHS=[
    "/.env","/.env.local","/.env.backup","/.git/config","/.git/HEAD","/.gitignore",
    "/config.php","/wp-config.php","/backup.zip","/backup.sql","/dump.sql","/database.sql",
    "/.htpasswd","/web.config","/composer.json","/composer.lock","/package.json",
    "/phpinfo.php","/info.php","/server-status","/.DS_Store","/crossdomain.xml",
    "/Dockerfile","/docker-compose.yml","/config.yaml","/settings.py","/.bash_history",
]
ADMIN_PATHS=[
    "/admin","/admin/","/administrator","/phpmyadmin","/wp-admin","/wp-login.php",
    "/cpanel","/manager","/console","/dashboard","/backend","/portal",
    "/login","/adminer.php","/dbadmin","/panel","/admin.php","/user/login",
]
XSS_PAYLOADS=["<script>alert(1)</script>",'"><script>alert(1)</script>',
              "<img src=x onerror=alert(1)>","'><svg/onload=alert(1)>"]
SQLI_PAYLOADS=["'","\"","' OR '1'='1","1' OR 1=1--","' UNION SELECT NULL--"]
SQLI_ERRORS=["sql syntax","mysql_fetch","ora-","unclosed quotation","microsoft ole db",
             "you have an error in your sql","warning: mysql","postgresql error",
             "pg_query()","sqlite_","sqlstate","jdbc","db2 sql error","invalid query",
             "syntax error","mysql_num_rows","pg_exec()","sql command not properly ended"]
REDIRECT_PARAMS=["url","redirect","next","return","goto","redir","dest","target","continue"]

class WebScanner:
    def __init__(self, target, profile, rate_limiter=None, auth_cookies="", auth_headers=None):
        self.target=target.rstrip("/")
        self.profile=profile
        self.rl=rate_limiter or RateLimiter(profile["rate_limit"])
        self.cook=auth_cookies
        self.ahdr=auth_headers or {}
        self.base=("https://"+self.target if not self.target.startswith("http") else self.target)
        self.findings=[]
        self.tech=TechStack()

    def _req(self, url, method="GET", data=None, extra=None):
        self.rl.acquire()
        try:
            hdrs={"User-Agent":"Mozilla/5.0 ZeroThreat/3.0","Accept":"*/*"}
            if self.cook: hdrs["Cookie"]=self.cook
            hdrs.update(self.ahdr)
            if extra: hdrs.update(extra)
            if data: data=urllib.parse.urlencode(data).encode()
            ctx=ssl.create_default_context()
            ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            req=urllib.request.Request(url,data=data,headers=hdrs,method=method)
            with urllib.request.urlopen(req,timeout=8,context=ctx) as r:
                return r.status, r.read(16384).decode("utf-8","ignore"), dict(r.headers)
        except urllib.error.HTTPError as e:
            try: body=e.read(4096).decode("utf-8","ignore")
            except: body=""
            return e.code,body,{}
        except: return 0,"",{}

    def _add(self, key, evidence, endpoint="", param="", req_s="", resp_s="", conf=""):
        import copy
        v=copy.deepcopy(WEB_VULN_DB[key])
        v["evidence"]=evidence
        v["evidence_detail"]={
            "check_id":v["id"],"endpoint":endpoint or self.base,"parameter":param,
            "request_snippet":req_s[:300],"response_snippet":resp_s[:300],
            "triggered_by":key,"confidence":conf or v["confidence"],
        }
        s=v["cvss_score"]
        c=conf or v["confidence"]
        if c=="LOW":  s=max(0,s-1.5)
        if c=="HIGH": s=min(10,s+0.2)
        v["adjusted_score"]=round(s,1)
        self.findings.append(v)

    def check_headers(self):
        st,body,hdrs=self._req(self.base)
        if st==0: st,body,hdrs=self._req(self.base.replace("https://","http://"))
        if not hdrs: return
        self.tech=TechDetector().detect(hdrs,body)
        hl={k.lower():v for k,v in hdrs.items()}
        missing=[]
        specific_map={
            "x-frame-options":"CLICKJACKING","strict-transport-security":"HSTS_MISSING",
            "content-security-policy":"CSP_MISSING",
        }
        fired=set()
        for hdr in ["x-frame-options","x-content-type-options","strict-transport-security",
                    "content-security-policy","referrer-policy","permissions-policy"]:
            if hdr not in hl:
                missing.append(hdr)
                if hdr in specific_map and hdr not in fired:
                    fired.add(hdr)
                    self._add(specific_map[hdr],f"'{hdr}' absent",endpoint=self.base,
                              resp_s=str(list(hdrs.items())[:8]),conf="HIGH")
        if len(missing)>=3:
            self._add("MISSING_HEADERS",f"Missing {len(missing)} headers: {', '.join(missing)}",
                      endpoint=self.base,resp_s=str(list(hdrs.items())[:10]),conf="HIGH")

        srv=hl.get("server",""); pw=hl.get("x-powered-by","")
        if srv or pw:
            self._add("INFO_DISCLOSURE",f"Server: {srv or '—'} | X-Powered-By: {pw or '—'}",
                      endpoint=self.base,resp_s=f"Server: {srv}\nX-Powered-By: {pw}",conf="HIGH")

        if hl.get("access-control-allow-origin","")=="*":
            self._add("CORS_WILDCARD","ACAO: * allows any origin",endpoint=self.base,
                      resp_s="Access-Control-Allow-Origin: *",conf="HIGH")

        sc=hl.get("set-cookie","")
        if sc:
            issues=[x for x,f in [("HttpOnly missing","httponly"),("Secure flag missing","secure"),
                                   ("SameSite not set","samesite")] if f not in sc.lower()]
            if issues:
                self._add("COOKIE_FLAGS",f"Cookie issues: {', '.join(issues)}",
                          endpoint=self.base,resp_s=sc[:200],conf="HIGH")

    def check_ssl(self):
        host=re.sub(r'^https?://','',self.base).split('/')[0]
        try:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            try:
                ctx.minimum_version=ssl.TLSVersion.TLSv1
                ctx.maximum_version=ssl.TLSVersion.TLSv1_1
            except: return
            with socket.create_connection((host,443),timeout=5) as sock:
                with ctx.wrap_socket(sock,server_hostname=host) as s:
                    ver=s.version()
                    self._add("SSL_WEAK",f"Server accepted deprecated {ver}",
                              endpoint=f"https://{host}:443",
                              resp_s=f"TLS handshake OK with {ver}",conf="HIGH")
        except: pass

    def check_sensitive_files(self):
        found=[]
        for path in SENSITIVE_PATHS:
            url=self.base+path
            st,body,_=self._req(url)
            if st==200 and len(body)>10:
                found.append(f"  {path} → HTTP 200 | {body[:60].replace(chr(10),' ')}")
        if found:
            self._add("SENSITIVE_FILES",f"{len(found)} sensitive file(s) accessible:\n"+"\n".join(found),
                      endpoint=self.base,req_s="GET "+"\nGET ".join(SENSITIVE_PATHS[:5]),
                      resp_s=found[0],conf="HIGH")

    def check_admin_panels(self):
        found=[]
        for path in ADMIN_PATHS:
            st,_,_=self._req(self.base+path)
            if st in (200,401,403): found.append(f"  {path} → HTTP {st}")
        if found:
            self._add("ADMIN_EXPOSED",f"{len(found)} admin path(s) found:\n"+"\n".join(found),
                      endpoint=self.base,resp_s="\n".join(found),
                      conf="HIGH" if any("200" in f for f in found) else "MEDIUM")

    def check_dir_listing(self):
        for path in ["/images/","/assets/","/uploads/","/files/","/static/","/css/","/js/"]:
            st,body,_=self._req(self.base+path)
            if st==200 and re.search(r"<title>Index of|Directory listing|Parent Directory",body,re.IGNORECASE):
                self._add("DIR_LISTING",f"Directory listing at: {self.base+path}",
                          endpoint=self.base+path,resp_s=body[:200],conf="HIGH"); return

    def check_xss(self):
        tests=[(self.base+f"/?{p}=PAYLOAD",p) for p in ["q","search","name","input","s"]]
        for payload in XSS_PAYLOADS[:3]:
            for url_t,param in tests[:3]:
                url=url_t.replace("PAYLOAD",urllib.parse.quote(payload))
                st,body,_=self._req(url)
                if st==200 and payload in body:
                    idx=body.find(payload)
                    self._add("XSS",f"XSS reflected for param '{param}'",endpoint=url_t,param=param,
                              req_s=f"GET {url}",resp_s=body[max(0,idx-50):idx+100],conf="HIGH"); return

    def check_sqli(self):
        tests=[(self.base+f"/?{p}=PAYLOAD",p) for p in ["id","user","page","cat"]]
        for payload in SQLI_PAYLOADS[:4]:
            for url_t,param in tests[:3]:
                url=url_t.replace("PAYLOAD",urllib.parse.quote(payload))
                _,body,_=self._req(url)
                bl=body.lower()
                for sig in SQLI_ERRORS:
                    if sig in bl:
                        idx=bl.find(sig)
                        self._add("SQLI",f"SQL error '{sig}' for param '{param}'",endpoint=url_t,param=param,
                                  req_s=f"GET {url}",resp_s=body[max(0,idx-30):idx+100],conf="HIGH"); return

    def check_open_redirect(self):
        for param in REDIRECT_PARAMS:
            url=f"{self.base}/?{param}=https://evil-zerothreat-test.com"
            st,_,hdrs=self._req(url)
            if st in (301,302,303,307,308):
                loc=hdrs.get("Location","") or hdrs.get("location","")
                if "evil-zerothreat-test" in loc:
                    self._add("OPEN_REDIRECT",f"Open redirect via '{param}' → {loc}",endpoint=self.base,
                              param=param,req_s=f"GET {url}",resp_s=f"HTTP {st} Location: {loc}",conf="HIGH"); return

    def _plugins(self, crawl):
        d=Path(__file__).parent/"checks"/"web"
        if not d.exists(): return
        for f in d.glob("*.py"):
            if f.name.startswith("_"): continue
            try:
                spec=importlib.util.spec_from_file_location(f.stem,f)
                mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
                if hasattr(mod,"run"):
                    r=mod.run(self.base,self._req,crawl)
                    if r: self.findings.extend(r if isinstance(r,list) else [r])
            except: pass

    def scan(self, crawl=None):
        for check in [self.check_headers,self.check_ssl,self.check_sensitive_files,
                      self.check_admin_panels,self.check_dir_listing,
                      self.check_xss,self.check_sqli,self.check_open_redirect]:
            try: check()
            except: pass
        self._plugins(crawl)
        return self.findings, self.tech


# ─────────────────────────────────────────
#  SEVERITY ENGINE
# ─────────────────────────────────────────

class SeverityEngine:
    ORDER=["CRITICAL","HIGH","MEDIUM","LOW","INFO"]

    def calculate(self, vulns, internet_exposed=False):
        if not vulns: return 0.0,"MINIMAL"
        scores=[]
        for v in vulns:
            s=v.get("adjusted_score") or v.get("cvss_score",0)
            if internet_exposed: s=min(10,s+0.3)
            scores.append(s)
        scores.sort(reverse=True)
        w=scores[0]*0.5+(sum(scores[1:])/(max(1,len(scores)-1))*0.5 if len(scores)>1 else 0)
        final=min(10,round(w+min(1.5,len(vulns)*0.1),1))
        return final,self._lbl(final)

    def _lbl(self, s):
        if s>=8: return "CRITICAL"
        if s>=6: return "HIGH"
        if s>=4: return "MEDIUM"
        if s>=2: return "LOW"
        return "MINIMAL"

    def summary(self, vulns):
        by_sev={s:0 for s in self.ORDER}
        for v in vulns: by_sev[v.get("severity","INFO")]=by_sev.get(v.get("severity","INFO"),0)+1
        return {"total":len(vulns),"by_severity":by_sev}


# ─────────────────────────────────────────
#  AI RISK ANALYZER
# ─────────────────────────────────────────

class AIRiskAnalyzer:
    def generate(self, target, ports, vulns, score, label, tech=None):
        if not vulns and not ports:
            return (f"Target {target}: No findings in scanned range. "
                    "Consider deep profile or expanded port range.")
        crit=[v for v in vulns if v.get("severity")=="CRITICAL"]
        high=[v for v in vulns if v.get("severity")=="HIGH"]
        med =[v for v in vulns if v.get("severity")=="MEDIUM"]
        pnums={p.get("port") if isinstance(p,dict) else p.port for p in ports}
        lines=[f"## AI Risk Assessment: {target}",
               f"**Overall Risk Score: {score}/10 ({label})**\n",
               f"**Attack Surface:** {len(ports)} open port(s). {len(vulns)} total finding(s)."]

        if tech and any([tech.server,tech.framework,tech.cms,tech.cdn,tech.waf]):
            parts=[x for x in [tech.server,tech.framework,tech.cms,tech.cdn,tech.waf] if x]
            lines.append(f"\n**Technology Stack:** {', '.join(parts)}. "
                         "Check NVD for version-specific CVEs.")
        if tech and tech.waf:
            lines.append(f"\n**WAF Detected ({tech.waf}):** Web application firewall present. "
                         "Some checks may be partially blocked.")

        if crit: lines.append(f"\n**Critical ({len(crit)}):** {', '.join(v['title'] for v in crit[:4])}. "
                               "Exploitable with minimal skill — full compromise risk.")
        if high: lines.append(f"\n**High ({len(high)}):** {', '.join(v['title'] for v in high[:4])}. "
                               "Require prompt remediation.")
        if med:  lines.append(f"\n**Medium ({len(med)}):** {', '.join(v['title'] for v in med[:3])}. "
                               "Compound risk when chained with higher severity findings.")

        if 445 in pnums and 3389 in pnums:
            lines.append("\n**Attack Chain: SMB + RDP** — Classic ransomware delivery vector. Lateral movement + RDP brute-force.")
        if any(p in pnums for p in [6379,27017,9200,11211]):
            lines.append("\n**Attack Chain: Exposed Datastores** — Automated scanners find and exfiltrate/ransom unauth databases within minutes.")
        if 4444 in pnums:
            lines.append("\n**COMPROMISE INDICATOR:** Port 4444 = likely active reverse shell. ISOLATE IMMEDIATELY.")
        if 8888 in pnums:
            lines.append("\n**Critical:** Jupyter Notebook exposed = OS-level code execution for any visitor.")

        if crit+high:
            lines.append(f"\n**Priority Remediation (Top {min(5,len(crit+high))}):**")
            for i,v in enumerate(crit+high,1):
                if i>5: break
                lines.append(f"  {i}. [{v['severity']}] {v['title']} — {v['recommendation']}")
        return "\n".join(lines)


# ─────────────────────────────────────────
#  SARIF EXPORTER
# ─────────────────────────────────────────

class SARIFExporter:
    LEVEL={"CRITICAL":"error","HIGH":"error","MEDIUM":"warning","LOW":"note","INFO":"none"}

    def export(self, result):
        all_vulns=result.vulnerabilities+result.web_findings
        rules=[]; seen=set(); results=[]
        for v in all_vulns:
            rid=v.get("id","UNKNOWN")
            if rid not in seen:
                seen.add(rid)
                rules.append({
                    "id":rid,"name":re.sub(r'[^a-zA-Z0-9]','',v.get("title","")),
                    "shortDescription":{"text":v.get("title","")},
                    "fullDescription":{"text":v.get("description","")},
                    "helpUri":(v.get("references",[""])[0] if v.get("references") else ""),
                    "properties":{"tags":["security",v.get("severity","").lower()],
                                  "security-severity":str(v.get("cvss_score",0))},
                    "defaultConfiguration":{"level":self.LEVEL.get(v.get("severity","INFO"),"note")},
                })
            ed=v.get("evidence_detail",{})
            results.append({
                "ruleId":rid,"level":self.LEVEL.get(v.get("severity","INFO"),"note"),
                "message":{"text":v.get("evidence",v.get("description",""))},
                "locations":[{"physicalLocation":{"artifactLocation":{"uri":ed.get("endpoint",result.target)}}}],
                "partialFingerprints":{"primaryLocationLineHash":hashlib.md5(
                    (rid+ed.get("endpoint","")+ed.get("parameter","")).encode()).hexdigest()},
                "properties":{
                    "confidence":ed.get("confidence","MEDIUM"),"parameter":ed.get("parameter",""),
                    "recommendation":v.get("recommendation",""),
                    "cve_ids":v.get("cve_ids",[]),"cwe_ids":v.get("cwe_ids",[]),
                },
            })
        return {
            "$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version":"2.1.0",
            "runs":[{
                "tool":{"driver":{"name":"ZeroThreat","version":"3.0.0","rules":rules}},
                "invocations":[{"executionSuccessful":True,"startTimeUtc":result.started_at,
                                "endTimeUtc":result.finished_at}],
                "results":results,
                "properties":{"target":result.target,"profile":result.profile,
                              "risk_score":result.risk_score,"risk_label":result.risk_label},
            }]
        }


# ─────────────────────────────────────────
#  MASTER SCANNER
# ─────────────────────────────────────────

class VAPTScanner:
    def __init__(self, target, scan_type="both", profile_name="normal",
                 allowlist=None, owner_confirmed=False, internet_exposed=False,
                 auth_cookies="", auth_headers=None, passive_only=False, log_fn=None):
        self.target=target; self.scan_type=scan_type
        self.profile_name=profile_name; self.profile=SCAN_PROFILES.get(profile_name,SCAN_PROFILES["normal"])
        self.allowlist=allowlist or []; self.owner_confirmed=owner_confirmed
        self.inet=internet_exposed; self.cook=auth_cookies; self.ahdr=auth_headers or {}
        self.passive_only=passive_only
        self.log=log_fn or (lambda m,p=None: print(m))
        self.rl=RateLimiter(self.profile["rate_limit"])
        self.scan_id=hashlib.md5(f"{target}{time.time()}".encode()).hexdigest()[:12]

    def run(self):
        started=datetime.now(timezone.utc).isoformat()
        res=ScanResult(target=self.target,scan_type=self.scan_type,
                       profile=self.profile_name,started_at=started,scan_id=self.scan_id)

        # Scope check
        scope=ScopeEngine(self.allowlist,self.owner_confirmed)
        ok,reason=scope.is_allowed(self.target)
        res.scope_status=reason
        if not ok:
            res.host_status="scope-blocked"; res.ai_analysis=f"SCAN BLOCKED: {reason}"
            res.finished_at=datetime.now(timezone.utc).isoformat()
            self.log(f"[!] SCOPE BLOCKED: {reason}"); return res
        self.log(f"[✓] Scope: {reason}")
        self.log(f"[*] Profile: {self.profile_name} — {self.profile['description']}")

        engine=SeverityEngine(); all_vulns=[]; open_port_objs=[]

        # Passive recon
        self.log("[*] Phase 0: Passive Recon (DNS, TLS, Headers)...")
        pr=PassiveRecon(self.target); passive=pr.run()
        res.passive_info=asdict(passive)
        self.log(f"[+] TLS: {passive.tls_info.get('version','N/A')} | DNS records: {len(passive.dns_records)}")
        if passive.tls_info.get("expiry_warning"):
            self.log(f"[!] {passive.tls_info['expiry_warning']}")

        if self.passive_only:
            res.finished_at=datetime.now(timezone.utc).isoformat()
            res.summary=engine.summary([]); res.risk_score=0.0; res.risk_label="MINIMAL"
            return res

        # Network
        if self.scan_type in ("network","both"):
            self.log("[*] Phase 1: Port & Service Discovery...")
            ps=PortScanner(self.target,self.profile,self.rl)
            ports,ip=ps.scan()
            res.open_ports=[asdict(p) for p in ports]
            res.host_status="up" if ip!="unresolvable" else "down"
            open_port_objs=ports
            self.log(f"[+] {len(ports)} open port(s)")

            self.log("[*] Phase 2: Network Vulnerability Analysis...")
            va=VulnAnalyzer(ports,self.inet)
            nvulns=va.analyze()
            all_vulns.extend(nvulns); res.vulnerabilities=nvulns
            self.log(f"[+] Network findings: {len(nvulns)}")

        # Crawl
        crawl=None
        if self.scan_type in ("webapp","both") and self.profile.get("crawl_depth",0)>0:
            self.log("[*] Phase 3a: Web Crawling...")
            base=(self.target if self.target.startswith("http") else "https://"+self.target)
            c=WebCrawler(base,self.profile["crawl_depth"],self.profile["crawl_pages"],auth_cookies=self.cook)
            crawl=c.crawl(); res.crawl_result=asdict(crawl)
            self.log(f"[+] {len(crawl.urls)} URLs | {len(crawl.forms)} forms | {len(crawl.params)} params")

        # Web
        if self.scan_type in ("webapp","both"):
            self.log("[*] Phase 3b: Web Application Scanning...")
            ws=WebScanner(self.target,self.profile,self.rl,self.cook,self.ahdr)
            wvulns,tech=ws.scan(crawl)
            all_vulns.extend(wvulns); res.web_findings=wvulns; res.tech_stack=asdict(tech)
            self.log(f"[+] Web findings: {len(wvulns)} | Stack: {tech.server or tech.framework or tech.cms or 'unknown'}")

        # AI + Score
        self.log("[*] Phase 4: AI Risk Analysis...")
        score,label=engine.calculate(all_vulns,self.inet)
        res.risk_score=score; res.risk_label=label; res.summary=engine.summary(all_vulns)

        tech_obj=TechStack(**(res.tech_stack if res.tech_stack else {}))
        ai=AIRiskAnalyzer()
        res.ai_analysis=ai.generate(self.target,[asdict(p) for p in open_port_objs],
                                    all_vulns,score,label,tech_obj)
        res.finished_at=datetime.now(timezone.utc).isoformat()
        self.log(f"[✓] Done | Risk: {score}/10 ({label}) | Findings: {res.summary['total']}")
        return res

    def export_sarif(self, result): return SARIFExporter().export(result)


# ─────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────

if __name__=="__main__":
    target  =sys.argv[1] if len(sys.argv)>1 else "scanme.nmap.org"
    stype   =sys.argv[2] if len(sys.argv)>2 else "both"
    profile =sys.argv[3] if len(sys.argv)>3 else "normal"
    scanner=VAPTScanner(target=target,scan_type=stype,profile_name=profile,owner_confirmed=True)
    res=scanner.run()
    ts=int(time.time())
    slug=target.replace("/","_").replace(":","")
    with open(f"scan_{slug}_{ts}.json","w") as f: json.dump(asdict(res),f,indent=2)
    with open(f"scan_{slug}_{ts}.sarif","w") as f: json.dump(scanner.export_sarif(res),f,indent=2)
    print(f"\n[✓] Saved: scan_{slug}_{ts}.json + .sarif")
    print(res.ai_analysis)
