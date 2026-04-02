#!/usr/bin/env python3


import os
import re
import sys
import json
import time
import socket
import tarfile
import zipfile
import hashlib
import argparse
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================
# CORES ANSI
# ============================================================
class C:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def cor_sev(sev):
    return {
        "critical": C.RED + C.BOLD,
        "high":     C.RED,
        "medium":   C.YELLOW,
        "low":      C.CYAN,
    }.get(sev, C.RESET)

BANNER = f"""
{C.CYAN}{C.BOLD}
 ██╗     ███████╗ █████╗ ██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
 ██║     ██╔════╝██╔══██╗██║ ██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██║     █████╗  ███████║█████╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██║     ██╔══╝  ██╔══██║██╔═██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ███████╗███████╗██║  ██║██║  ██╗██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{C.RESET}
{C.YELLOW}  Attack Surface Recon & Sensitive Data Exposure Scanner{C.RESET}
{C.RED}  ⚠  Use somente em alvos com autorização explícita{C.RESET}
"""

# ============================================================
# ARGUMENTOS CLI
# ============================================================
def parse_args():
    p = argparse.ArgumentParser(
        description="Recon avançado para Bug Bounty",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Exemplos:
  python3 coleta_dados.py exemplo.com
  python3 coleta_dados.py exemplo.com --threads 20 --katana-depth 5
  python3 coleta_dados.py exemplo.com --sem-subdomain --min-severity high
  python3 coleta_dados.py exemplo.com --scope-file meus_subs.txt
  python3 coleta_dados.py exemplo.com --sem-download   # só coleta URLs
""")
    p.add_argument("dominio",          nargs="?", default=None)
    p.add_argument("--threads",        type=int,  default=10)
    p.add_argument("--timeout",        type=int,  default=30)
    p.add_argument("--max-size",       type=int,  default=10,   help="MB máximo por arquivo (padrão: 10)")
    p.add_argument("--katana-depth",   type=int,  default=3,    help="Profundidade do katana (padrão: 3)")
    p.add_argument("--min-severity",   choices=["low","medium","high","critical"], default="low")
    p.add_argument("--sem-katana",     action="store_true")
    p.add_argument("--sem-gau",        action="store_true")
    p.add_argument("--sem-wayback",    action="store_true")
    p.add_argument("--sem-subdomain",  action="store_true")
    p.add_argument("--sem-download",   action="store_true")
    p.add_argument("--scope-file",     type=str,  default=None, help="Arquivo .txt com subdomínios no escopo")
    return p.parse_args()

CONFIG = {}
LOCK   = threading.Lock()

# ============================================================
# EXTENSÕES
# ============================================================
EXTS_INTERESSE = (
    ".js", ".json", ".map", ".env", ".log", ".bak", ".old", ".zip", ".tar",
    ".gz", ".tgz", ".7z", ".rar", ".conf", ".config", ".ini", ".yaml", ".yml",
    ".sql", ".xml", ".txt", ".pdf", ".doc", ".docx", ".csv", ".pem", ".key",
    ".crt", ".pfx", ".p12", ".db", ".sqlite", ".sqlite3", ".backup", ".swp",
    ".sh", ".bash", ".htaccess", ".htpasswd", ".npmrc", ".netrc", ".toml",
    ".lock", ".properties", ".gradle", ".DS_Store",
)
EXTS_SENSIVEIS = (
    ".env", ".bak", ".old", ".zip", ".tar", ".gz", ".tgz", ".sql", ".pem",
    ".key", ".pfx", ".p12", ".db", ".sqlite", ".sqlite3", ".backup", ".config",
    ".ini", ".yaml", ".yml", ".conf", ".htpasswd", ".netrc", ".npmrc",
)
EXTS_CRITICAS = (
    ".env", ".sql", ".pem", ".key", ".pfx", ".p12", ".db", ".sqlite",
    ".sqlite3", ".htpasswd", ".netrc", ".npmrc",
)

SEVERITY_ORDER  = {"low": 1, "medium": 2, "high": 3, "critical": 4}
RETRY           = 3
ROBOTS_STATUS   = {"200", "204", "301", "302", "401", "403"}

# ============================================================
# PADRÕES DE DETECÇÃO
# ============================================================
PATTERNS = {
    # ── Tokens / Auth ──────────────────────────────────────
    "JWT": {
        "regex": r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+\b",
        "severity": "high",
    },
    "Bearer Token": {
        "regex": r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b",
        "severity": "high",
    },
    "Basic Auth": {
        "regex": r"\bBasic\s+[A-Za-z0-9+/=]{8,}\b",
        "severity": "medium",
    },
    # ── AWS ────────────────────────────────────────────────
    "AWS Access Key": {
        "regex": r"\bAKIA[0-9A-Z]{16}\b",
        "severity": "critical",
    },
    "AWS Secret Key": {
        "regex": r"""(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[:=]\s*['"]?[A-Za-z0-9/+]{40}['"]?""",
        "severity": "critical",
    },
    # ── Google ─────────────────────────────────────────────
    "Google API Key": {
        "regex": r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "severity": "high",
    },
    "Google OAuth Client": {
        "regex": r"\b[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com\b",
        "severity": "medium",
    },
    "Firebase URL": {
        "regex": r"\bhttps://[a-z0-9-]+\.firebaseio\.com\b",
        "severity": "medium",
    },
    # ── Stripe ─────────────────────────────────────────────
    "Stripe Secret Key": {
        "regex": r"\bsk_live_[0-9a-zA-Z]{16,}\b",
        "severity": "critical",
    },
    "Stripe Publishable Key": {
        "regex": r"\bpk_live_[0-9a-zA-Z]{16,}\b",
        "severity": "low",
    },
    # ── Comunicação ────────────────────────────────────────
    "Twilio SID": {
        "regex": r"\bAC[a-z0-9]{32}\b",
        "severity": "high",
    },
    "SendGrid API Key": {
        "regex": r"\bSG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{43,}\b",
        "severity": "critical",
    },
    "Mailgun API Key": {
        "regex": r"\bkey-[0-9a-zA-Z]{32}\b",
        "severity": "high",
    },
    "Mailchimp API Key": {
        "regex": r"\b[0-9a-f]{32}-us[0-9]{1,2}\b",
        "severity": "high",
    },
    # ── Repositórios / CI ──────────────────────────────────
    "GitHub Token": {
        "regex": r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
        "severity": "critical",
    },
    "GitLab Token": {
        "regex": r"\bglpat-[A-Za-z0-9\-_]{20,}\b",
        "severity": "critical",
    },
    "NPM Token": {
        "regex": r"\bnpm_[A-Za-z0-9]{36}\b",
        "severity": "critical",
    },
    # ── Slack ──────────────────────────────────────────────
    "Slack Token": {
        "regex": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        "severity": "critical",
    },
    "Slack Webhook": {
        "regex": r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
        "severity": "critical",
    },
    # ── PKI / Chaves ───────────────────────────────────────
    "Private Key": {
        "regex": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
        "severity": "critical",
    },
    "Certificate": {
        "regex": r"-----BEGIN CERTIFICATE-----",
        "severity": "medium",
    },
    # ── Credenciais genéricas ──────────────────────────────
    "Password Assignment": {
        "regex": r"""(?i)\b(password|passwd|pwd|senha|secret|token|api[_-]?key)\b\s*[:=]\s*['"][^'"]{6,}['"]""",
        "severity": "high",
    },
    "Hardcoded Secret": {
        "regex": r"""(?i)\b(api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['"][A-Za-z0-9\-_=+/]{10,}['"]""",
        "severity": "high",
    },
    "Env File Secret": {
        "regex": r"""(?im)^(DB_PASSWORD|DATABASE_URL|AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY|TOKEN|ACCESS_TOKEN|PRIVATE_KEY|MAIL_PASSWORD|SMTP_PASS|REDIS_URL|MONGO_URI)\s*=\s*.+$""",
        "severity": "critical",
    },
    "Connection String": {
        "regex": r"""(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|oracle):\/\/[^\s"'<>]+""",
        "severity": "critical",
    },
    # ── Cloud Storage ──────────────────────────────────────
    "S3 Bucket": {
        "regex": r"\b[a-z0-9.\-]+\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com\b",
        "severity": "medium",
    },
    "Azure Storage": {
        "regex": r"\b[a-z0-9]+\.blob\.core\.windows\.net\b",
        "severity": "medium",
    },
    "GCP Storage": {
        "regex": r"\bstorage\.googleapis\.com/[a-z0-9\-_]+\b",
        "severity": "medium",
    },
    # ── Infraestrutura ─────────────────────────────────────
    "Internal URL": {
        "regex": r"""https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|localhost)(?::\d+)?[^\s"']*""",
        "severity": "medium",
    },
    "IP Address": {
        "regex": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "severity": "low",
    },
    # ── Web vulnerabilidades ───────────────────────────────
    "Open Redirect": {
        "regex": r"""(?i)[?&](?:redirect|return|url|next|goto|redir|redirect_uri|callback)\s*=\s*https?://""",
        "severity": "medium",
    },
    "GraphQL Endpoint": {
        "regex": r"(?i)(/__graphql|/graphql\?|/api/graphql|introspectionQuery)",
        "severity": "low",
    },
    "Sentry DSN": {
        "regex": r"https://[a-zA-Z0-9]+@[a-zA-Z0-9.-]+\.ingest\.sentry\.io/\d+",
        "severity": "low",
    },
    "Source Map": {
        "regex": r"//# sourceMappingURL=(.+\.map)",
        "severity": "low",
    },
    # ── Código / Debug ─────────────────────────────────────
    "Debug Artifact": {
        "regex": r"(?i)\b(console\.log|debugger|window\.debug)\b",
        "severity": "low",
    },
    "Admin / Role Reference": {
        "regex": r"(?i)\b(isAdmin|isSuperAdmin|impersonate|role_impersonate|superadmin)\b",
        "severity": "medium",
    },
    "XSS Vector": {
        "regex": r"""(?i)(eval\s*\(|innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\()""",
        "severity": "medium",
    },
    "Prototype Pollution": {
        "regex": r"""(?i)(__proto__|constructor\[prototype\]|Object\.prototype\.)""",
        "severity": "medium",
    },
    # ── JS Endpoints ───────────────────────────────────────
    "Hidden API Endpoint": {
        "regex": r"""['"`](/(?:api|v\d|internal|admin|graphql|rest|backend|private|auth|oauth|user|account)/[^\s'"`?#]{2,})['"`]""",
        "severity": "medium",
    },
    "Absolute API URL": {
        "regex": r"""['"`](https?://[^'"`\s]{10,})['"`]""",
        "severity": "low",
    },
    # ── Misc ───────────────────────────────────────────────
    "Email": {
        "regex": r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b",
        "severity": "low",
    },
}

KEYWORDS_JS = [
    "Authorization", "Bearer ", "apiKey", "clientSecret", "secretKey",
    "accessToken", "refreshToken", "document.cookie", "localStorage.setItem",
    "sessionStorage.setItem", "fetch(", "axios.", "XMLHttpRequest",
    "impersonate", "isAdmin", "isSuperAdmin", "eval(", "innerHTML",
    "dangerouslySetInnerHTML", "postMessage", "__proto__",
    "Access-Control-Allow-Origin", "withCredentials", "cors",
]

# ============================================================
# UTILITÁRIOS
# ============================================================
def log(msg, cor=C.RESET):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{C.DIM}[{ts}]{C.RESET} {cor}{msg}{C.RESET}")


def aviso_tool(nome, install_cmd):
    log(f"{nome} não encontrado → instale: {install_cmd}", C.YELLOW)


def cmd_exists(name):
    try:
        subprocess.run([name, "--version"], capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def is_interesting_url(url):
    try:
        path = urlparse(url).path.lower()
        return (
            path.endswith(EXTS_INTERESSE)
            or path.endswith("/robots.txt")
            or path == "/robots.txt"
            or "/.git/config" in path
            or "/.env" in path
            or "backup" in path
        )
    except Exception:
        return False


def is_js_url(url):
    try:
        return urlparse(url).path.lower().endswith((".js", ".map", ".ts"))
    except Exception:
        return False


def unique_filename(url):
    parsed = urlparse(url)
    base   = os.path.basename(parsed.path) or "sem_nome"
    digest = hashlib.md5(url.encode()).hexdigest()[:10]
    if parsed.path.lower().endswith("/robots.txt"):
        base = "robots.txt"
    return f"{digest}_{base}"


def try_decode(path):
    raw = path.read_bytes()
    for enc in ("utf-8", "latin-1", "utf-16"):
        try:
            return raw.decode(enc, errors="ignore")
        except Exception:
            continue
    return ""


def is_binary(path):
    try:
        return b"\x00" in path.read_bytes()[:2048]
    except Exception:
        return True


def get_context(content, start, end, radius=120):
    l = max(0, start - radius)
    r = min(len(content), end + radius)
    return content[l:r].replace("\n", " ")[:300]


def line_number(content, index):
    return content.count("\n", 0, index) + 1


def extract_base(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


# ============================================================
# ENUMERAÇÃO DE SUBDOMÍNIOS
# ============================================================
def enum_subdomains(domain, scope_file=None):
    log("Iniciando enumeração de subdomínios...", C.CYAN)
    subs = set()

    if scope_file:
        try:
            with open(scope_file) as f:
                for line in f:
                    s = line.strip()
                    if s:
                        subs.add(s)
            log(f"scope file: {len(subs)} subdomínios carregados", C.GREEN)
        except Exception as e:
            log(f"Erro ao ler scope file: {e}", C.YELLOW)

    # subfinder
    if cmd_exists("subfinder"):
        try:
            r = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True, text=True, timeout=300
            )
            antes = len(subs)
            for line in r.stdout.splitlines():
                s = line.strip()
                if s:
                    subs.add(s)
            log(f"subfinder: +{len(subs)-antes} subdomínios", C.GREEN)
        except subprocess.TimeoutExpired:
            log("subfinder: timeout", C.YELLOW)
        except Exception as e:
            log(f"subfinder erro: {e}", C.YELLOW)
    else:
        aviso_tool("subfinder", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")

    # assetfinder
    if cmd_exists("assetfinder"):
        try:
            r = subprocess.run(
                ["assetfinder", "--subs-only", domain],
                capture_output=True, text=True, timeout=120
            )
            antes = len(subs)
            for line in r.stdout.splitlines():
                s = line.strip()
                if s:
                    subs.add(s)
            log(f"assetfinder: +{len(subs)-antes} subdomínios", C.GREEN)
        except Exception as e:
            log(f"assetfinder erro: {e}", C.YELLOW)
    else:
        aviso_tool("assetfinder", "go install github.com/tomnomnom/assetfinder@latest")

    # amass (opcional, mais lento)
    if cmd_exists("amass"):
        try:
            r = subprocess.run(
                ["amass", "enum", "-passive", "-d", domain],
                capture_output=True, text=True, timeout=180
            )
            antes = len(subs)
            for line in r.stdout.splitlines():
                s = line.strip()
                if s:
                    subs.add(s)
            log(f"amass: +{len(subs)-antes} subdomínios", C.GREEN)
        except Exception:
            pass

    # Fallback sem dependências: crt.sh
    if not subs:
        subs.update(crtsh_enum(domain))

    log(f"Total subdomínios encontrados: {len(subs)}", C.GREEN)
    return subs


def crtsh_enum(domain):
    subs = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for entry in data:
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.")
                    if name and domain in name:
                        subs.add(name)
        log(f"crt.sh fallback: {len(subs)} subdomínios", C.GREEN)
    except Exception as e:
        log(f"crt.sh erro: {e}", C.YELLOW)
    return subs


def probe_subdomains(subs, threads=20):
    """Verifica subdomínios ativos via httpx ou DNS."""
    log(f"Verificando {len(subs)} subdomínios ativos...", C.CYAN)
    ativos = set()

    if cmd_exists("httpx"):
        try:
            entrada = "\n".join(subs)
            r = subprocess.run(
                ["httpx", "-silent", "-no-color"],
                input=entrada, capture_output=True, text=True, timeout=300
            )
            for line in r.stdout.splitlines():
                url = line.strip().split()[0] if line.strip() else ""
                if url:
                    ativos.add(url)
            log(f"httpx: {len(ativos)} subdomínios ativos", C.GREEN)
            return ativos
        except Exception as e:
            log(f"httpx erro: {e}", C.YELLOW)
    else:
        aviso_tool("httpx", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest")

    # Fallback: resolução DNS
    def resolve(sub):
        try:
            socket.getaddrinfo(sub, 80, proto=socket.IPPROTO_TCP)
            return f"http://{sub}"
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        for result in as_completed({ex.submit(resolve, s): s for s in subs}):
            r = result.result()
            if r:
                ativos.add(r)

    log(f"DNS probe: {len(ativos)} subdomínios ativos", C.GREEN)
    return ativos


# ============================================================
# COLETA DE URLs
# ============================================================
def collect_katana(target, depth=3):
    urls = set()
    if not cmd_exists("katana"):
        aviso_tool("katana", "go install github.com/projectdiscovery/katana/cmd/katana@latest")
        return urls
    log(f"katana → {target} (depth={depth})", C.CYAN)
    try:
        r = subprocess.run(
            [
                "katana", "-u", target,
                "-d", str(depth),
                "-jc",                    # JS crawling (extrai endpoints/imports de arquivos JS)
                "-kf", "all",             # extrai forms, scripts, links
                "-ef", "png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",
                "-silent", "-nc",
                "-timeout", "10",
            ],
            capture_output=True, text=True, timeout=600
        )
        for line in r.stdout.splitlines():
            line = line.strip()
            if line:
                urls.add(line)
        log(f"katana: {len(urls)} URLs coletadas", C.GREEN)
    except subprocess.TimeoutExpired:
        log("katana: timeout", C.YELLOW)
    except Exception as e:
        log(f"katana erro: {e}", C.YELLOW)
    return urls


def collect_gau(domain):
    urls = set()
    if not cmd_exists("gau"):
        aviso_tool("gau", "go install github.com/lc/gau/v2/cmd/gau@latest")
        return urls
    try:
        r = subprocess.run(["gau", domain], capture_output=True, text=True, timeout=300)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line and is_interesting_url(line):
                urls.add(line)
        log(f"gau: {len(urls)} URLs relevantes", C.GREEN)
    except Exception as e:
        log(f"gau erro: {e}", C.YELLOW)
    return urls


def collect_wayback(domain):
    urls = set()
    if not cmd_exists("waybackurls"):
        aviso_tool("waybackurls", "go install github.com/tomnomnom/waybackurls@latest")
        return urls
    try:
        r = subprocess.run(["waybackurls"], input=domain, capture_output=True, text=True, timeout=300)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line and is_interesting_url(line):
                urls.add(line)
        log(f"waybackurls: {len(urls)} URLs relevantes", C.GREEN)
    except Exception as e:
        log(f"waybackurls erro: {e}", C.YELLOW)
    return urls


def collect_cdx(domain):
    """Fallback sem dependências via Wayback CDX API."""
    urls = set()
    cdx = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=5000"
    )
    try:
        req = Request(cdx, headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=60) as resp:
            for line in resp.read().decode("utf-8").splitlines():
                line = line.strip()
                if line and is_interesting_url(line):
                    urls.add(line)
        log(f"CDX API fallback: {len(urls)} URLs", C.GREEN)
    except Exception as e:
        log(f"CDX API erro: {e}", C.YELLOW)
    return urls


def collect_all_urls(targets, args):
    all_urls = set()
    all_js   = set()

    for target in targets:
        domain = urlparse(target).netloc or target.lstrip("http://").lstrip("https://").split("/")[0]

        if not args.sem_katana:
            ku = collect_katana(target, depth=args.katana_depth)
            all_urls.update(ku)
            all_js.update(u for u in ku if is_js_url(u))

        if not args.sem_gau:
            gu = collect_gau(domain)
            all_urls.update(gu)
            all_js.update(u for u in gu if is_js_url(u))

        if not args.sem_wayback:
            wu = collect_wayback(domain)
            all_urls.update(wu)
            all_js.update(u for u in wu if is_js_url(u))

    # Fallback caso nenhuma ferramenta esteja instalada
    if not all_urls:
        for target in targets:
            domain = urlparse(target).netloc or target
            cdx = collect_cdx(domain)
            all_urls.update(cdx)
            all_js.update(u for u in cdx if is_js_url(u))

    download_urls = {u for u in all_urls if is_interesting_url(u)}
    all_js.update(u for u in download_urls if is_js_url(u))

    return download_urls, all_js


# ============================================================
# DOWNLOAD
# ============================================================
def download_file(url, dest):
    timeout  = CONFIG["timeout"]
    max_size = CONFIG["max_size"]
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"})
    for attempt in range(1, RETRY + 1):
        try:
            with urlopen(req, timeout=timeout) as resp:
                if getattr(resp, "status", 200) >= 400:
                    return False
                cl = resp.headers.get("Content-Length")
                if cl:
                    try:
                        if int(cl) > max_size:
                            return False
                    except ValueError:
                        pass
                data = resp.read(max_size + 1)
                if len(data) > max_size:
                    return False
                dest.write_bytes(data)
                return True
        except (socket.timeout, URLError):
            pass
        except HTTPError as e:
            if e.code in (404, 410, 403):
                return False
        except Exception:
            pass
        if attempt < RETRY:
            time.sleep(1)
    return False


def batch_download(urls, download_dir, sensitive_dir):
    tasks = []
    for url in sorted(urls):
        fname   = unique_filename(url)
        path    = urlparse(url).path.lower()
        is_sens = path.endswith(EXTS_SENSIVEIS)
        dest    = (sensitive_dir if is_sens else download_dir) / fname
        tasks.append((url, dest))

    downloaded = []
    url_map    = {}
    total      = len(tasks)

    log(f"Baixando {total} arquivos com {CONFIG['threads']} threads...", C.CYAN)

    def worker(task):
        url, dest = task
        ok = download_file(url, dest)
        return url, dest, ok

    with ThreadPoolExecutor(max_workers=CONFIG["threads"]) as ex:
        futures = {ex.submit(worker, t): t for t in tasks}
        done = 0
        for fut in as_completed(futures):
            done += 1
            url, dest, ok = fut.result()
            sys.stdout.write(f"\r    [{done}/{total}] baixados...")
            sys.stdout.flush()
            if ok:
                downloaded.append(dest)
                url_map[str(dest)] = url
                if dest.name.lower().endswith(EXTS_CRITICAS):
                    print()
                    log(f"ARQUIVO CRÍTICO BAIXADO: {dest}", C.RED + C.BOLD)
    print()
    return downloaded, url_map


# ============================================================
# EXTRAÇÃO DE ARQUIVOS
# ============================================================
def extract_archive(path, out_dir):
    extracted = []
    lower = path.name.lower()
    try:
        if lower.endswith(".zip"):
            target = out_dir / path.stem
            target.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(path, "r") as zf:
                zf.extractall(target)
                extracted.extend(p for p in target.rglob("*") if p.is_file())
        elif lower.endswith((".tar", ".tgz", ".tar.gz")):
            target = out_dir / path.stem.replace(".tar", "")
            target.mkdir(parents=True, exist_ok=True)
            with tarfile.open(path, "r:*") as tf:
                tf.extractall(target)
                extracted.extend(p for p in target.rglob("*") if p.is_file())
    except Exception:
        pass
    return extracted


def extract_content(path):
    lower = path.name.lower()
    if lower.endswith(".pdf"):
        return _extract_pdf(path)
    if lower.endswith(".docx"):
        return _extract_docx(path)
    if is_binary(path) and not lower.endswith((
        ".json", ".js", ".map", ".xml", ".txt", ".log", ".sql", ".conf",
        ".config", ".ini", ".yaml", ".yml", ".env", ".csv", ".sh",
        ".toml", ".properties", ".htaccess", ".htpasswd", ".netrc", ".npmrc",
    )):
        return ""
    return try_decode(path)


def _extract_pdf(path):
    try:
        import pypdf
        texts = []
        with open(path, "rb") as f:
            reader = pypdf.PdfReader(f)
            for page in reader.pages:
                texts.append(page.extract_text() or "")
        return "\n".join(texts)
    except ModuleNotFoundError:
        log("pypdf não instalado: pip install pypdf", C.YELLOW)
        return ""
    except Exception:
        return ""


def _extract_docx(path):
    try:
        import xml.etree.ElementTree as ET
        with zipfile.ZipFile(path) as docx:
            xml_content = docx.read("word/document.xml")
        root = ET.fromstring(xml_content)
        return "\n".join(n.text for n in root.iter() if n.tag.endswith("}t") and n.text)
    except Exception:
        return ""


# ============================================================
# ANÁLISE DE CONTEÚDO
# ============================================================
def extract_js_endpoints(content):
    """Extrai endpoints e URLs ocultas de arquivos JS."""
    endpoints = set()
    # Paths de API relativos
    for m in re.finditer(
        r"""['"`](/(?:api|v\d+|internal|admin|graphql|rest|backend|private|auth|oauth|user|account)/[^\s'"`?#]{2,})['"`]""",
        content
    ):
        endpoints.add(m.group(1))
    # URLs absolutas
    for m in re.finditer(r"""['"`](https?://[^'"`\s]{10,})['"`]""", content):
        endpoints.add(m.group(1))
    # import / require
    for m in re.finditer(r"""(?:import|require)\s*\(?['"`]([^'"`]+)['"`]\)?""", content):
        val = m.group(1)
        if val.startswith("http") or val.startswith("/"):
            endpoints.add(val)
    return endpoints


def analyze_content(content, file_path):
    findings = []
    seen     = set()

    # Regex patterns
    for name, meta in PATTERNS.items():
        try:
            pattern = re.compile(meta["regex"])
        except re.error:
            continue
        for m in pattern.finditer(content):
            found = m.group(0)
            key   = (name, found)
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "type":     name,
                "severity": meta["severity"],
                "file":     str(file_path),
                "line":     line_number(content, m.start()),
                "match":    found[:300],
                "context":  get_context(content, m.start(), m.end()),
            })

    # Análise extra para arquivos JS
    lower = file_path.name.lower()
    if lower.endswith((".js", ".map", ".ts")):
        # Endpoints descobertos
        for ep in extract_js_endpoints(content):
            findings.append({
                "type":     "JS Endpoint Discovered",
                "severity": "low",
                "file":     str(file_path),
                "line":     0,
                "match":    ep,
                "context":  "",
            })
        # Keywords sensíveis
        kw_seen = set()
        for kw in KEYWORDS_JS:
            for m in re.finditer(re.escape(kw), content, re.IGNORECASE):
                k = ("JS Keyword", kw, line_number(content, m.start()))
                if k in kw_seen:
                    continue
                kw_seen.add(k)
                findings.append({
                    "type":     "JS Sensitive Keyword",
                    "severity": "low",
                    "file":     str(file_path),
                    "line":     line_number(content, m.start()),
                    "match":    kw,
                    "context":  get_context(content, m.start(), m.end()),
                })

    return findings


# ============================================================
# ROBOTS.TXT
# ============================================================
def parse_robots(content):
    paths = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key   = key.strip().lower()
        value = value.strip()
        if key in ("disallow", "allow") and value and value != "/":
            if value.startswith("http"):
                try:
                    p = urlparse(value)
                    value = p.path or "/"
                    if p.query:
                        value += "?" + p.query
                except Exception:
                    continue
            if not value.startswith("/"):
                value = "/" + value
            paths.add(value)
    return sorted(paths)


def check_robots_paths(content, source_url):
    findings = []
    base  = extract_base(source_url)
    paths = parse_robots(content)
    if not paths:
        return findings

    log(f"robots.txt: testando {len(paths)} caminhos em {base}", C.CYAN)
    seen = set()

    def test_path(path):
        full = base + path
        if full in seen:
            return None
        seen.add(full)
        try:
            result = subprocess.run(
                ["curl", "-k", "-L", "-s", "-o", "/dev/null",
                 "-w", "%{http_code}|%{content_type}|%{size_download}",
                 "--max-time", "15", full],
                capture_output=True, text=True, timeout=20
            )
            out = result.stdout.strip()
            if "|" in out:
                code, ctype, size = out.split("|", 2)
                return full, code, ctype, size
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(test_path, p) for p in paths]
        for fut in as_completed(futures):
            res = fut.result()
            if not res:
                continue
            full, code, ctype, size = res
            if code not in ROBOTS_STATUS:
                continue
            sev = "medium" if code in ("200", "204", "401", "403") else "low"
            findings.append({
                "type":     "Robots Path Exposure",
                "severity": sev,
                "file":     source_url,
                "line":     0,
                "match":    full,
                "context":  f"status={code} content_type={ctype} size={size}",
            })
            if code in ("200", "401", "403"):
                cor = C.RED if code == "200" else C.YELLOW
                log(f"robots: {full} → HTTP {code}", cor)

    return findings


# ============================================================
# ALERTA EM TEMPO REAL
# ============================================================
def alert(finding, min_sev):
    if SEVERITY_ORDER.get(finding["severity"], 0) < SEVERITY_ORDER.get(min_sev, 0):
        return
    cor = cor_sev(finding["severity"])
    with LOCK:
        print(f"\n{cor}{'━'*60}{C.RESET}")
        print(f"{cor}[{finding['severity'].upper()}] {finding['type']}{C.RESET}")
        print(f"  Arquivo : {finding['file']}")
        if finding.get("line"):
            print(f"  Linha   : {finding['line']}")
        print(f"  Match   : {finding['match'][:200]}")
        if finding.get("context"):
            print(f"  Contexto: {finding['context'][:200]}")
        print(f"{cor}{'━'*60}{C.RESET}\n")


# ============================================================
# RELATÓRIOS (TXT + JSON + HTML interativo)
# ============================================================
def save_reports(findings, dominio, base_dir):
    report_txt  = base_dir / f"relatorio_{dominio}.txt"
    report_json = base_dir / f"relatorio_{dominio}.json"
    report_html = base_dir / f"relatorio_{dominio}.html"

    fs = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 0), reverse=True)

    resumo = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in fs:
        resumo[item["severity"]] = resumo.get(item["severity"], 0) + 1

    # JSON
    with open(report_json, "w", encoding="utf-8") as f:
        json.dump(fs, f, indent=2, ensure_ascii=False)

    # TXT
    with open(report_txt, "w", encoding="utf-8") as f:
        f.write(f"Relatório — {dominio}\n")
        f.write(f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        f.write("RESUMO:\n")
        for sev in ["critical", "high", "medium", "low"]:
            f.write(f"  {sev.upper():8}: {resumo[sev]}\n")
        f.write(f"  {'TOTAL':8}: {len(fs)}\n\n")
        for item in fs:
            f.write(f"[{item['severity'].upper()}] {item['type']}\n")
            f.write(f"Arquivo : {item['file']}\n")
            f.write(f"Linha   : {item['line']}\n")
            f.write(f"Match   : {item['match']}\n")
            f.write(f"Contexto: {item['context']}\n")
            f.write("-" * 80 + "\n")

    # HTML interativo com filtros
    sev_colors = {
        "critical": "#dc2626", "high": "#ea580c",
        "medium": "#d97706",   "low": "#2563eb",
    }
    rows = ""
    for item in fs:
        cor = sev_colors.get(item["severity"], "#6b7280")
        rows += (
            f'<tr data-sev="{item["severity"]}">'
            f'<td><span class="badge" style="background:{cor}">{item["severity"].upper()}</span></td>'
            f'<td>{item["type"]}</td>'
            f'<td class="small brk">{item["file"]}</td>'
            f'<td>{item["line"]}</td>'
            f'<td class="small brk">{item["match"][:200]}</td>'
            f'<td class="small">{item["context"][:150]}</td>'
            f'</tr>\n'
        )

    html = f"""<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recon — {dominio}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}}
h1{{color:#38bdf8;margin-bottom:.3rem}}
.ts{{color:#64748b;font-size:.8rem;margin-bottom:1.5rem}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem}}
.card{{background:#1e293b;border-radius:8px;padding:.9rem 1.4rem;min-width:110px;text-align:center}}
.card .num{{font-size:1.8rem;font-weight:700}}
.card .lbl{{font-size:.72rem;color:#94a3b8;text-transform:uppercase;margin-top:.2rem}}
.toolbar{{display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:1rem;align-items:center}}
input[type=text]{{background:#1e293b;border:1px solid #334155;border-radius:6px;
  padding:.38rem .8rem;color:#e2e8f0;width:280px;font-size:.88rem}}
button{{padding:.35rem .9rem;border-radius:6px;border:none;cursor:pointer;
  font-size:.82rem;background:#334155;color:#e2e8f0;transition:.15s}}
button.on{{font-weight:700;color:#0f172a}}
table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;
  overflow:hidden;font-size:.84rem}}
th{{background:#334155;padding:.6rem 1rem;text-align:left;font-size:.73rem;
  text-transform:uppercase;color:#94a3b8}}
td{{padding:.55rem 1rem;border-bottom:1px solid #1e3a5f;vertical-align:top}}
tr:hover td{{background:#1a3050}}
.badge{{display:inline-block;padding:2px 7px;border-radius:4px;
  color:#fff;font-size:.72rem;font-weight:700}}
.small{{font-size:.79rem}}.brk{{word-break:break-all;max-width:220px}}
#count{{color:#64748b;font-size:.82rem}}
</style>
</head>
<body>
<h1>🔍 Recon — {dominio}</h1>
<p class="ts">Gerado em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
<div class="cards">
  <div class="card"><div class="num" style="color:#dc2626">{resumo['critical']}</div><div class="lbl">Critical</div></div>
  <div class="card"><div class="num" style="color:#ea580c">{resumo['high']}</div><div class="lbl">High</div></div>
  <div class="card"><div class="num" style="color:#d97706">{resumo['medium']}</div><div class="lbl">Medium</div></div>
  <div class="card"><div class="num" style="color:#2563eb">{resumo['low']}</div><div class="lbl">Low</div></div>
  <div class="card"><div class="num">{len(fs)}</div><div class="lbl">Total</div></div>
</div>
<div class="toolbar">
  <input type="text" id="q" placeholder="Filtrar por tipo, arquivo, match..." oninput="filter()">
  <button class="on" style="background:#38bdf8" onclick="setSev('all',this)">Todos</button>
  <button onclick="setSev('critical',this)" style="--c:#dc2626">Critical</button>
  <button onclick="setSev('high',this)"     style="--c:#ea580c">High</button>
  <button onclick="setSev('medium',this)"   style="--c:#d97706">Medium</button>
  <button onclick="setSev('low',this)"      style="--c:#2563eb">Low</button>
  <span id="count"></span>
</div>
<table>
<thead><tr>
  <th>Severity</th><th>Tipo</th><th>Arquivo</th>
  <th>Linha</th><th>Match</th><th>Contexto</th>
</tr></thead>
<tbody id="tbody">{rows}</tbody>
</table>
<script>
let sev='all';
function setSev(s,btn){{
  sev=s;
  document.querySelectorAll('button').forEach(b=>{{b.classList.remove('on');b.style.background='';}});
  btn.classList.add('on');
  btn.style.background = btn.style.getPropertyValue('--c')||'#38bdf8';
  filter();
}}
function filter(){{
  const q=document.getElementById('q').value.toLowerCase();
  let vis=0;
  document.querySelectorAll('#tbody tr').forEach(row=>{{
    const ok=(sev==='all'||row.dataset.sev===sev)&&(!q||row.innerText.toLowerCase().includes(q));
    row.style.display=ok?'':'none';
    if(ok) vis++;
  }});
  document.getElementById('count').textContent=vis+' resultado(s)';
}}
filter();
</script>
</body>
</html>"""

    with open(report_html, "w", encoding="utf-8") as f:
        f.write(html)

    log(f"TXT  → {report_txt}", C.GREEN)
    log(f"JSON → {report_json}", C.GREEN)
    log(f"HTML → {report_html}", C.GREEN)


# ============================================================
# MAIN
# ============================================================
def main():
    print(BANNER)
    args = parse_args()

    dominio = args.dominio or input(f"{C.CYAN}Informe o domínio (ex: exemplo.com): {C.RESET}").strip().lower()
    if not dominio:
        log("Domínio inválido.", C.RED)
        sys.exit(1)

    global CONFIG
    CONFIG = {
        "threads":  args.threads,
        "timeout":  args.timeout,
        "max_size": args.max_size * 1024 * 1024,
    }

    base_dir       = Path(f"coleta_{dominio}")
    download_dir   = base_dir / "downloads"
    sensitive_dir  = base_dir / "possivelmente_sensiveis"
    extract_dir    = base_dir / "extraidos"
    subs_file      = base_dir / f"subdomains_{dominio}.txt"
    urls_file      = base_dir / f"urls_{dominio}.txt"
    endpoints_file = base_dir / f"js_endpoints_{dominio}.txt"

    for d in [base_dir, download_dir, sensitive_dir, extract_dir]:
        d.mkdir(parents=True, exist_ok=True)

    inicio = datetime.now()
    log(f"Alvo       : {dominio}", C.BOLD)
    log(f"Threads    : {CONFIG['threads']}", C.CYAN)
    log(f"Timeout    : {CONFIG['timeout']}s", C.CYAN)
    log(f"Max tamanho: {args.max_size}MB\n", C.CYAN)

    # ── 1. Subdomínios ────────────────────────────────────────
    targets = {f"https://{dominio}", f"http://{dominio}"}

    if not args.sem_subdomain:
        subs = enum_subdomains(dominio, args.scope_file)
        with open(subs_file, "w") as f:
            for s in sorted(subs):
                f.write(s + "\n")
        log(f"{len(subs)} subdomínios salvos → {subs_file}", C.GREEN)

        ativos = probe_subdomains(subs, threads=args.threads)
        targets.update(ativos)
        log(f"{len(ativos)} subdomínios ativos adicionados ao escopo\n", C.GREEN)

    log(f"Targets no escopo: {len(targets)}", C.BOLD)

    # ── 2. Coleta de URLs ─────────────────────────────────────
    download_urls, js_urls = collect_all_urls(targets, args)
    all_js = js_urls | {u for u in download_urls if is_js_url(u)}

    with open(urls_file, "w") as f:
        for u in sorted(download_urls):
            f.write(u + "\n")

    log(f"{len(download_urls)} URLs relevantes → {urls_file}", C.GREEN)
    log(f"{len(all_js)} arquivos JS identificados\n", C.GREEN)

    all_findings  = []
    all_endpoints = set()

    if not args.sem_download:
        # ── 3. Download paralelo ──────────────────────────────
        to_download = download_urls | all_js
        downloaded, url_map = batch_download(to_download, download_dir, sensitive_dir)
        log(f"Arquivos baixados: {len(downloaded)}", C.GREEN)

        # ── 4. Extração ───────────────────────────────────────
        extracted = []
        for fp in downloaded:
            extracted.extend(extract_archive(fp, extract_dir))
        log(f"Arquivos extraídos: {len(extracted)}\n", C.GREEN)

        all_files = downloaded + extracted

        # ── 5. Análise ────────────────────────────────────────
        log(f"Analisando {len(all_files)} arquivos...", C.CYAN)

        for fp in all_files:
            try:
                content = extract_content(fp)
                if not content.strip():
                    continue

                findings = analyze_content(content, fp)

                # robots.txt
                if fp.name.lower().endswith("robots.txt"):
                    src = url_map.get(str(fp), "")
                    if src:
                        findings.extend(check_robots_paths(content, src))

                # Endpoints JS
                if fp.name.lower().endswith((".js", ".ts", ".map")):
                    all_endpoints.update(extract_js_endpoints(content))

                for finding in findings:
                    all_findings.append(finding)
                    alert(finding, args.min_severity)

            except Exception:
                pass

    # ── 6. Salva endpoints JS ─────────────────────────────────
    if all_endpoints:
        with open(endpoints_file, "w") as f:
            for ep in sorted(all_endpoints):
                f.write(ep + "\n")
        log(f"{len(all_endpoints)} endpoints JS → {endpoints_file}", C.GREEN)

    # ── 7. Relatórios ─────────────────────────────────────────
    save_reports(all_findings, dominio, base_dir)

    # ── Resumo final ──────────────────────────────────────────
    resumo  = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in all_findings:
        resumo[item["severity"]] = resumo.get(item["severity"], 0) + 1

    duracao = int((datetime.now() - inicio).total_seconds())
    print(f"\n{C.BOLD}{'═'*55}{C.RESET}")
    print(f"{C.BOLD}  RESUMO FINAL — {dominio}{C.RESET}")
    print(f"{'═'*55}")
    print(f"  {C.RED+C.BOLD}CRITICAL : {resumo['critical']}{C.RESET}")
    print(f"  {C.RED}HIGH     : {resumo['high']}{C.RESET}")
    print(f"  {C.YELLOW}MEDIUM   : {resumo['medium']}{C.RESET}")
    print(f"  {C.CYAN}LOW      : {resumo['low']}{C.RESET}")
    print(f"  TOTAL    : {len(all_findings)}")
    print(f"  Tempo    : {duracao}s")
    print(f"  Saída    : coleta_{dominio}/")
    print(f"{'═'*55}\n")


if __name__ == "__main__":
    main()
