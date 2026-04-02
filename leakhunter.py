#!/usr/bin/env python3
"""
coleta_dados.py - Ferramenta de reconhecimento e análise para Pentest / Bug Bounty
Uso autorizado apenas em alvos com permissão explícita.
"""

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
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

def cor_severity(sev: str) -> str:
    return {
        "critical": C.RED + C.BOLD,
        "high":     C.RED,
        "medium":   C.YELLOW,
        "low":      C.CYAN,
    }.get(sev, C.RESET)

# ============================================================
# BANNER
# ============================================================
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
    parser = argparse.ArgumentParser(
        description="Coleta e análise de arquivos públicos de um domínio."
    )
    parser.add_argument(
        "dominio",
        nargs="?",
        default=None,
        help="Domínio alvo (ex: exemplo.com)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Número de threads para download paralelo (padrão: 5)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Timeout de download em segundos (padrão: 60)"
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=30,
        help="Tamanho máximo de download em MB (padrão: 30)"
    )
    parser.add_argument(
        "--sem-wayback",
        action="store_true",
        help="Pular coleta via waybackurls"
    )
    parser.add_argument(
        "--sem-gau",
        action="store_true",
        help="Pular coleta via gau"
    )
    parser.add_argument(
        "--sem-download",
        action="store_true",
        help="Apenas coletar URLs, sem baixar arquivos"
    )
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Severidade mínima para exibir alertas em tempo real (padrão: low)"
    )
    return parser.parse_args()

# ============================================================
# CONFIG GLOBAL (preenchida após parse_args)
# ============================================================
CONFIG = {}

EXTENSOES_INTERESSE = (
    ".js", ".json", ".map", ".env", ".log", ".bak", ".old", ".zip", ".tar", ".gz",
    ".tgz", ".7z", ".rar", ".conf", ".config", ".ini", ".yaml", ".yml", ".sql",
    ".xml", ".txt", ".pdf", ".doc", ".docx", ".csv", ".pem", ".key", ".crt",
    ".pfx", ".p12", ".db", ".sqlite", ".sqlite3", ".backup", ".swp", ".sh",
    ".bash", ".htaccess", ".htpasswd", ".DS_Store", ".npmrc", ".netrc",
    ".git", ".gitconfig", ".gitignore", ".dockerignore", ".dockerfile",
    ".toml", ".lock", ".gradle", ".properties",
)

EXTENSOES_SENSIVEIS = (
    ".env", ".bak", ".old", ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".sql",
    ".pem", ".key", ".pfx", ".p12", ".db", ".sqlite", ".sqlite3", ".backup",
    ".config", ".ini", ".yaml", ".yml", ".conf", ".htpasswd", ".netrc", ".npmrc",
)

EXTENSOES_CRITICAS = (
    ".env", ".sql", ".pem", ".key", ".pfx", ".p12", ".db", ".sqlite", ".sqlite3",
    ".htpasswd", ".netrc", ".npmrc",
)

RETRY_DOWNLOAD = 3
ROBOTS_STATUS_INTERESSANTES = {"200", "204", "301", "302", "401", "403"}
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# ============================================================
# PADRÕES DE DETECÇÃO
# ============================================================
PATTERNS = {
    "JWT": {
        "regex": r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+\b",
        "severity": "high",
    },
    "AWS Access Key": {
        "regex": r"\bAKIA[0-9A-Z]{16}\b",
        "severity": "critical",
    },
    "AWS Secret Key": {
        "regex": r"""(?i)\baws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\b\s*[:=]\s*['"]?[A-Za-z0-9/+]{40}['"]?""",
        "severity": "critical",
    },
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
    "Stripe Live Key": {
        "regex": r"\bsk_live_[0-9a-zA-Z]{16,}\b",
        "severity": "critical",
    },
    "Stripe Publishable Key": {
        "regex": r"\bpk_live_[0-9a-zA-Z]{16,}\b",
        "severity": "low",
    },
    "Twilio Account SID": {
        "regex": r"\bAC[a-z0-9]{32}\b",
        "severity": "high",
    },
    "Twilio Auth Token": {
        "regex": r"(?i)twilio.*\b[a-z0-9]{32}\b",
        "severity": "critical",
    },
    "SendGrid API Key": {
        "regex": r"\bSG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{43,}\b",
        "severity": "critical",
    },
    "Mailgun API Key": {
        "regex": r"\bkey-[0-9a-zA-Z]{32}\b",
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
    "Private Key": {
        "regex": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
        "severity": "critical",
    },
    "Certificate": {
        "regex": r"-----BEGIN CERTIFICATE-----",
        "severity": "medium",
    },
    "Slack Token": {
        "regex": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        "severity": "critical",
    },
    "Slack Webhook": {
        "regex": r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
        "severity": "critical",
    },
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
    "Heroku API Key": {
        "regex": r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        "severity": "low",
    },
    "Password Assignment": {
        "regex": r"""(?i)\b(password|passwd|pwd|senha|secret|token|api[_-]?key)\b\s*[:=]\s*['"][^'"]{6,}['"]""",
        "severity": "high",
    },
    "Hardcoded Secret": {
        "regex": r"""(?i)\b(api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['"][A-Za-z0-9\-_=+/]{10,}['"]""",
        "severity": "high",
    },
    "Env File Secret": {
        "regex": r"""(?im)^(DB_PASSWORD|DATABASE_URL|AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY|TOKEN|ACCESS_TOKEN|PRIVATE_KEY|MAIL_PASSWORD|SMTP_PASS)\s*=\s*.+$""",
        "severity": "critical",
    },
    "Connection String": {
        "regex": r"""(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|oracle):\/\/[^\s"'<>]+""",
        "severity": "critical",
    },
    "Internal URL": {
        "regex": r"""https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|169\.254\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|localhost)(?::\d+)?[^\s"']*""",
        "severity": "medium",
    },
    "IP Address Exposed": {
        "regex": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "severity": "low",
    },
    "Open Redirect": {
        "regex": r"""(?i)[?&](?:redirect|return|url|next|goto|redir|redirect_uri|callback)\s*=\s*https?://""",
        "severity": "medium",
    },
    "Debug Artifact": {
        "regex": r"(?i)\b(console\.log|debugger|window\.debug)\b",
        "severity": "low",
    },
    "Role / Admin Reference": {
        "regex": r"(?i)\b(admin|superadmin|super admin|impersonate|role_impersonate|isAdmin|isSuperAdmin)\b",
        "severity": "medium",
    },
    "Sentry DSN": {
        "regex": r"https://[a-zA-Z0-9]+@[a-zA-Z0-9.-]+\.ingest\.sentry\.io/\d+",
        "severity": "low",
    },
    "GraphQL Introspection": {
        "regex": r"(?i)(/__graphql|/graphql\?query=|introspectionQuery)",
        "severity": "low",
    },
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
    "Email": {
        "regex": r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b",
        "severity": "low",
    },
    "Source Map Reference": {
        "regex": r"//# sourceMappingURL=(.+\.map)",
        "severity": "low",
    },
}

KEYWORDS_JS = [
    "Authorization", "Bearer ", "apiKey", "clientSecret", "secretKey",
    "accessToken", "refreshToken", "document.cookie", "localStorage.setItem",
    "sessionStorage.setItem", "fetch(", "axios.", "XMLHttpRequest", "graphql",
    "impersonate", "role_impersonate", "isAdmin", "isSuperAdmin",
    "eval(", "innerHTML", "dangerouslySetInnerHTML", "postMessage",
    "__proto__", "prototype pollution",
]

# ============================================================
# UTILITÁRIOS
# ============================================================
def aviso_pip(pacote: str) -> None:
    print(f"\n{C.YELLOW}[!] Biblioteca opcional ausente: {pacote}")
    print(f"    pip install {pacote}{C.RESET}")


def is_interesting_url(url: str) -> bool:
    try:
        path = urlparse(url).path.lower()
        return (
            path.endswith(EXTENSOES_INTERESSE)
            or path.endswith("/robots.txt")
            or path == "/robots.txt"
            or path.endswith("/.git/config")
            or path.endswith("/.env")
            or "backup" in path
        )
    except Exception:
        return False


def unique_filename(url: str) -> str:
    parsed = urlparse(url)
    base = os.path.basename(parsed.path) or "sem_nome"
    digest = hashlib.md5(url.encode()).hexdigest()[:10]
    if parsed.path.lower().endswith("/robots.txt") or parsed.path.lower() == "/robots.txt":
        base = "robots.txt"
    return f"{digest}_{base}"


def is_binary_file(path: Path) -> bool:
    try:
        return b"\x00" in path.read_bytes()[:2048]
    except Exception:
        return True


def try_decode(path: Path) -> str:
    raw = path.read_bytes()
    for enc in ("utf-8", "latin-1", "utf-16"):
        try:
            return raw.decode(enc, errors="ignore")
        except Exception:
            continue
    return ""


def get_context(content: str, start: int, end: int, radius: int = 120) -> str:
    left = max(0, start - radius)
    right = min(len(content), end + radius)
    return content[left:right].replace("\n", " ")[:300]


def line_number(content: str, index: int) -> int:
    return content.count("\n", 0, index) + 1


def extract_base_from_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


# ============================================================
# COLETA DE URLs
# ============================================================
def collect_urls(domain: str, sem_gau: bool, sem_wayback: bool) -> set:
    print(f"\n{C.CYAN}[+] Coletando URLs...{C.RESET}")
    urls = set()

    if not sem_gau:
        try:
            gau = subprocess.run(["gau", domain], capture_output=True, text=True, timeout=300)
            for line in gau.stdout.splitlines():
                line = line.strip()
                if line and is_interesting_url(line):
                    urls.add(line)
            print(f"{C.GREEN}    gau: {len(urls)} URLs relevantes{C.RESET}")
        except FileNotFoundError:
            print(f"{C.YELLOW}[!] gau não encontrado. Instale: go install github.com/lc/gau/v2/cmd/gau@latest{C.RESET}")
        except subprocess.TimeoutExpired:
            print(f"{C.YELLOW}[!] gau excedeu o tempo limite{C.RESET}")
        except Exception as e:
            print(f"{C.YELLOW}[!] gau erro: {e}{C.RESET}")

    if not sem_wayback:
        antes = len(urls)
        try:
            wayback = subprocess.run(
                ["waybackurls"], input=domain, capture_output=True, text=True, timeout=300
            )
            for line in wayback.stdout.splitlines():
                line = line.strip()
                if line and is_interesting_url(line):
                    urls.add(line)
            print(f"{C.GREEN}    waybackurls: +{len(urls)-antes} URLs relevantes{C.RESET}")
        except FileNotFoundError:
            print(f"{C.YELLOW}[!] waybackurls não encontrado. Instale: go install github.com/tomnomnom/waybackurls@latest{C.RESET}")
        except subprocess.TimeoutExpired:
            print(f"{C.YELLOW}[!] waybackurls excedeu o tempo limite{C.RESET}")
        except Exception as e:
            print(f"{C.YELLOW}[!] waybackurls erro: {e}{C.RESET}")

    # Fallback via Wayback Machine CDX API (sem dependências externas)
    if not urls:
        print(f"{C.YELLOW}[~] Tentando fallback via Wayback Machine API...{C.RESET}")
        urls.update(collect_via_cdx(domain))

    return urls


def collect_via_cdx(domain: str) -> set:
    """Coleta URLs via Wayback Machine CDX API (sem ferramentas externas)."""
    urls = set()
    ext_list = "|".join(e.lstrip(".") for e in EXTENSOES_INTERESSE)
    cdx_url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
        f"&filter=mimetype:.*&limit=5000"
    )
    try:
        req = Request(cdx_url, headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=60) as resp:
            for line in resp.read().decode("utf-8").splitlines():
                line = line.strip()
                if line and is_interesting_url(line):
                    urls.add(line)
        print(f"{C.GREEN}    CDX API: {len(urls)} URLs relevantes{C.RESET}")
    except Exception as e:
        print(f"{C.YELLOW}[!] Wayback CDX API falhou: {e}{C.RESET}")
    return urls


# ============================================================
# DOWNLOAD
# ============================================================
def download_file(url: str, dest: Path) -> bool:
    timeout = CONFIG["timeout"]
    max_size = CONFIG["max_size"]
    headers = {"User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"}
    req = Request(url, headers=headers)

    for tentativa in range(1, RETRY_DOWNLOAD + 1):
        try:
            with urlopen(req, timeout=timeout) as response:
                status = getattr(response, "status", 200)
                if status >= 400:
                    return False

                cl = response.headers.get("Content-Length")
                if cl:
                    try:
                        if int(cl) > max_size:
                            return False
                    except ValueError:
                        pass

                data = response.read(max_size + 1)
                if len(data) > max_size:
                    return False

                dest.write_bytes(data)
                return True

        except socket.timeout:
            pass
        except HTTPError as e:
            if e.code in (404, 410):
                return False
            pass
        except URLError:
            pass
        except Exception:
            pass

        if tentativa < RETRY_DOWNLOAD:
            time.sleep(2)

    return False


def download_worker(args):
    url, dest, is_sensitive = args
    ok = download_file(url, dest)
    return url, dest, ok, is_sensitive


def batch_download(urls: set, download_dir: Path, sensitive_dir: Path) -> tuple[list, dict]:
    tasks = []
    for url in sorted(urls):
        filename = unique_filename(url)
        path = urlparse(url).path.lower()
        is_sens = path.endswith(EXTENSOES_SENSIVEIS)
        dest_dir = sensitive_dir if is_sens else download_dir
        dest = dest_dir / filename
        tasks.append((url, dest, is_sens))

    downloaded = []
    url_map = {}
    total = len(tasks)

    print(f"\n{C.CYAN}[+] Baixando {total} arquivos com {CONFIG['threads']} threads...{C.RESET}")

    with ThreadPoolExecutor(max_workers=CONFIG["threads"]) as executor:
        futures = {executor.submit(download_worker, t): t for t in tasks}
        concluido = 0
        for future in as_completed(futures):
            concluido += 1
            url, dest, ok, is_sens = future.result()
            sys.stdout.write(f"\r    Progresso: {concluido}/{total}")
            sys.stdout.flush()

            if ok:
                downloaded.append(dest)
                url_map[str(dest)] = url
                if dest.name.lower().endswith(EXTENSOES_CRITICAS):
                    print(f"\n{C.RED}{C.BOLD}[!!!] ARQUIVO CRÍTICO BAIXADO: {dest}{C.RESET}")

    print()
    return downloaded, url_map


# ============================================================
# EXTRAÇÃO
# ============================================================
def extract_if_archive(path: Path, out_dir: Path) -> list:
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
    except Exception as e:
        pass
    return extracted


# ============================================================
# LEITURA DE CONTEÚDO
# ============================================================
def extract_content(path: Path) -> str:
    lower = path.name.lower()

    if lower.endswith(".pdf"):
        return extract_text_from_pdf(path)

    if lower.endswith(".docx"):
        return extract_text_from_docx(path)

    if is_binary_file(path) and not lower.endswith((
        ".json", ".js", ".map", ".xml", ".txt", ".log", ".sql", ".conf",
        ".config", ".ini", ".yaml", ".yml", ".env", ".csv", ".sh", ".bash",
        ".toml", ".properties", ".htaccess", ".htpasswd", ".netrc", ".npmrc",
    )):
        return ""

    return try_decode(path)


def extract_text_from_pdf(path: Path) -> str:
    try:
        import pypdf
        texts = []
        with open(path, "rb") as f:
            reader = pypdf.PdfReader(f)
            for page in reader.pages:
                texts.append(page.extract_text() or "")
        return "\n".join(texts)
    except ModuleNotFoundError:
        aviso_pip("pypdf")
        return ""
    except Exception:
        return ""


def extract_text_from_docx(path: Path) -> str:
    try:
        import zipfile as zf
        import xml.etree.ElementTree as ET
        with zf.ZipFile(path) as docx:
            xml_content = docx.read("word/document.xml")
        root = ET.fromstring(xml_content)
        return "\n".join(n.text for n in root.iter() if n.tag.endswith("}t") and n.text)
    except Exception:
        return ""


# ============================================================
# ANÁLISE DE CONTEÚDO
# ============================================================
def analyze_content(content: str, file_path: Path) -> list:
    findings = []
    seen = set()

    for name, meta in PATTERNS.items():
        try:
            pattern = re.compile(meta["regex"])
        except re.error:
            continue

        for match in pattern.finditer(content):
            found = match.group(0)
            key = (name, found)
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "type": name,
                "severity": meta["severity"],
                "file": str(file_path),
                "line": line_number(content, match.start()),
                "match": found[:300],
                "context": get_context(content, match.start(), match.end()),
            })

    lower = file_path.name.lower()
    if lower.endswith((".js", ".map", ".json", ".ts")):
        kw_seen = set()
        for kw in KEYWORDS_JS:
            for m in re.finditer(re.escape(kw), content, re.IGNORECASE):
                k = ("JS Keyword", kw, line_number(content, m.start()))
                if k in kw_seen:
                    continue
                kw_seen.add(k)
                findings.append({
                    "type": "JS Keyword",
                    "severity": "low",
                    "file": str(file_path),
                    "line": line_number(content, m.start()),
                    "match": kw,
                    "context": get_context(content, m.start(), m.end()),
                })

    return findings


# ============================================================
# ROBOTS.TXT
# ============================================================
def parse_robots_txt(content: str) -> list:
    paths = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key in ("disallow", "allow") and value and value != "/":
            if value.startswith("http"):
                try:
                    parsed = urlparse(value)
                    value = parsed.path or "/"
                    if parsed.query:
                        value += "?" + parsed.query
                except Exception:
                    continue
            if not value.startswith("/"):
                value = "/" + value
            paths.add(value)
    return sorted(paths)


def check_url_with_curl(url: str) -> dict:
    try:
        result = subprocess.run(
            ["curl", "-k", "-L", "-s", "-o", "/dev/null",
             "-w", "%{http_code}|%{content_type}|%{size_download}",
             "--max-time", "20", url],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout.strip()
        if "|" in output:
            code, ctype, size = output.split("|", 2)
            return {"url": url, "status": code, "content_type": ctype, "size": size}
    except Exception:
        pass
    return {"url": url, "status": "erro", "content_type": "", "size": ""}


def analyze_robots_paths(content: str, source_url: str) -> list:
    findings = []
    base_url = extract_base_from_url(source_url)
    paths = parse_robots_txt(content)
    if not paths:
        return findings

    print(f"\n{C.CYAN}[+] robots.txt: testando {len(paths)} caminhos...{C.RESET}")
    seen = set()
    for path in paths:
        full_url = base_url + path
        if full_url in seen:
            continue
        seen.add(full_url)

        result = check_url_with_curl(full_url)
        status = result["status"]
        if status not in ROBOTS_STATUS_INTERESSANTES:
            continue

        severity = "medium" if status in ("200", "204", "401", "403") else "low"
        findings.append({
            "type": "Robots Path Exposure",
            "severity": severity,
            "file": source_url,
            "line": 0,
            "match": full_url,
            "context": f"status={status} content_type={result['content_type']} size={result['size']}",
        })

        if status in ("200", "401", "403"):
            print(f"  {C.RED if status=='200' else C.YELLOW}[!!!] {full_url} -> HTTP {status}{C.RESET}")

    return findings


# ============================================================
# ALERTAS E RELATÓRIO
# ============================================================
def immediate_alert(finding: dict, min_severity: str) -> None:
    if SEVERITY_ORDER.get(finding["severity"], 0) < SEVERITY_ORDER.get(min_severity, 0):
        return
    cor = cor_severity(finding["severity"])
    print(f"\n{cor}[!!!] {finding['severity'].upper()} — {finding['type']}{C.RESET}")
    print(f"      Arquivo: {finding['file']}")
    print(f"      Linha  : {finding['line']}")
    print(f"      Match  : {finding['match'][:200]}")


def save_reports(findings: list, dominio: str, base_dir: Path) -> None:
    report_txt  = base_dir / f"relatorio_{dominio}.txt"
    report_json = base_dir / f"relatorio_{dominio}.json"
    report_html = base_dir / f"relatorio_{dominio}.html"

    findings_sorted = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 0), reverse=True)

    # JSON
    with open(report_json, "w", encoding="utf-8") as f:
        json.dump(findings_sorted, f, indent=2, ensure_ascii=False)

    # TXT
    resumo = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in findings_sorted:
        resumo[item["severity"]] = resumo.get(item["severity"], 0) + 1

    with open(report_txt, "w", encoding="utf-8") as f:
        f.write(f"Relatório de triagem — {dominio}\n")
        f.write(f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        f.write("Resumo:\n")
        for sev in ["critical", "high", "medium", "low"]:
            f.write(f"  {sev.upper():8}: {resumo.get(sev, 0)}\n")
        f.write(f"\n  TOTAL   : {len(findings_sorted)}\n\n")
        for item in findings_sorted:
            f.write(f"[{item['severity'].upper()}] {item['type']}\n")
            f.write(f"Arquivo : {item['file']}\n")
            f.write(f"Linha   : {item['line']}\n")
            f.write(f"Match   : {item['match']}\n")
            f.write(f"Contexto: {item['context']}\n")
            f.write("-" * 80 + "\n")

    # HTML
    sev_colors = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#2563eb"}
    rows = ""
    for item in findings_sorted:
        cor = sev_colors.get(item["severity"], "#6b7280")
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{cor}">{item['severity'].upper()}</span></td>
          <td>{item['type']}</td>
          <td style="word-break:break-all;font-size:0.85em">{item['file']}</td>
          <td>{item['line']}</td>
          <td style="word-break:break-all;font-size:0.85em;max-width:300px">{item['match'][:200]}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Relatório — {dominio}</title>
<style>
  body{{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:2rem}}
  h1{{color:#38bdf8}}
  .summary{{display:flex;gap:1rem;margin:1.5rem 0;flex-wrap:wrap}}
  .card{{background:#1e293b;border-radius:8px;padding:1rem 1.5rem;min-width:120px;text-align:center}}
  .card .num{{font-size:2rem;font-weight:bold}}
  .card .label{{font-size:0.8rem;color:#94a3b8;text-transform:uppercase}}
  table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden}}
  th{{background:#334155;padding:0.75rem 1rem;text-align:left;font-size:0.8rem;text-transform:uppercase;color:#94a3b8}}
  td{{padding:0.65rem 1rem;border-bottom:1px solid #334155;vertical-align:top}}
  tr:hover td{{background:#263148}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-size:0.75rem;font-weight:bold}}
  .ts{{color:#64748b;font-size:0.8rem;margin-top:0.5rem}}
</style>
</head>
<body>
<h1>🔍 Relatório de Segurança — {dominio}</h1>
<p class="ts">Gerado em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
<div class="summary">
  <div class="card"><div class="num" style="color:#dc2626">{resumo.get('critical',0)}</div><div class="label">Critical</div></div>
  <div class="card"><div class="num" style="color:#ea580c">{resumo.get('high',0)}</div><div class="label">High</div></div>
  <div class="card"><div class="num" style="color:#d97706">{resumo.get('medium',0)}</div><div class="label">Medium</div></div>
  <div class="card"><div class="num" style="color:#2563eb">{resumo.get('low',0)}</div><div class="label">Low</div></div>
  <div class="card"><div class="num">{len(findings_sorted)}</div><div class="label">Total</div></div>
</div>
<table>
<thead><tr><th>Severity</th><th>Tipo</th><th>Arquivo</th><th>Linha</th><th>Match</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body>
</html>"""

    with open(report_html, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n{C.GREEN}[+] Relatórios gerados:{C.RESET}")
    print(f"    TXT  → {report_txt}")
    print(f"    JSON → {report_json}")
    print(f"    HTML → {report_html}")


# ============================================================
# MAIN
# ============================================================
def main():
    print(BANNER)
    args = parse_args()

    dominio = args.dominio or input(f"{C.CYAN}Informe o domínio (ex: exemplo.com): {C.RESET}").strip().lower()
    if not dominio:
        print(f"{C.RED}[!] Domínio inválido.{C.RESET}")
        sys.exit(1)

    global CONFIG
    CONFIG = {
        "threads":       args.threads,
        "timeout":       args.timeout,
        "max_size":      args.max_size * 1024 * 1024,
        "min_severity":  args.min_severity,
    }

    base_dir      = Path(f"coleta_{dominio}")
    download_dir  = base_dir / "downloads"
    sensitive_dir = base_dir / "possivelmente_sensiveis"
    extract_dir   = base_dir / "extraidos"
    urls_file     = base_dir / f"urls_{dominio}.txt"

    for d in [base_dir, download_dir, sensitive_dir, extract_dir]:
        d.mkdir(parents=True, exist_ok=True)

    inicio = datetime.now()
    print(f"{C.CYAN}[+] Alvo       : {dominio}")
    print(f"[+] Threads    : {CONFIG['threads']}")
    print(f"[+] Timeout    : {CONFIG['timeout']}s")
    print(f"[+] Max tamanho: {args.max_size}MB{C.RESET}\n")

    # 1. Coleta de URLs
    urls = collect_urls(dominio, args.sem_gau, args.sem_wayback)
    with open(urls_file, "w", encoding="utf-8") as f:
        for url in sorted(urls):
            f.write(url + "\n")
    print(f"{C.GREEN}[+] {len(urls)} URLs filtradas → {urls_file}{C.RESET}")

    if not urls:
        print(f"{C.YELLOW}[!] Nenhuma URL encontrada. Encerrando.{C.RESET}")
        sys.exit(0)

    all_findings = []

    if not args.sem_download:
        # 2. Download paralelo
        downloaded_files, url_map = batch_download(urls, download_dir, sensitive_dir)
        print(f"{C.GREEN}[+] Arquivos baixados: {len(downloaded_files)}{C.RESET}")

        # 3. Extração de arquivos compactados
        extracted_files = []
        for fp in downloaded_files:
            ex = extract_if_archive(fp, extract_dir)
            extracted_files.extend(ex)
        print(f"{C.GREEN}[+] Arquivos extraídos: {len(extracted_files)}{C.RESET}")

        all_files = downloaded_files + extracted_files

        # 4. Análise
        print(f"\n{C.CYAN}[+] Analisando {len(all_files)} arquivos...{C.RESET}")
        for fp in all_files:
            try:
                content = extract_content(fp)
                if not content.strip():
                    continue

                findings = analyze_content(content, fp)

                if fp.name.lower().endswith("robots.txt"):
                    src_url = url_map.get(str(fp), "")
                    if src_url:
                        findings.extend(analyze_robots_paths(content, src_url))

                for finding in findings:
                    all_findings.append(finding)
                    immediate_alert(finding, CONFIG["min_severity"])

            except Exception as e:
                pass

    # 5. Relatório
    save_reports(all_findings, dominio, base_dir)

    # Resumo final
    resumo = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in all_findings:
        resumo[item["severity"]] = resumo.get(item["severity"], 0) + 1

    duracao = (datetime.now() - inicio).seconds
    print(f"\n{C.BOLD}{'='*50}{C.RESET}")
    print(f"{C.BOLD}  RESUMO FINAL — {dominio}{C.RESET}")
    print(f"{'='*50}")
    print(f"  {C.RED}CRITICAL : {resumo.get('critical',0)}{C.RESET}")
    print(f"  {C.RED}HIGH     : {resumo.get('high',0)}{C.RESET}")
    print(f"  {C.YELLOW}MEDIUM   : {resumo.get('medium',0)}{C.RESET}")
    print(f"  {C.CYAN}LOW      : {resumo.get('low',0)}{C.RESET}")
    print(f"  TOTAL    : {len(all_findings)}")
    print(f"  Tempo    : {duracao}s")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
