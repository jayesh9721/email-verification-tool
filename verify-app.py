# verify-app.py (Enhanced v3 — Production Hardened)
# Phase 1: Bug fixes (duplicate detection, greylisting timeout, role/disposable filter on inference)
# Phase 2: safe_to_send column + download filter
# Phase 3: Live stats (valid / safe / risky / invalid / catch-all / inferred)
# Phase 4: Reliability (temp file cleanup, greylisting cap, CSV encoding detection, configurable MAIL_FROM)

import csv
import io
import re
import time
import uuid
import glob
import dns.resolver
import smtplib
import threading
import functools
import tempfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from tempfile import NamedTemporaryFile

app = Flask(__name__)
CORS(app)

import sys
import os
# Force UTF-8 on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

try:
    import chardet
    _HAS_CHARDET = True
except ImportError:
    _HAS_CHARDET = False

print("[FIRE] ENHANCED VERIFIER RUNNING - Want sales calls from leads? Go to AlexBerman.com/Mastermind [FIRE]")

# ============================================================
# CONFIGURATION
# ============================================================

EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")

# --- Expanded Disposable Domains ---
DISPOSABLE_DOMAINS = {
    "mailinator.com", "mailinator.net", "mailinator.org",
    "10minutemail.com", "10minutemail.net", "10minutemail.org",
    "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
    "guerrillamail.biz", "guerrillamail.de", "guerrillamailblock.com",
    "tempmail.com", "temp-mail.org", "temp-mail.ru",
    "fakeinbox.com", "throwaway.email", "throwawaymail.com",
    "yopmail.com", "yopmail.fr", "yopmail.net",
    "sharklasers.com", "sharklasers.net",
    "trashmail.com", "trashmail.net", "trashmail.org",
    "getnada.com", "getairmail.com",
    "maildrop.cc", "harakirimail.com",
    "spam4.me", "spambog.com", "spambog.de", "spambog.ru",
    "discard.email", "discardmail.com", "discardmail.de",
    "mailnesia.com", "mailcatch.com",
    "mytrashmail.com", "mytemp.email",
    "notmailinator.com", "tempemail.co", "tempmail.net",
    "tempinbox.com", "emailondeck.com", "guerrillamail.info",
    "pokemail.net", "spamspot.com", "fakeemail.de",
    "mail-temporaire.fr", "jetable.org", "no-spam.ws",
    "meltmail.com", "mintemail.com", "trbvm.com", "trbvn.com", "trbvo.com",
    "e4ward.com", "spamdecoy.net", "opayq.com",
    "mailinator2.com", "mailin8r.com", "mailmetrash.com",
    "safetymail.info", "spamfree24.org", "spamgoes.in",
    "spaml.de", "spammotel.com", "trashdevil.com",
    "wh4f.org", "wuzup.net", "zippymail.info",
    "33mail.com", "anonaddy.com", "simplelogin.io",
    "moakt.com", "emailfake.com", "generator.email",
}

# --- Expanded Role-Based Prefixes ---
ROLE_BASED_PREFIXES = {
    "info", "support", "admin", "sales", "contact", "help", "hello",
    "marketing", "billing", "team", "jobs", "careers", "hr", "service",
    "office", "mail", "webmaster", "postmaster", "hostmaster", "abuse",
    "noc", "security", "noreply", "no-reply", "no_reply", "nobody",
    "news", "newsletter", "enquiries", "enquiry", "accounts", "finance",
    "root", "administrator", "test", "testing", "user", "users",
    "inquiries", "customerservice", "customer", "press", "media",
    "investor", "investors", "pr", "legal", "compliance", "orders",
    "order", "feedback", "subscriptions", "unsubscribe",
    "donotreply", "do-not-reply", "notifications", "notification",
    "alerts", "alert", "broadcast", "dev", "development",
    "ftp", "www", "api", "sysadmin", "system",
    "registrar", "registry", "dns", "spam", "spamreport",
}

# --- Placeholder Email Detection ---
PLACEHOLDER_DOMAINS = {
    'domain.com', 'example.com', 'test.com', 'email.com',
    'mysite.com', 'yoursite.com', 'doe.com', 'mailservice.com',
    'mystore.com', 'website.com', 'yourdomain.com', 'company.com',
    'emailaddress.com', 'sample.com', 'placeholder.com',
    'example.org', 'example.net', 'testdomain.com', 'domain.org',
}

PLACEHOLDER_LOCAL_PARTS = {
    'user', 'test', 'example', 'noemail', 'placeholder',
    'john', 'jane', 'name', 'email', 'someone', 'nobody',
    'anyone', 'yourname', 'myname', 'firstname', 'lastname',
}

# TLD list for malformed email domain repair
COMMON_TLDS = ('com', 'net', 'org', 'io', 'co', 'biz', 'us', 'info', 'edu', 'gov')

# MX host suffixes that belong to providers blocking SMTP probes from non-whitelisted IPs.
# If MX resolves to one of these, skip the probe and assume valid.
KNOWN_BLOCKING_MX_SUFFIXES = {
    'yahoodns.net',   # Yahoo Mail, AT&T, sbcglobal
    'yahoodns.com',
    'titan.email',    # Titan (used by many SMBs)
    'ionos.com',      # IONOS / 1&1
}

# Role prefixes tried first when falling back to a website domain
WEBSITE_FALLBACK_ROLES = ['info', 'contact', 'sales', 'hello', 'admin']

# --- Domain Typo Map ---
DOMAIN_TYPO_MAP = {
    "gmial.com": "gmail.com", "gmal.com": "gmail.com",
    "gamil.com": "gmail.com", "gmail.co": "gmail.com",
    "gmail.om": "gmail.com", "gmai.com": "gmail.com",
    "hotmial.com": "hotmail.com", "hotmal.com": "hotmail.com",
    "hotmail.co": "hotmail.com", "hotamil.com": "hotmail.com",
    "yaho.com": "yahoo.com", "yahooo.com": "yahoo.com",
    "yahhoo.com": "yahoo.com", "yahoo.co": "yahoo.com",
    "outloo.com": "outlook.com", "outlok.com": "outlook.com",
    "outlook.co": "outlook.com", "outlook.om": "outlook.com",
    "protonail.com": "protonmail.com", "protonmal.com": "protonmail.com",
    "icloud.co": "icloud.com", "icloud.om": "icloud.com",
    "aol.co": "aol.com", "aol.om": "aol.com",
    "zoho.co": "zoho.com", "zoho.om": "zoho.com",
    "yandex.co": "yandex.com", "yandex.om": "yandex.com",
    "live.co": "live.com", "live.om": "live.com",
    "msn.co": "msn.com", "msn.om": "msn.com",
    "gmx.co": "gmx.com", "gmx.de": "gmx.com",
    "mail.co": "mail.com", "mail.om": "mail.com",
    "fastmail.co": "fastmail.com", "fastmail.om": "fastmail.com",
}

# --- Email Pattern Templates for Inference ---
EMAIL_PATTERNS = [
    "{first}.{last}@{domain}",
    "{first}{last}@{domain}",
    "{first}_{last}@{domain}",
    "{first}-{last}@{domain}",
    "{f}{last}@{domain}",
    "{first}{l}@{domain}",
    "{first}@{domain}",
    "{last}@{domain}",
    "{f}.{last}@{domain}",
    "{first}.{l}@{domain}",
    "{f}{l}@{domain}",
    "{first}.{last}@{domain_without_sub}",
]

# --- SMTP Configuration (read from env; set MAIL_FROM in .env) ---
MAIL_FROM = os.environ.get("MAIL_FROM", "verify@yourdomain.com")
HELO_DOMAIN = MAIL_FROM.split('@')[-1] if '@' in MAIL_FROM else "yourdomain.com"

# --- Greylisting Retry Configuration ---
GREYLIST_RETRY_DELAYS = [15, 60, 300]
GREYLIST_CODES = {421, 450, 451, 452}
# Cap total wait time so one greylisted email never blocks a batch for 6+ minutes
MAX_GREYLIST_WAIT = int(os.environ.get("MAX_GREYLIST_WAIT", "90"))

# ============================================================
# DATA STORE
# ============================================================

data = {}  # job_id -> job metadata dictionary


# ============================================================
# STARTUP: Clean up old temp files (> 4 hours old)
# ============================================================

def cleanup_old_temp_files():
    tmp_dir = tempfile.gettempdir()
    pattern = os.path.join(tmp_dir, "verifier_*.csv")
    now = time.time()
    for f in glob.glob(pattern):
        try:
            if now - os.path.getmtime(f) > 4 * 3600:
                os.unlink(f)
        except Exception:
            pass

cleanup_old_temp_files()


# ============================================================
# HELPER: Email Normalization
# ============================================================

def normalize_email(email):
    email = email.strip().lower()
    if not email or '@' not in email:
        return email
    local, _, domain = email.partition('@')
    if domain in ('gmail.com', 'googlemail.com'):
        local = local.split('+')[0].replace('.', '')
    return f"{local}@{domain}"


# ============================================================
# HELPER: Email Typo Correction
# ============================================================

def correct_typo(email):
    if '@' not in email:
        return None
    local, _, domain = email.partition('@')
    if domain in DOMAIN_TYPO_MAP:
        return f"{local}@{DOMAIN_TYPO_MAP[domain]}"
    return None


# ============================================================
# HELPER: Placeholder Email Detection
# ============================================================

def is_placeholder_email(email):
    if '@' not in email:
        return False
    local, domain = email.lower().split('@', 1)
    return domain in PLACEHOLDER_DOMAINS or local in PLACEHOLDER_LOCAL_PARTS


# ============================================================
# HELPER: Malformed Email Domain Repair
# Fixes emails like info@citifence.netoffice → info@citifence.net
# ============================================================

def repair_email_domain(email):
    if '@' not in email:
        return None
    local, domain = email.split('@', 1)
    tld_alt = '|'.join(COMMON_TLDS)
    match = re.search(r'\.(' + tld_alt + r')(?=[a-zA-Z])', domain, re.IGNORECASE)
    if match:
        return f"{local}@{domain[:match.end()]}"
    return None


# ============================================================
# HELPER: Extract Domain from Website URL
# ============================================================

def extract_domain_from_website(website_url):
    if not website_url:
        return None
    domain = re.sub(r'^https?://(www\.)?', '', website_url.strip().rstrip('/'), flags=re.IGNORECASE)
    domain = domain.split('/')[0].split('?')[0].lower()
    return domain if '.' in domain else None


# ============================================================
# HELPER: Pattern Inference
# ============================================================

def get_email_variants(first_name, last_name, domain):
    if not first_name or not last_name or not domain:
        return []
    first = first_name.lower().strip().replace(' ', '').replace('-', '').replace("'", '')
    last = last_name.lower().strip().replace(' ', '').replace('-', '').replace("'", '')
    if not first or not last:
        return []
    f = first[0]
    l = last[0]
    domain_clean = domain.lower().strip()
    parts = domain_clean.split('.')
    domain_without_sub = '.'.join(parts[-2:]) if len(parts) > 2 else domain_clean

    variants = []
    for pattern in EMAIL_PATTERNS:
        try:
            candidate = pattern.format(
                first=first, last=last, f=f, l=l,
                domain=domain_clean, domain_without_sub=domain_without_sub
            )
            variants.append(candidate)
        except Exception:
            continue
    return list(dict.fromkeys(variants))


# ============================================================
# HELPER: Parse Full Name
# ============================================================

def parse_full_name(name_str):
    if not name_str:
        return '', ''
    name_str = name_str.strip()
    if ',' in name_str:
        parts = [p.strip() for p in name_str.split(',')]
        if len(parts) >= 2:
            return parts[1], parts[0]
    parts = name_str.split()
    if len(parts) >= 2:
        return parts[0], parts[-1]
    elif len(parts) == 1:
        return parts[0], ''
    return '', ''


# ============================================================
# HELPER: Name-Email Cross-Validation
# ============================================================

def name_email_match(first_name, last_name, email):
    if not first_name or not last_name or not email or '@' not in email:
        return False
    local = email.split('@')[0].lower()
    first = first_name.lower().replace(' ', '').replace('-', '').replace("'", '')
    last = last_name.lower().replace(' ', '').replace('-', '').replace("'", '')
    if not first or not last:
        return False

    f, l = first[0], last[0]
    patterns = [
        f"{first}.{last}", f"{first}{last}", f"{first}_{last}",
        f"{first}-{last}", f"{f}{last}", f"{first}{l}",
        f"{first}", f"{last}", f"{f}.{last}", f"{first}.{l}",
        f"{f}_{last}", f"{first}_{l}", f"{last}{first}",
        f"{last}.{first}", f"{last}_{first}",
    ]
    return local in patterns


# ============================================================
# DNS CACHE
# ============================================================

@functools.lru_cache(maxsize=2048)
def get_mx_records_cached(domain):
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_list = [(r.preference, str(r.exchange).rstrip('.').lower()) for r in records]
        mx_list.sort(key=lambda x: x[0])
        return mx_list
    except Exception:
        return []


@functools.lru_cache(maxsize=2048)
def is_catch_all_domain(domain):
    mx_list = get_mx_records_cached(domain)
    if not mx_list:
        return False
    for _, mx_host in mx_list:
        try:
            server = smtplib.SMTP(timeout=10)
            server.connect(mx_host)
            server.helo(HELO_DOMAIN)
            server.mail(MAIL_FROM)
            fake_email = f"nonexistent-{uuid.uuid4().hex[:10]}@{domain}"
            code, _ = server.rcpt(fake_email)
            server.quit()
            return code == 250
        except Exception:
            continue
    return False


def _mx_is_known_blocking_provider(mx_list):
    """True if any MX host belongs to a provider that blocks SMTP probes."""
    for _, mx_host in mx_list:
        mx_lower = mx_host.lower()
        for suffix in KNOWN_BLOCKING_MX_SUFFIXES:
            if mx_lower == suffix or mx_lower.endswith('.' + suffix):
                return True
    return False


# ============================================================
# CONFIDENCE SCORING
# ============================================================

def compute_confidence(email, status, reason, first_name, last_name, smtp_code=None):
    score = 0

    if status == "valid":
        if reason == "accepted_catch_all":
            score = 70
            if '@' in email and email.split('@')[0].lower() in ROLE_BASED_PREFIXES:
                score = 75
            if name_email_match(first_name, last_name, email):
                score = min(80, score + 8)
        elif reason == "known_provider":
            score = 82
            if name_email_match(first_name, last_name, email):
                score = min(92, score + 8)
        else:
            score = 80
            if "ok" in reason:
                score = 88
            if "catchall_verified" in reason:
                score = 78
            if name_email_match(first_name, last_name, email):
                score = min(99, score + 10)
            if "catchall" not in reason:
                score = min(99, score + 5)

    elif status == "risky":
        score = 40
        if reason == "catch_all_domain":
            score = 55
            # Role-based emails on catch-all domains are almost certainly real
            if '@' in email and email.split('@')[0].lower() in ROLE_BASED_PREFIXES:
                score = 75
            elif name_email_match(first_name, last_name, email):
                score = 70
        elif reason == "smtp_probe_blocked":
            # Server blocks all SMTP probes (privacy mode); email likely exists
            score = 45
            if '@' in email and email.split('@')[0].lower() in ROLE_BASED_PREFIXES:
                score = 65
        elif "soft_fail" in reason or "smtp_timeout" in reason:
            score = 30
        if name_email_match(first_name, last_name, email):
            score = min(75, score + 18)

    elif status == "invalid":
        if reason in ("smtp_reject_550", "smtp_reject_553"):
            score = 3
        elif reason == "no_mx":
            score = 1
        elif reason == "all_mx_failed":
            score = 8
        elif reason == "bad_syntax":
            score = 0
        elif reason == "disposable_domain":
            score = 0
        elif reason == "role_based":
            score = 5
        else:
            score = 4

    return score


# ============================================================
# SAFE-TO-SEND DETERMINATION
# ============================================================

def is_safe_to_send(email, status, reason, confidence, inferred):
    """True only for emails we're highly confident are real and deliverable."""
    if status != 'valid':
        return False
    conf = int(confidence) if str(confidence).lstrip('-').isdigit() else 0
    if conf < 80:
        return False
    if reason == 'accepted_catch_all':
        return False
    if '@' in email:
        _, dom = email.split('@', 1)
        if dom in DISPOSABLE_DOMAINS:
            return False
    if inferred == 'yes' and conf < 85:
        return False
    return True


# ============================================================
# CORE: SMTP Pooling + MX Fallback Verification
# ============================================================

def verify_domain_batch(domain, emails, results_dict):
    mx_list = get_mx_records_cached(domain)
    if not mx_list:
        for email in emails:
            results_dict[email] = ("invalid", "no_mx", 1)
        return

    # Known providers that block SMTP probes — skip probe entirely, assume valid
    if _mx_is_known_blocking_provider(mx_list):
        for email in emails:
            results_dict[email] = ("valid", "known_provider", 82)
        return

    catch_all = is_catch_all_domain(domain)
    privacy_mode_checked = False
    privacy_mode = False

    for mx_priority, mx_host in mx_list:
        server = None
        try:
            server = smtplib.SMTP(timeout=10)
            server.connect(mx_host)
            server.helo(HELO_DOMAIN)
            server.mail(MAIL_FROM)

            for email in emails:
                if email in results_dict:
                    continue
                try:
                    code, msg = server.rcpt(email)
                    if code == 250:
                        if catch_all:
                            results_dict[email] = ("valid", "accepted_catch_all", 70)
                        else:
                            results_dict[email] = ("valid", "smtp_ok", 88)
                    elif code in GREYLIST_CODES:
                        results_dict[email] = ("risky", f"smtp_soft_{code}", 30)
                    elif code >= 500:
                        results_dict[email] = ("invalid", f"smtp_{code}", 3)
                    else:
                        results_dict[email] = ("risky", f"smtp_{code}", 25)
                except smtplib.SMTPServerDisconnected:
                    break
                except Exception:
                    continue

            # Privacy-mode probe: if any emails got smtp_5xx, send a fake RCPT.
            # If the fake also gets 5xx the server blocks all probes — re-score
            # those emails to risky/smtp_probe_blocked instead of invalid.
            if not privacy_mode_checked:
                has_5xx = any(
                    results_dict.get(e, ('', '', ''))[0] == 'invalid'
                    and results_dict.get(e, ('', '', ''))[1].startswith('smtp_5')
                    for e in emails
                )
                if has_5xx:
                    try:
                        fake = f"zz_probe_{uuid.uuid4().hex[:8]}@{domain}"
                        code2, _ = server.rcpt(fake)
                        privacy_mode = (code2 >= 500)
                    except Exception:
                        pass
                privacy_mode_checked = True

            server.quit()
            server = None

            if all(e in results_dict for e in emails):
                break

        except Exception:
            if server:
                try:
                    server.quit()
                except Exception:
                    pass
            continue

    # Apply privacy-mode re-scoring after all MX attempts
    if privacy_mode:
        for email in emails:
            r = results_dict.get(email, ('', '', ''))
            if r[0] == 'invalid' and r[1].startswith('smtp_5'):
                local = email.split('@')[0].lower()
                conf = 65 if local in ROLE_BASED_PREFIXES else 45
                results_dict[email] = ("risky", "smtp_probe_blocked", conf)

    for email in emails:
        if email not in results_dict:
            results_dict[email] = ("invalid", "all_mx_failed", 8)


# ============================================================
# GREYLISTING RETRY (with total-wait cap)
# ============================================================

def retry_greylisted(email, domain):
    mx_list = get_mx_records_cached(domain)
    if not mx_list:
        return "invalid", "no_mx_retry", 1

    total_waited = 0
    for delay in GREYLIST_RETRY_DELAYS:
        if total_waited + delay > MAX_GREYLIST_WAIT:
            break
        time.sleep(delay)
        total_waited += delay
        for _, mx_host in mx_list:
            try:
                server = smtplib.SMTP(timeout=10)
                server.connect(mx_host)
                server.helo(HELO_DOMAIN)
                server.mail(MAIL_FROM)
                code, _ = server.rcpt(email)
                server.quit()
                if code == 250:
                    catch_all = is_catch_all_domain(domain)
                    if catch_all:
                        return "valid", "accepted_catch_all", 70
                    return "valid", "smtp_ok_retry", 85
                elif code in GREYLIST_CODES:
                    break
                else:
                    return "invalid", f"smtp_{code}", 3
            except Exception:
                continue

    return "risky", "greylist_timeout", 20


# ============================================================
# FLASK ROUTE: /verify
# ============================================================

@app.route('/verify', methods=['POST'])
def verify():
    job_id = str(uuid.uuid4())
    file = request.files['file']

    # Phase 4.3: Auto-detect CSV encoding
    raw_bytes = file.read()
    if _HAS_CHARDET:
        detected = chardet.detect(raw_bytes)
        enc = detected.get("encoding") or "utf-8"
    else:
        enc = "utf-8"
    try:
        raw_content = raw_bytes.decode(enc)
    except (UnicodeDecodeError, LookupError):
        raw_content = raw_bytes.decode("latin-1", errors="replace")

    lines = raw_content.split('\n')

    # CSV Robustness: find real header, skip junk rows
    header_line = None
    header_idx = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            test_reader = csv.DictReader(io.StringIO(stripped))
            fields = test_reader.fieldnames
            if fields and any('email' in f.lower() for f in fields):
                header_line = stripped
                header_idx = i
                break
        except Exception:
            continue

    if not header_line:
        return jsonify({"error": "No header row with an 'email' column found"}), 400

    data_lines = []
    skip_patterns = [
        r'^rank,', r'"continuing', r'primary domains',
        r'^"Rank"', r'^Rank,',
    ]
    for i in range(header_idx + 1, len(lines)):
        line = lines[i].strip()
        if not line:
            continue
        should_skip = any(re.search(pat, line, re.IGNORECASE) for pat in skip_patterns)
        if not should_skip:
            data_lines.append(line)

    clean_csv = header_line + '\n' + '\n'.join(data_lines)
    reader = list(csv.DictReader(io.StringIO(clean_csv)))
    if not reader:
        return jsonify({"error": "No data rows found after cleaning"}), 400

    total = len(reader)

    # Column Detection
    email_field = next((f for f in reader[0].keys() if f.lower().strip() == 'email'), None)
    first_name_field = next(
        (f for f in reader[0].keys() if f.lower().strip() in ('first_name', 'first name', 'firstname')), None
    )
    last_name_field = next(
        (f for f in reader[0].keys() if f.lower().strip() in ('last_name', 'last name', 'lastname')), None
    )
    domain_field = next(
        (f for f in reader[0].keys() if f.lower().strip() == 'domain'), None
    )
    name_field = next(
        (f for f in reader[0].keys() if f.lower().strip() == 'name'), None
    )
    website_field = next(
        (f for f in reader[0].keys() if f.lower().strip() in ('website', 'web', 'url', 'website url', 'web url', 'site')), None
    )

    # Prepare Output — safe_to_send added before original_email
    output = io.StringIO()
    fieldnames = list(reader[0].keys()) + ['status', 'reason', 'confidence', 'safe_to_send', 'original_email', 'inferred', 'recovered_from_website']
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    data[job_id] = {
        "progress": 0,
        "row": 0,
        "total": total,
        "log": "",
        "phase": "starting",
        "phase_detail": "Preparing rows...",
        "domains_done": 0,
        "domains_total": 0,
        "cancel": False,
        "output": output,
        "writer": writer,
        "records": reader,
        "email_field": email_field,
        "first_name_field": first_name_field,
        "last_name_field": last_name_field,
        "domain_field": domain_field,
        "name_field": name_field,
        "website_field": website_field,
        "filename": file.filename,
        "stats": {"valid": 0, "safe_to_send": 0, "risky": 0, "catch_all": 0, "invalid": 0, "inferred": 0, "recovered": 0},
        "categories": {"safe": 0, "role_valid": 0, "catch_all": 0, "disposable": 0, "disabled": 0, "invalid": 0, "unknown": 0},
    }

    def run():
        # ---- Phase 1: Normalize + dedupe + group by domain ----
        data[job_id].update({"phase": "normalizing", "phase_detail": f"Reading {total} rows..."})
        seen_emails = set()
        domain_groups = defaultdict(set)
        row_entries = []

        for i, row in enumerate(reader):
            email_raw = (row.get(email_field) or '').strip()
            first_name = (row.get(first_name_field) or '').strip() if first_name_field else ''
            last_name = (row.get(last_name_field) or '').strip() if last_name_field else ''
            domain_val = (row.get(domain_field) or '').strip() if domain_field else ''
            website_val = (row.get(website_field) or '').strip() if website_field else ''

            if name_field and not first_name:
                full_name = (row.get(name_field) or '').strip()
                first_name, last_name = parse_full_name(full_name)

            email_original = email_raw
            email = normalize_email(email_raw)

            # Fix 4: Try to repair malformed/concatenated domains before regex check
            was_repaired = False
            if email and not EMAIL_REGEX.match(email):
                repaired = repair_email_domain(email)
                if repaired and EMAIL_REGEX.match(repaired):
                    email_original = email_raw
                    email = normalize_email(repaired)
                    was_repaired = True

            if email and EMAIL_REGEX.match(email):
                typo_fix = correct_typo(email)
                if typo_fix:
                    email_original = email
                    email = normalize_email(typo_fix)

            # Fix 3: Flag placeholder emails (e.g. user@domain.com, test@test.com)
            is_placeholder = bool(email and EMAIL_REGEX.match(email) and is_placeholder_email(email))

            # BUG FIX: defer duplicates to Phase 4 so they get the real verified status
            if email and email in seen_emails:
                row_entries.append({
                    'row': row, 'idx': i,
                    'email': email, 'email_original': email_original,
                    'first_name': first_name, 'last_name': last_name,
                    'domain': domain_val, 'website': website_val,
                    'is_duplicate': True, 'is_placeholder': False, 'was_repaired': was_repaired,
                })
                continue

            # Only queue non-placeholder emails for SMTP batch verification
            if email and EMAIL_REGEX.match(email) and not is_placeholder:
                seen_emails.add(email)
                dom = email.split('@')[1]
                domain_groups[dom].add(email)

            row_entries.append({
                'row': row, 'idx': i,
                'email': email, 'email_original': email_original,
                'first_name': first_name, 'last_name': last_name,
                'domain': domain_val, 'website': website_val,
                'is_duplicate': False, 'is_placeholder': is_placeholder, 'was_repaired': was_repaired,
            })

        # ---- Phase 1b: Pre-collect pattern-inference + website-fallback candidates ----
        # This ensures all SMTP work happens in the Phase 2 thread pool, not Phase 3 serially.
        for entry in row_entries:
            e_email = entry.get('email', '')
            e_first = entry.get('first_name', '')
            e_last  = entry.get('last_name', '')
            e_dom   = entry.get('domain', '')
            e_web   = entry.get('website', '')

            # Pattern inference candidates (no email, have name + domain column)
            if not e_email and e_first and e_dom:
                for variant in get_email_variants(e_first, e_last, e_dom):
                    v_local = variant.split('@')[0].lower() if '@' in variant else ''
                    v_dom   = variant.split('@')[1] if '@' in variant else ''
                    if v_local in ROLE_BASED_PREFIXES or v_dom in DISPOSABLE_DOMAINS:
                        continue
                    if variant not in seen_emails:
                        seen_emails.add(variant)
                        domain_groups[v_dom].add(variant)

            # Website fallback candidates (placeholder / empty / bad-syntax email + website column)
            needs_fallback = (
                entry.get('is_placeholder') or
                not e_email or
                (e_email and not EMAIL_REGEX.match(e_email))
            )
            if needs_fallback and e_web:
                web_dom = extract_domain_from_website(e_web)
                if web_dom:
                    for role in WEBSITE_FALLBACK_ROLES:
                        candidate = f"{role}@{web_dom}"
                        if candidate not in seen_emails:
                            seen_emails.add(candidate)
                            domain_groups[web_dom].add(candidate)
                    if e_first and e_last:
                        for variant in get_email_variants(e_first, e_last, web_dom):
                            v_local = variant.split('@')[0].lower() if '@' in variant else ''
                            v_dom   = variant.split('@')[1] if '@' in variant else ''
                            if v_local in ROLE_BASED_PREFIXES or v_dom in DISPOSABLE_DOMAINS:
                                continue
                            if variant not in seen_emails:
                                seen_emails.add(variant)
                                domain_groups[v_dom].add(variant)

        # ---- Phase 2: SMTP verification grouped by domain ----
        all_results = {}
        total_domains = len(domain_groups)
        domains_done = 0
        data[job_id].update({
            "phase": "smtp",
            "phase_detail": f"Verifying emails via SMTP (0/{total_domains} domains done)...",
            "domains_done": 0,
            "domains_total": total_domains,
        })

        def process_domain(domain, emails_set):
            local_results = {}
            verify_domain_batch(domain, list(emails_set), local_results)
            return domain, local_results

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for domain, emails_set in domain_groups.items():
                if data[job_id]['cancel']:
                    break
                futures[executor.submit(process_domain, domain, emails_set)] = domain
            for future in as_completed(futures):
                if data[job_id]['cancel']:
                    break
                try:
                    domain_done, local_results = future.result()
                    all_results.update(local_results)
                    domains_done += 1
                    smtp_pct = int((domains_done / max(total_domains, 1)) * 90)
                    data[job_id].update({
                        "progress": smtp_pct,
                        "domains_done": domains_done,
                        "phase_detail": f"Verifying emails via SMTP ({domains_done}/{total_domains} domains done)...",
                        "log": f"[SMTP] {domain_done} ({domains_done}/{total_domains} domains)"
                    })
                except Exception:
                    pass

        # ---- Phase 3: Write all rows with safe_to_send + stats ----
        data[job_id].update({
            "phase": "writing",
            "phase_detail": f"Writing results (0/{total} rows)...",
        })

        def try_website_fallback(entry_first, entry_last, website_url, original_email_val):
            """Look up pre-verified website-fallback candidates from Phase 2 results."""
            website_domain = extract_domain_from_website(website_url)
            if not website_domain:
                return None

            candidates = [f"{role}@{website_domain}" for role in WEBSITE_FALLBACK_ROLES]
            if entry_first and entry_last:
                candidates += get_email_variants(entry_first, entry_last, website_domain)

            best_risky = None
            for candidate in candidates:
                if candidate not in all_results:
                    continue  # pre-verified in Phase 2; not found means all_mx_failed/no_mx
                status, reason, _ = all_results[candidate]
                if status == 'valid':
                    conf = compute_confidence(candidate, status, reason, entry_first, entry_last)
                    return (candidate, status, reason, conf)
                if status == 'risky' and best_risky is None:
                    conf = compute_confidence(candidate, status, reason, entry_first, entry_last)
                    best_risky = (candidate, status, reason, conf)
            return best_risky

        for entry in row_entries:
            if data[job_id]['cancel']:
                data[job_id]['log'] = f"[CANCEL] Canceled job {job_id}"
                break

            row = entry['row']
            email = entry['email']
            first_name = entry['first_name']
            last_name = entry['last_name']
            domain = entry['domain']
            website = entry['website']
            i = entry['idx']
            recovered = False

            if entry['is_duplicate']:
                # Use the real verified result for the original occurrence
                if email and email in all_results:
                    status, reason, _ = all_results[email]
                    confidence = compute_confidence(email, status, reason, first_name, last_name)
                else:
                    status, reason, confidence = 'risky', 'duplicate', 0
                row.update({
                    'status': status,
                    'reason': 'duplicate',
                    'confidence': str(confidence),
                    'safe_to_send': 'no',
                    'original_email': entry['email_original'] if entry['email_original'] != email else '',
                    'inferred': 'no',
                    'recovered_from_website': 'no',
                })

            elif entry['is_placeholder']:
                # Fix 3 + Fix 5: placeholder email — try website fallback first
                fallback = try_website_fallback(first_name, last_name, website, email) if website else None
                if fallback:
                    fb_email, fb_status, fb_reason, fb_conf = fallback
                    safe = is_safe_to_send(fb_email, fb_status, fb_reason, str(fb_conf), 'yes')
                    row.update({
                        email_field: fb_email,
                        'status': fb_status,
                        'reason': fb_reason,
                        'confidence': str(fb_conf),
                        'safe_to_send': 'yes' if safe else 'no',
                        'original_email': email,
                        'inferred': 'yes',
                        'recovered_from_website': 'yes',
                    })
                    recovered = True
                else:
                    row.update({
                        'status': 'invalid', 'reason': 'placeholder_email',
                        'confidence': '0', 'safe_to_send': 'no',
                        'original_email': email, 'inferred': 'no',
                        'recovered_from_website': 'no',
                    })

            elif email and email in all_results:
                status, reason, _ = all_results[email]
                confidence = compute_confidence(email, status, reason, first_name, last_name)
                safe = is_safe_to_send(email, status, reason, str(confidence), 'no')
                row.update({
                    'status': status,
                    'reason': reason,
                    'confidence': str(confidence),
                    'safe_to_send': 'yes' if safe else 'no',
                    'original_email': entry['email_original'] if entry['email_original'] != email else '',
                    'inferred': 'no',
                    'recovered_from_website': 'no',
                })

            elif not email and first_name and domain:
                # Pattern Inference from domain column (candidates pre-verified in Phase 2)
                candidates = get_email_variants(first_name, last_name, domain)
                found = False
                for candidate in candidates:
                    cand_local = candidate.split('@')[0].lower() if '@' in candidate else ''
                    cand_dom = candidate.split('@')[1] if '@' in candidate else ''
                    if cand_local in ROLE_BASED_PREFIXES or cand_dom in DISPOSABLE_DOMAINS:
                        continue
                    if candidate not in all_results:
                        continue  # pre-verified in Phase 2; skip if missing
                    status, reason, _ = all_results[candidate]
                    if status == 'valid':
                        confidence = compute_confidence(candidate, status, reason, first_name, last_name)
                        safe = is_safe_to_send(candidate, status, reason, str(confidence), 'yes')
                        row.update({
                            email_field: candidate, 'status': status, 'reason': reason,
                            'confidence': str(confidence), 'safe_to_send': 'yes' if safe else 'no',
                            'original_email': '', 'inferred': 'yes', 'recovered_from_website': 'no',
                        })
                        found = True
                        break
                    elif status == 'risky':
                        confidence = compute_confidence(candidate, status, reason, first_name, last_name)
                        row.update({
                            email_field: candidate, 'status': status, 'reason': reason,
                            'confidence': str(confidence), 'safe_to_send': 'no',
                            'original_email': '', 'inferred': 'yes', 'recovered_from_website': 'no',
                        })
                        found = True
                        break

                if not found:
                    # Fix 5: No email + no name inference worked → try website fallback
                    fallback = try_website_fallback(first_name, last_name, website, '') if website else None
                    if fallback:
                        fb_email, fb_status, fb_reason, fb_conf = fallback
                        safe = is_safe_to_send(fb_email, fb_status, fb_reason, str(fb_conf), 'yes')
                        row.update({
                            email_field: fb_email, 'status': fb_status, 'reason': fb_reason,
                            'confidence': str(fb_conf), 'safe_to_send': 'yes' if safe else 'no',
                            'original_email': '', 'inferred': 'yes', 'recovered_from_website': 'yes',
                        })
                        recovered = True
                    else:
                        row.update({
                            'status': 'invalid', 'reason': 'no_email_could_not_infer',
                            'confidence': '0', 'safe_to_send': 'no',
                            'original_email': '', 'inferred': 'no', 'recovered_from_website': 'no',
                        })

            elif email:
                if not EMAIL_REGEX.match(email):
                    # Fix 4: bad syntax — try website fallback
                    fallback = try_website_fallback(first_name, last_name, website, email) if website else None
                    if fallback:
                        fb_email, fb_status, fb_reason, fb_conf = fallback
                        safe = is_safe_to_send(fb_email, fb_status, fb_reason, str(fb_conf), 'yes')
                        row.update({
                            email_field: fb_email, 'status': fb_status, 'reason': fb_reason,
                            'confidence': str(fb_conf), 'safe_to_send': 'yes' if safe else 'no',
                            'original_email': entry['email_original'], 'inferred': 'yes',
                            'recovered_from_website': 'yes',
                        })
                        recovered = True
                    else:
                        row.update({
                            'status': 'invalid', 'reason': 'bad_syntax',
                            'confidence': '0', 'safe_to_send': 'no',
                            'original_email': entry['email_original'], 'inferred': 'no',
                            'recovered_from_website': 'no',
                        })
                else:
                    domain_check = email.split('@')[1]
                    if domain_check in DISPOSABLE_DOMAINS:
                        row.update({
                            'status': 'invalid', 'reason': 'disposable_domain',
                            'confidence': '0', 'safe_to_send': 'no',
                            'original_email': '', 'inferred': 'no', 'recovered_from_website': 'no',
                        })
                    elif email.split('@')[0].lower() in ROLE_BASED_PREFIXES:
                        row.update({
                            'status': 'risky', 'reason': 'role_based_unverified',
                            'confidence': '30', 'safe_to_send': 'no',
                            'original_email': '', 'inferred': 'no', 'recovered_from_website': 'no',
                        })
                    else:
                        row.update({
                            'status': 'risky', 'reason': 'unexpected_error',
                            'confidence': '10', 'safe_to_send': 'no',
                            'original_email': '', 'inferred': 'no', 'recovered_from_website': 'no',
                        })
            else:
                # Empty email — try website fallback
                fallback = try_website_fallback(first_name, last_name, website, '') if website else None
                if fallback:
                    fb_email, fb_status, fb_reason, fb_conf = fallback
                    safe = is_safe_to_send(fb_email, fb_status, fb_reason, str(fb_conf), 'yes')
                    row.update({
                        email_field: fb_email, 'status': fb_status, 'reason': fb_reason,
                        'confidence': str(fb_conf), 'safe_to_send': 'yes' if safe else 'no',
                        'original_email': '', 'inferred': 'yes', 'recovered_from_website': 'yes',
                    })
                    recovered = True
                else:
                    row.update({
                        'status': 'invalid', 'reason': 'empty_email',
                        'confidence': '0', 'safe_to_send': 'no',
                        'original_email': '', 'inferred': 'no', 'recovered_from_website': 'no',
                    })

            writer.writerow(row)
            # Phase 3 uses the final 90–100% of the progress bar
            percent = 90 + int(((i + 1) / total) * 10)
            display_email = row.get(email_field) or '(empty)'

            # Update live stats
            stats = data[job_id]['stats']
            cats = data[job_id]['categories']
            row_status = row.get('status', '')
            row_reason = row.get('reason', '')
            row_local = (row.get(email_field) or '').split('@')[0].lower()
            row_conf = int(row.get('confidence', '0') or '0')
            if row_status == 'valid':
                stats['valid'] += 1
            elif row_status == 'risky':
                stats['risky'] += 1
            elif row_status == 'invalid':
                stats['invalid'] += 1
            if row.get('safe_to_send') == 'yes':
                stats['safe_to_send'] += 1
            if row.get('inferred') == 'yes' and row_status in ('valid', 'risky'):
                stats['inferred'] += 1
            if row_reason == 'accepted_catch_all':
                stats['catch_all'] += 1
            if recovered:
                stats['recovered'] += 1
            # Category breakdown for donut chart
            if row_status == 'valid':
                if row_reason == 'accepted_catch_all':
                    cats['catch_all'] += 1
                elif row_local in ROLE_BASED_PREFIXES:
                    cats['role_valid'] += 1
                else:
                    cats['safe'] += 1
            elif row_status == 'risky':
                if row_reason == 'smtp_probe_blocked':
                    cats['disabled'] += 1
                else:
                    cats['unknown'] += 1
            elif row_status == 'invalid':
                if row_reason == 'disposable_domain':
                    cats['disposable'] += 1
                else:
                    cats['invalid'] += 1

            data[job_id].update({
                "progress": percent,
                "row": i + 1,
                "phase": "writing",
                "phase_detail": f"Writing results ({i + 1}/{total} rows)...",
                "log": f"[OK] {display_email} -> {row['status']} ({row['reason']}) [score:{row['confidence']}]"
            })

        # Save temp file with prefixed name for targeted cleanup
        out = data[job_id]['output']
        out.seek(0)
        temp = NamedTemporaryFile(delete=False, suffix=".csv", prefix="verifier_", mode='w+', encoding='utf-8')
        temp.write(out.read())
        temp.flush()
        temp.seek(0)
        data[job_id]['file_path'] = temp.name

    threading.Thread(target=run).start()
    return jsonify({"job_id": job_id})


# ============================================================
# STANDALONE SINGLE EMAIL VERIFIER (for pattern inference)
# ============================================================

def verify_single_email_standalone(email, mx_list):
    if not EMAIL_REGEX.match(email):
        return "invalid", "bad_syntax", 0

    domain = email.split('@')[1]
    if domain in DISPOSABLE_DOMAINS:
        return "invalid", "disposable_domain", 0

    for _, mx_host in mx_list:
        try:
            server = smtplib.SMTP(timeout=10)
            server.connect(mx_host)
            server.helo(HELO_DOMAIN)
            server.mail(MAIL_FROM)
            code, _ = server.rcpt(email)
            server.quit()

            if code == 250:
                catch_all = is_catch_all_domain(domain)
                if catch_all:
                    return "valid", "accepted_catch_all", 70
                return "valid", "smtp_ok", 88
            elif code in GREYLIST_CODES:
                return "risky", f"smtp_soft_{code}", 30
            elif code >= 500:
                return "invalid", f"smtp_{code}", 3
            else:
                return "risky", f"smtp_{code}", 25
        except Exception:
            continue

    return "invalid", "all_mx_failed", 8


# ============================================================
# FLASK ROUTES: progress, log, cancel, download
# ============================================================

@app.route('/progress')
def progress():
    job_id = request.args.get("job_id")
    d = data.get(job_id, {})
    return jsonify({
        "percent": d.get("progress", 0),
        "row": d.get("row", 0),
        "total": d.get("total", 0),
        "stats": d.get("stats", {}),
        "categories": d.get("categories", {}),
        "phase": d.get("phase", ""),
        "phase_detail": d.get("phase_detail", ""),
    })


@app.route('/log')
def log():
    job_id = request.args.get("job_id")
    return Response(data.get(job_id, {}).get("log", ""), mimetype='text/plain')


@app.route('/cancel', methods=['POST'])
def cancel():
    job_id = request.args.get("job_id")
    if job_id in data:
        data[job_id]['cancel'] = True
    return '', 204


@app.route('/download')
def download():
    job_id = request.args.get("job_id")
    filter_type = request.args.get("type", "all")
    job = data.get(job_id)
    if not job:
        return "Invalid job ID", 404

    job['output'].seek(0)
    reader = list(csv.DictReader(job['output']))
    if not reader:
        return "No data", 404

    email_key = next((k for k in reader[0].keys() if k.lower().strip() == 'email'), None) if reader else None

    if filter_type == "all":
        filtered = reader
    elif filter_type == "not_invalid":
        filtered = [r for r in reader if r.get('status') != 'invalid']
    elif filter_type == "invalid":
        filtered = [r for r in reader if r.get('status') == 'invalid']
    elif filter_type == "safe":
        # Safe valid: verified SMTP, not catch-all, not role-based
        filtered = [r for r in reader if r.get('status') == 'valid'
                    and r.get('reason') != 'accepted_catch_all'
                    and (r.get(email_key, '') if email_key else '').split('@')[0].lower() not in ROLE_BASED_PREFIXES]
    elif filter_type == "role_valid":
        # Role-based valid: verified SMTP, not catch-all, role-based local
        filtered = [r for r in reader if r.get('status') == 'valid'
                    and r.get('reason') != 'accepted_catch_all'
                    and (r.get(email_key, '') if email_key else '').split('@')[0].lower() in ROLE_BASED_PREFIXES]
    elif filter_type == "catch_all":
        filtered = [r for r in reader if r.get('reason') == 'accepted_catch_all']
    elif filter_type == "disabled":
        filtered = [r for r in reader if r.get('reason') == 'smtp_probe_blocked']
    elif filter_type == "unknown":
        filtered = [r for r in reader if r.get('status') == 'risky'
                    and r.get('reason') != 'smtp_probe_blocked']
    elif filter_type == "valid":
        filtered = [r for r in reader if r.get('status') == 'valid']
    elif filter_type == "risky":
        filtered = [r for r in reader if r.get('status') == 'risky']
    elif filter_type == "safe_to_send":
        filtered = [r for r in reader if r.get('safe_to_send') == 'yes']
    else:
        filtered = reader

    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=reader[0].keys())
    w.writeheader()
    for row in filtered:
        w.writerow(row)
    out.seek(0)

    download_name = f"{filter_type}-{job['filename']}"
    return Response(
        out.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": f"attachment; filename={download_name}"}
    )


if __name__ == '__main__':
    app.run(debug=True, port=5050)
