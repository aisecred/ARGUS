import subprocess
import os
import sys
import shutil
import argparse
import json
import sqlite3
import urllib.request
import urllib.error
import re
import ipaddress
import tempfile
import time
import logging
import glob
import random
import base64
import socket
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
try:
    import geoip2.database
    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False
from datetime import datetime, timezone
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# CNAME service classification — suffix → (label, is_cloud_storage, is_takeover_prone)
_CNAME_SERVICES = {
    ".s3.amazonaws.com":              ("AWS S3",            True,  False),
    ".s3-website-":                   ("AWS S3 Website",    True,  False),
    ".s3-":                           ("AWS S3 Regional",   True,  False),
    ".blob.core.windows.net":         ("Azure Blob",        True,  False),
    ".file.core.windows.net":         ("Azure Files",       True,  False),
    ".storage.googleapis.com":        ("GCP Storage",       True,  False),
    ".github.io":                     ("GitHub Pages",      False, True),
    ".pages.dev":                     ("Cloudflare Pages",  False, True),
    ".netlify.app":                   ("Netlify",           False, True),
    ".vercel.app":                    ("Vercel",            False, True),
    ".surge.sh":                      ("Surge",             False, True),
    ".herokudns.com":                 ("Heroku",            False, True),
    ".herokuapp.com":                 ("Heroku",            False, True),
    ".azurewebsites.net":             ("Azure Web App",     False, True),
    ".cloudapp.azure.com":            ("Azure Cloud App",   False, True),
    ".myshopify.com":                 ("Shopify",           False, False),
    ".wpengine.com":                  ("WP Engine",         False, False),
    ".cloudfront.net":                ("CloudFront CDN",    False, False),
    ".fastly.net":                    ("Fastly CDN",        False, False),
}


def _check_resolves(hostname):
    """Return True if hostname resolves, False on NXDOMAIN or error."""
    try:
        socket.getaddrinfo(hostname.rstrip("."), None)
        return True
    except socket.gaierror:
        return False


def _dns_txt(name):
    """Query TXT records. Returns list of de-quoted strings."""
    try:
        r = subprocess.run(
            ["dig", "+short", "+time=5", "+tries=2", "TXT", name],
            capture_output=True, text=True, timeout=10
        )
        lines = []
        for l in r.stdout.strip().splitlines():
            l = re.sub(r'"\s+"', '', l.strip()).strip('"')
            if l:
                lines.append(l)
        return lines
    except Exception:
        return []


def _dns_mx(name):
    """Query MX records. Returns sorted list of (priority, exchange) tuples."""
    try:
        r = subprocess.run(
            ["dig", "+short", "+time=5", "+tries=2", "MX", name],
            capture_output=True, text=True, timeout=10
        )
        records = []
        for l in r.stdout.strip().splitlines():
            parts = l.strip().split()
            if len(parts) >= 2:
                try:
                    records.append((int(parts[0]), parts[1].rstrip(".")))
                except ValueError:
                    pass
        return sorted(records)
    except Exception:
        return []


def _spf_lookup_count(record):
    """Count DNS-consuming SPF mechanisms (hard limit is 10)."""
    count = 0
    for token in record.split():
        token = token.lstrip("+-~?")
        if token.startswith(("include:", "exists:", "redirect=")):
            count += 1
        elif token in ("a", "mx", "ptr") or token.startswith(("a:", "a/", "mx:", "mx/", "ptr:")):
            count += 1
    return count


def _analyze_spf(domain):
    """Analyse SPF. Returns findings dict with risk, issues, record."""
    txt = _dns_txt(domain)
    spf_records = [r for r in txt if r.startswith("v=spf1")]

    if not spf_records:
        return {
            "present": False, "risk": "critical",
            "issues": ["No SPF record — anyone can send email as this domain"],
        }

    findings = {"present": True, "record": spf_records[0], "issues": [], "risk": "pass"}

    if len(spf_records) > 1:
        findings["issues"].append(f"Multiple SPF records ({len(spf_records)}) — permerror, some receivers treat this as pass")
        findings["risk"] = "high"

    rec = spf_records[0]
    if "+all" in rec:
        findings["issues"].append("+all: every IP on the internet is authorised to send as this domain")
        findings["risk"] = "critical"
    elif "?all" in rec:
        findings["issues"].append("?all (neutral): no enforcement against unauthorised senders")
        if findings["risk"] not in ("critical",): findings["risk"] = "high"
    elif "~all" in rec:
        findings["issues"].append("~all (soft fail): fails are flagged but mail is still delivered")
        if findings["risk"] == "pass": findings["risk"] = "medium"
    elif "-all" not in rec:
        findings["issues"].append("No 'all' mechanism: evaluation is undefined for non-matching senders")
        if findings["risk"] == "pass": findings["risk"] = "medium"

    lookups = _spf_lookup_count(rec)
    findings["lookup_count"] = lookups
    if lookups > 10:
        findings["issues"].append(f"Lookup chain is {lookups}/10 — permerror; spoofed mail may pass at receivers that treat permerror as pass")
        if findings["risk"] not in ("critical",): findings["risk"] = "high"
    elif lookups >= 8:
        findings["issues"].append(f"Lookup count {lookups}/10 — approaching limit, one new include: will break it")

    return findings


def _analyze_dmarc(domain):
    """Analyse DMARC. Returns findings dict."""
    records = _dns_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]

    if not dmarc_records:
        return {
            "present": False, "risk": "critical",
            "issues": ["No DMARC record — even with SPF/DKIM passing, receivers have no instruction to reject spoofed mail"],
        }

    record = dmarc_records[0]
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "none")
    pct    = int(tags.get("pct", 100))
    findings = {"present": True, "record": record, "policy": policy, "pct": pct, "tags": tags, "issues": [], "risk": "pass"}

    if policy == "none":
        findings["issues"].append("p=none: monitoring only — spoofed mail is delivered normally, attackers face zero enforcement")
        findings["risk"] = "high"
    elif policy == "quarantine":
        findings["issues"].append("p=quarantine: failing mail goes to spam folder, not rejected outright")
        if findings["risk"] == "pass": findings["risk"] = "medium"

    if pct < 100:
        findings["issues"].append(f"pct={pct}: policy only applied to {pct}% of mail — {100-pct}% of spoofed messages bypass enforcement")
        if findings["risk"] == "pass": findings["risk"] = "medium"

    if not tags.get("rua") and not tags.get("ruf"):
        findings["issues"].append("No aggregate or forensic reporting (rua/ruf) — organisation is blind to spoofing campaigns and delivery failures")
        if findings["risk"] == "pass": findings["risk"] = "low"

    if not tags.get("sp") and policy != "reject":
        findings["issues"].append("No subdomain policy (sp=) — subdomains can be spoofed independently of root domain protection")

    return findings


def _estimate_rsa_bits(p_value):
    """Estimate RSA key size from base64-encoded DER public key in DKIM record."""
    if not p_value:
        return None
    try:
        b64 = p_value.replace(" ", "").replace("\t", "")
        padding = (4 - len(b64) % 4) % 4
        der = base64.b64decode(b64 + "=" * padding)
        n = len(der)
        if n < 162:  return 512
        if n < 270:  return 1024
        if n < 430:  return 2048
        return 4096
    except Exception:
        return None


def _analyze_dkim(domain, extra_selectors=None):
    """Probe DKIM selectors. Returns list of per-selector dicts."""
    selectors = list(_DKIM_COMMON_SELECTORS)
    for s in (extra_selectors or []):
        if s not in selectors:
            selectors.append(s)

    found = []
    for sel in selectors:
        records = _dns_txt(f"{sel}._domainkey.{domain}")
        dkim = [r for r in records if "v=DKIM1" in r or "k=" in r or "p=" in r]
        if not dkim:
            continue
        tags = {}
        for part in dkim[0].split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        p       = tags.get("p", "")
        algo    = tags.get("k", "rsa")
        revoked = (p == "")
        bits    = _estimate_rsa_bits(p) if not revoked and algo == "rsa" else None

        issues, risk = [], "pass"
        if revoked:
            issues.append("Key revoked (p= empty) — mail signed with this selector will fail DKIM validation")
            risk = "low"
        elif bits and bits <= 1024:
            issues.append(f"{bits}-bit key — considered breakable; a compromised key bypasses p=reject entirely")
            risk = "medium"

        found.append({"selector": sel, "algorithm": algo, "key_bits": bits, "revoked": revoked, "issues": issues, "risk": risk})

    return found


def _analyze_mta_sts(domain):
    """Analyse MTA-STS DNS policy record."""
    records = _dns_txt(f"_mta-sts.{domain}")
    sts = [r for r in records if "v=STSv1" in r]
    if not sts:
        return {"present": False, "risk": "info", "issues": ["No MTA-STS — inbound SMTP TLS is unenforced; network-level attackers can intercept or tamper with mail in transit"]}
    tags = {}
    for part in sts[0].split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return {"present": True, "record": sts[0], "tags": tags, "issues": [], "risk": "pass"}


def _identify_mx_provider(exchange):
    for suffix, name in _MX_PROVIDERS.items():
        if exchange.lower().endswith(suffix):
            return name
    return None


def _email_risk_score(spf, dmarc, dkim_list):
    """Synthesise overall spoofing risk from SPF, DMARC, DKIM findings."""
    levels = {"critical": 4, "high": 3, "medium": 2, "low": 1, "pass": 0, "info": 0}
    worst = max(levels.get(spf.get("risk", "pass"), 0),
                levels.get(dmarc.get("risk", "pass"), 0))
    if worst >= 4: return "CRITICAL"
    if worst >= 3: return "HIGH"
    if worst >= 2: return "MEDIUM"

    # Check DKIM weakness even when SPF/DMARC look ok
    if not dkim_list:
        if dmarc.get("policy") == "reject":
            return "MEDIUM"  # p=reject without DKIM breaks forwarded mail alignment
    else:
        weak = any(d.get("key_bits") and d["key_bits"] <= 1024 for d in dkim_list if not d.get("revoked"))
        if weak:
            return "MEDIUM"

    return "LOW" if worst >= 1 else "PASS"


def audit_email_security(domains, db, outdir, verbose=False):
    """Full email security audit for each domain. Returns results dict."""
    if not shutil.which("dig"):
        print_status("--audit-email requires 'dig' (dnsutils package) — not found in PATH", Colors.YELLOW, "[!]")
        return {}

    with db._connection() as conn:
        all_hosts = [r["host"] for r in conn.execute("SELECT host FROM assets").fetchall()]

    results = {}
    for domain in domains:
        print_status(f"Auditing email security: {domain}", Colors.CYAN, "[*]")

        # Infer extra DKIM selectors from subdomains we discovered
        extra = []
        for h in all_hosts:
            sub = h.replace(f".{domain}", "")
            if sub != h and "." not in sub and 1 < len(sub) <= 20 and sub not in _DKIM_COMMON_SELECTORS:
                extra.append(sub)

        spf    = _analyze_spf(domain)
        dmarc  = _analyze_dmarc(domain)
        dkim   = _analyze_dkim(domain, extra)
        mta    = _analyze_mta_sts(domain)
        mx     = _dns_mx(domain)
        bimi   = _dns_txt(f"_bimi.{domain}")
        tlsrpt = _dns_txt(f"_smtp._tls.{domain}")

        provider = None
        for _, exchange in mx:
            provider = _identify_mx_provider(exchange)
            if provider:
                break

        risk = _email_risk_score(spf, dmarc, dkim)
        results[domain] = {
            "spf": spf, "dmarc": dmarc, "dkim": dkim, "mta_sts": mta,
            "mx": mx, "provider": provider, "bimi_present": bool(bimi),
            "tlsrpt_present": bool(tlsrpt), "spoofing_risk": risk,
        }

        risk_color = {
            "CRITICAL": Colors.RED, "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW, "LOW": Colors.GREEN, "PASS": Colors.GREEN,
        }.get(risk, Colors.CYAN)
        print_status(f"  Spoofing risk: {risk}", risk_color, "[*]")

        def _status_line(label, findings):
            if not findings.get("present"):
                print_status(f"  {label}: MISSING", Colors.RED, "[!]")
            elif findings.get("issues"):
                for issue in findings["issues"]:
                    print_status(f"  {label}: {issue}", Colors.YELLOW, "[!]")
            else:
                print_status(f"  {label}: ✓", Colors.GREEN, "[+]")

        _status_line("SPF", spf)
        _status_line("DMARC", dmarc)
        if dkim:
            valid = [d for d in dkim if not d["revoked"]]
            for d in dkim:
                if d.get("issues"):
                    print_status(f"  DKIM [{d['selector']}]: {d['issues'][0]}", Colors.YELLOW, "[!]")
            if valid:
                print_status(f"  DKIM: {len(valid)} valid selector(s) — {', '.join(d['selector'] for d in valid)}", Colors.GREEN, "[+]")
        else:
            print_status(f"  DKIM: no selectors found under common names", Colors.YELLOW, "[!]")
        _status_line("MTA-STS", mta)
        if provider:
            print_status(f"  MX provider: {provider}", Colors.CYAN, "[*]")
        if bimi:
            print_status(f"  BIMI: present", Colors.GREEN, "[+]")

        # Store email findings as vuln tags on the domain asset
        vuln_tags = []
        if not spf["present"]:
            vuln_tags.append("email:spf-missing(critical)")
        elif "+all" in spf.get("record", ""):
            vuln_tags.append("email:spf-plus-all(critical)")
        elif "~all" in spf.get("record", ""):
            vuln_tags.append("email:spf-soft-fail(medium)")
        if spf.get("lookup_count", 0) > 10:
            vuln_tags.append("email:spf-lookup-limit-exceeded(high)")

        if not dmarc["present"]:
            vuln_tags.append("email:dmarc-missing(critical)")
        elif dmarc.get("policy") == "none":
            vuln_tags.append("email:dmarc-p-none(high)")
        elif dmarc.get("policy") == "quarantine":
            vuln_tags.append("email:dmarc-quarantine(medium)")
        if dmarc.get("pct", 100) < 100:
            vuln_tags.append(f"email:dmarc-pct-{dmarc['pct']}(medium)")

        if not dkim:
            vuln_tags.append("email:dkim-not-found(medium)")
        else:
            for d in dkim:
                if d.get("key_bits") and d["key_bits"] <= 1024 and not d["revoked"]:
                    vuln_tags.append(f"email:dkim-weak-key-{d['selector']}(medium)")

        if vuln_tags:
            try:
                db.update_asset(domain, vulns=vuln_tags)
            except Exception:
                pass

    # Write detailed JSON
    audit_path = os.path.join(outdir, "email_audit.json")
    try:
        with open(audit_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        print_status(f"Email audit saved: {audit_path}", Colors.GREEN, "[+]")
    except OSError:
        pass

    return results


def _classify_cname(cname):
    """Return (service_label, is_cloud_storage, is_takeover_prone, bucket_name).
    Returns (None, False, False, None) if the CNAME is not a recognised service.
    """
    cname_lower = cname.lower().rstrip(".")
    for suffix, (label, is_storage, is_takeover) in _CNAME_SERVICES.items():
        if suffix.endswith("-") and suffix[:-1] in cname_lower:
            if is_storage:
                bucket = cname_lower.split(".s3")[0]
                return label, True, is_takeover, bucket
            return label, False, is_takeover, None
        if cname_lower.endswith(suffix.rstrip(".")):
            if is_storage:
                bucket = cname_lower[: cname_lower.rfind(suffix.rstrip("."))]
                return label, True, is_takeover, bucket.rstrip(".")
            return label, False, is_takeover, None
    return None, False, False, None


# Email security audit constants
_DKIM_COMMON_SELECTORS = [
    "default", "google", "k1", "k2", "k3", "s1", "s2", "s3",
    "mail", "dkim", "email", "selector1", "selector2",
    "proofpoint", "pp1", "mimecast", "mx", "smtp",
    "mandrill", "sendgrid", "mailchimp", "postmark", "pm",
    "zendesk1", "zendesk2", "zendesk3",
]

_MX_PROVIDERS = {
    "google.com":              "Google Workspace",
    "googlemail.com":          "Google Workspace",
    "outlook.com":             "Microsoft 365",
    "protection.outlook.com":  "Microsoft 365",
    "pphosted.com":            "Proofpoint",
    "mimecast.com":            "Mimecast",
    "messagelabs.com":         "Symantec Email Security",
    "mailgun.org":             "Mailgun",
    "sendgrid.net":            "SendGrid",
    "amazonses.com":           "Amazon SES",
    "mailchannels.net":        "MailChannels",
    "mandrillapp.com":         "Mandrill",
    "sparkpostmail.com":       "SparkPost",
}

# PTR records that are universal internet infrastructure — never add to DB
_PTR_HARD_SKIP = {".root-servers.net", ".in-addr.arpa"}

# PTR records from generic hosting platforms — store at confidence 25 (infra intel,
# not target assets; visible with --min-conf 0 but below all default thresholds)
_PTR_INFRA_SUFFIXES = {
    ".amazonaws.com", ".cloudfront.net", ".github.com",
    ".googleusercontent.com", ".fastly.net", ".akamai.net",
    ".akamaitechnologies.com", ".azurewebsites.net", ".azure.com",
    ".cloudflare.com", ".cdn77.com", ".incapdns.net",
}


def _ptr_confidence(ptr, seed_domains):
    """Return (skip, confidence) for a reverse DNS PTR record.

    skip=True  → do not add to DB at all.
    skip=False → add with the returned confidence value.
    """
    ptr_lower = ptr.lower()

    # Hard skip: universal internet infrastructure
    if any(ptr_lower.endswith(s) for s in _PTR_HARD_SKIP):
        return True, 0

    # Related to a seed domain → standard reverse DNS confidence
    for domain in seed_domains:
        if ptr_lower == domain or ptr_lower.endswith("." + domain):
            return False, 50

    # Generic hosting/CDN PTR → low confidence (infra intel only)
    if any(ptr_lower.endswith(s) for s in _PTR_INFRA_SUFFIXES):
        return False, 25

    # Unknown PTR with no domain relationship → treat same as reverse DNS
    return False, 50


# --- TERMINAL COLORS ---
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def print_status(msg, color=Colors.BLUE, symbol="[*]"):
    logging.info(f"{symbol} {msg}")
    print(f"{color}{Colors.BOLD}{symbol} {msg}{Colors.END}")

def check_dependencies(tools):
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        print_status(f"Missing required tools: {', '.join(missing)}", Colors.YELLOW, "[!]")
        # do not exit; warn and continue (operators may run parts without all tools)

# new: simple env-var pre-checks for optional enrichments (e.g. PDCP)
def check_env_vars(vars_list):
    for v in vars_list:
        if not os.environ.get(v):
            print_status(f"Environment variable {v} not set — setting {v}=<key> can improve enrichment accuracy", Colors.YELLOW, "[!]")

def query_shodan(domain, api_key, verbose=False):
    """Query Shodan DNS domain endpoint for subdomains. Returns set of FQDNs."""
    try:
        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
        req = urllib.request.Request(url, headers={"User-Agent": "argus/2.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        found = set()
        for sub in (data.get("subdomains") or []):
            found.add(f"{sub}.{domain}".lower())
        return found
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print_status("Shodan: invalid API key", Colors.YELLOW, "[!]")
        elif verbose:
            print_status(f"Shodan query failed for {domain}: {e}", Colors.YELLOW, "[!]")
        return set()
    except Exception as e:
        if verbose:
            print_status(f"Shodan query error for {domain}: {e}", Colors.YELLOW, "[!]")
        return set()


def query_censys(domain, api_token=None, api_id=None, api_secret=None, verbose=False):
    """Query Censys certificate search for subdomains. Returns set of FQDNs.

    The /v2/certificates/search endpoint requires a paid Legacy Search account
    (App ID + Secret). Free-tier bearer tokens are lookup-only and cannot
    search, so App ID + Secret takes precedence when both are provided.
    """
    if api_id and api_secret:
        credentials = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        auth_header = f"Basic {credentials}"
        auth_label = "App ID/Secret"
    elif api_token:
        auth_header = f"Bearer {api_token}"
        auth_label = "bearer token"
    else:
        return set()

    try:
        payload = json.dumps({"q": f"parsed.names: {domain}", "per_page": 100, "fields": ["parsed.names"]}).encode()
        req = urllib.request.Request(
            "https://search.censys.io/api/v2/certificates/search",
            data=payload,
            headers={
                "Authorization": auth_header,
                "Content-Type": "application/json",
                "User-Agent": "argus/2.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        found = set()
        for hit in (data.get("result", {}).get("hits") or []):
            for name in (hit.get("parsed.names") or []):
                name = name.lower().strip("*. ")
                if name and name.endswith(domain):
                    found.add(name)
        return found
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            if auth_label == "bearer token":
                print_status("Censys: bearer token cannot search certificates — free tier is lookup-only. Add censys_api_id + censys_api_secret (paid) for subdomain discovery.", Colors.YELLOW, "[!]")
            else:
                print_status(f"Censys: invalid credentials ({auth_label})", Colors.YELLOW, "[!]")
        elif verbose:
            print_status(f"Censys query failed for {domain}: {e}", Colors.YELLOW, "[!]")
        return set()
    except Exception as e:
        if verbose:
            print_status(f"Censys query error for {domain}: {e}", Colors.YELLOW, "[!]")
        return set()


def query_virustotal(domain, api_key, verbose=False):
    """Query VirusTotal subdomains endpoint. Returns set of FQDNs."""
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
        req = urllib.request.Request(url, headers={"x-apikey": api_key, "User-Agent": "argus/2.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        found = set()
        for item in (data.get("data") or []):
            host = item.get("id", "").lower()
            if host:
                found.add(host)
        return found
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            print_status("VirusTotal: invalid API key", Colors.YELLOW, "[!]")
        elif verbose:
            print_status(f"VirusTotal query failed for {domain}: {e}", Colors.YELLOW, "[!]")
        return set()
    except Exception as e:
        if verbose:
            print_status(f"VirusTotal query error for {domain}: {e}", Colors.YELLOW, "[!]")
        return set()


def run_api_enrichment(domains, args, verbose=False):
    """Run all configured API enrichment sources. Returns set of discovered hostnames."""
    shodan_key     = os.environ.get("SHODAN_API_KEY")     or getattr(args, "shodan_api_key",     None)
    censys_token   = os.environ.get("CENSYS_API_TOKEN")   or getattr(args, "censys_api_token",   None)
    censys_id      = os.environ.get("CENSYS_API_ID")      or getattr(args, "censys_api_id",      None)
    censys_secret  = os.environ.get("CENSYS_API_SECRET")  or getattr(args, "censys_api_secret",  None)
    vt_key         = os.environ.get("VIRUSTOTAL_API_KEY") or getattr(args, "virustotal_api_key",  None)

    has_censys = bool(censys_token or (censys_id and censys_secret))

    shodan_found = set()
    censys_found = set()
    vt_found     = set()

    for domain in domains:
        if shodan_key:
            shodan_found.update(query_shodan(domain, shodan_key, verbose))
        if has_censys:
            censys_found.update(query_censys(
                domain,
                api_token=censys_token,
                api_id=censys_id,
                api_secret=censys_secret,
                verbose=verbose,
            ))
        if vt_key:
            vt_found.update(query_virustotal(domain, vt_key, verbose))

    if shodan_key:
        print_status(f"Shodan: {len(shodan_found)} entries added to seeds", Colors.GREEN, "[+]")
    if has_censys:
        print_status(f"Censys: {len(censys_found)} entries added to seeds", Colors.GREEN, "[+]")
    if vt_key:
        print_status(f"VirusTotal: {len(vt_found)} entries added to seeds", Colors.GREEN, "[+]")

    return shodan_found | censys_found | vt_found


def detect_wildcard_dns(domain, resolvers=None):
    """Return set of IPs if domain has wildcard DNS, else empty set."""
    probe = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=12)) + '.' + domain
    cmd = ["dnsx", "-d", probe, "-a", "-json", "-silent"]
    if resolvers:
        cmd.extend(["-r", resolvers])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        wildcard_ips = set()
        for line in result.stdout.splitlines():
            try:
                d = json.loads(line)
                for ip in (d.get("a") or []):
                    wildcard_ips.add(ip)
            except json.JSONDecodeError:
                continue
        return wildcard_ips
    except Exception:
        return set()


def get_random_user_agent():
    """Return a random popular browser User-Agent string."""
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0"
    ]
    return random.choice(user_agents)

def run_command(command, log_msg, verbose=False, use_shell=False, timeout=None):
    """Run a command, capture stdout/stderr and return CompletedProcess-like dict.
    If verbose=True stream stdout/stderr live (useful for long tools like tlsx)."""
    print_status(f"{log_msg}...", Colors.CYAN)
    try:
        if verbose:
            # stream output live for visibility
            cmd = command if not use_shell else (command if isinstance(command, str) else " ".join(command))
            proc = subprocess.Popen(cmd, shell=use_shell, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            out_lines = []
            start = time.time()
            try:
                for line in proc.stdout:
                    out_lines.append(line)
                    print(line.rstrip())
                    if timeout and (time.time() - start) > timeout:
                        proc.kill()
                        raise subprocess.TimeoutExpired(cmd=command, timeout=timeout)
                proc.wait()
            except subprocess.TimeoutExpired:
                proc.kill()
                raise
            stdout = "".join(out_lines)
            stderr = ""
            returncode = proc.returncode
        else:
            if use_shell:
                proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
            else:
                proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
            stdout = proc.stdout
            stderr = proc.stderr
            returncode = proc.returncode

    except subprocess.TimeoutExpired as e:
        print_status(f"Timeout in {log_msg}: {e}", Colors.YELLOW, "[!]")
        return {"returncode": -1, "stdout": e.stdout or "", "stderr": str(e)}
    except subprocess.CalledProcessError as e:
        print_status(f"Error in {log_msg}: {e}", Colors.YELLOW, "[!]")
        return {"returncode": getattr(e, "returncode", -1), "stdout": getattr(e, "stdout", ""), "stderr": getattr(e, "stderr", str(e))}
    except OSError as e:
        print_status(f"OS error running {log_msg}: {e}", Colors.YELLOW, "[!]")
        return {"returncode": -1, "stdout": "", "stderr": str(e)}

    if returncode != 0:
        print_status(f"{log_msg} returned code {returncode}", Colors.YELLOW, "[!]")
        if verbose:
            logging.debug(stdout)
            logging.debug(stderr)

    if verbose:
        logging.debug(stdout)
        logging.debug(stderr)

    return {"returncode": returncode, "stdout": stdout, "stderr": stderr}


def find_recon_db_files(directories, recursive=False):
    """Return a sorted list of recon.db file paths found under directories."""
    files = set()
    for path in directories:
        if not path:
            continue
        path = os.path.abspath(path)
        if os.path.isfile(path) and os.path.basename(path) == "recon.db":
            files.add(path)
            continue
        if os.path.isdir(path):
            direct = os.path.join(path, "recon.db")
            if os.path.isfile(direct):
                files.add(direct)
            if recursive:
                for root, _, filenames in os.walk(path):
                    if "recon.db" in filenames:
                        files.add(os.path.join(root, "recon.db"))
    return sorted(files)


def merge_recon_databases(output_db, source_db_paths, brand_hint=None):
    """Merge multiple source recon.db files into a single output DB."""
    if not source_db_paths:
        return 0
    output_db = ReconDB(output_db)
    merged = 0
    for source_path in source_db_paths:
        try:
            abs_source = os.path.abspath(source_path)
            abs_output = os.path.abspath(output_db.db_path)
            if abs_source == abs_output:
                continue
            with sqlite3.connect(source_path) as src_conn:
                src_conn.row_factory = sqlite3.Row
                for row in src_conn.execute("SELECT * FROM assets"):
                    kwargs = {
                        k: row[k] for k in row.keys() if k not in ("host",)
                    }
                    output_db.update_asset(row["host"], brand_hint=brand_hint, **kwargs)
                    merged += 1
        except sqlite3.Error as e:
            print_status(f"Failed to merge DB {source_path}: {e}", Colors.YELLOW, "[!]")
            continue
    print_status(f"Merged {merged} asset records from {len(source_db_paths)} recon.db files", Colors.GREEN, "[+]")
    return merged


def send_webhook_payload(url, payload, timeout=15):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or getattr(resp, "code", None)
            body = resp.read().decode("utf-8", errors="replace")
            print_status(f"Webhook {url} responded with {status}", Colors.GREEN, "[+]")
            if body:
                logging.debug(body)
            return True
    except Exception as e:
        print_status(f"Failed to send webhook to {url}: {e}", Colors.YELLOW, "[!]")
        return False


def send_webhook_notifications(urls, payload):
    for url in urls:
        send_webhook_payload(url, payload)


def load_config_file(config_path):
    """Load configuration from YAML or JSON file."""
    if not os.path.exists(config_path):
        print_status(f"Config file not found: {config_path}", Colors.YELLOW, "[!]")
        return {}
    
    try:
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            if not HAS_YAML:
                print_status("PyYAML not installed. Install with: pip install pyyaml", Colors.YELLOW, "[!]")
                return {}
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f) or {}
        elif config_path.endswith('.json'):
            with open(config_path, 'r') as f:
                config = json.load(f)
        else:
            print_status(f"Unsupported config format: {config_path} (use .yaml or .json)", Colors.YELLOW, "[!]")
            return {}
        
        print_status(f"Loaded configuration from {config_path}", Colors.GREEN, "[+]")
        return config
    except Exception as e:
        print_status(f"Failed to parse config file {config_path}: {e}", Colors.YELLOW, "[!]")
        return {}


def apply_preset(args, preset):
    """Apply a built-in preset configuration."""
    if preset == 'passive':
        # Passive recon only: no active tools
        args.httpx = False
        args.gowitness = False
        args.tech_stack_enum = False
        args.nuclei = False
        args.reverse_dns = True
        args.geolocate   = True
        args.audit_email = True
        print_status("Applied 'passive' preset: passive recon with reverse DNS, geolocation, and email audit", Colors.GREEN, "[+]")
    elif preset == 'active':
        # Active recon: safe active tools
        args.httpx = True
        args.tech_stack_enum = True
        args.reverse_dns = True
        args.geolocate = True
        args.gowitness = False  # Skip screenshots for speed
        args.nuclei = False  # Skip vuln scan
        print_status("Applied 'active' preset: active recon with tech stack enum, reverse DNS, and geolocation", Colors.GREEN, "[+]")
    elif preset == 'full':
        # Full recon: everything
        args.httpx = True
        args.gowitness = True
        args.tech_stack_enum = True
        args.nuclei = True
        args.reverse_dns = True
        args.geolocate = True
        print_status("Applied 'full' preset: complete recon with all tools", Colors.GREEN, "[+]")


class ReconDB:
    def __init__(self, db_path):
        self.db_path = db_path
        self._setup_tables()

    @contextmanager
    def _connection(self):
        # set timeout to reduce lock errors; enable WAL for concurrency/durability
        conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
        except sqlite3.DatabaseError:
            pass
        try:
            yield conn
        finally:
            conn.close()

    def _setup_tables(self):
        with self._connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS assets (
                    host TEXT PRIMARY KEY, ip TEXT, asn TEXT, cdn TEXT,
                    confidence INTEGER DEFAULT 0, discovery_reason TEXT,
                    web_title TEXT, status_code INTEGER, tech_stack TEXT,
                    open_ports TEXT, vulns TEXT, is_live INTEGER DEFAULT 1,
                    first_seen TEXT, last_seen TEXT, last_scanned TEXT,
                    tools_run TEXT, screenshot_path TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT,
                    completed_at TEXT,
                    domains TEXT
                )
            ''')
            conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_confidence ON assets(confidence);")
            conn.commit()
            # add columns introduced later without breaking existing DBs
            for col_ddl in [
                "ALTER TABLE assets ADD COLUMN cidr TEXT;",
                "ALTER TABLE assets ADD COLUMN geolocation TEXT;",
                "ALTER TABLE assets ADD COLUMN cname TEXT;",
            ]:
                try:
                    conn.execute(col_ddl)
                except sqlite3.OperationalError:
                    pass

    def update_asset(self, host, tool_name=None, brand_hint=None, **kwargs):
        if not host:
            return
        host = host.split(":")[0].lower().strip()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
         
        with self._connection() as conn:
            cursor = conn.cursor()
            # safer IP detection using ipaddress
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                is_ip = False

            if is_ip:
                cursor.execute("SELECT host FROM assets WHERE ip LIKE ?", (f"%{host}%",))
                row = cursor.fetchone()
                if row:
                    host = row[0]
                else:
                    return 

            if 'ip' in kwargs:
                if isinstance(kwargs['ip'], list):
                    kwargs['ip'] = ", ".join(kwargs['ip'])
                kwargs['ip'] = str(kwargs['ip']).replace("[", "").replace("]", "").replace("'", "")

            if tool_name:
                cursor.execute("SELECT tools_run FROM assets WHERE host = ?", (host,))
                row = cursor.fetchone()
                existing_tools = set(row[0].split(", ")) if row and row[0] else set()
                existing_tools.add(tool_name)
                kwargs['tools_run'] = ", ".join(sorted(list(existing_tools)))
                kwargs['last_scanned'] = now

            if brand_hint and kwargs.get('web_title'):
                try:
                    title_lower = kwargs['web_title'].lower()
                    if isinstance(brand_hint, (list, set)):
                        if any(bk.lower() in title_lower for bk in brand_hint):
                            kwargs['confidence'] = 100
                    else:
                        if brand_hint.lower() in title_lower:
                            kwargs['confidence'] = 100
                except AttributeError:
                    pass

            for col in ['open_ports', 'tech_stack', 'vulns']:
                if col in kwargs:
                    new_vals = set(map(str, kwargs[col])) if isinstance(kwargs[col], list) else {str(kwargs[col])}
                    cursor.execute(f"SELECT {col} FROM assets WHERE host = ?", (host,))
                    row = cursor.fetchone()
                    if row and row[0]:
                        existing = set(row[0].split(", "))
                        new_vals.update(existing)
                    kwargs[col] = ", ".join(sorted([v for v in list(new_vals) if v and v != 'None']))

            cursor.execute("SELECT first_seen FROM assets WHERE host = ?", (host,))
            if not cursor.fetchone():
                kwargs['first_seen'] = now
            kwargs['last_seen'] = now
            
            cols = ', '.join([f"{k} = ?" for k in kwargs.keys()])
            vals = list(kwargs.values()) + [host]
            cursor.execute(f"INSERT OR IGNORE INTO assets (host) VALUES (?)", (host,))
            if cols:
                cursor.execute(f"UPDATE assets SET {cols} WHERE host = ?", vals)
            conn.commit()

    # new: utility helpers required by orchestration logic
    def get_total_count(self):
        with self._connection() as conn:
            cur = conn.execute("SELECT COUNT(*) AS cnt FROM assets")
            row = cur.fetchone()
            return int(row["cnt"]) if row else 0

    def get_hosts_by_confidence(self, min_conf=0):
        with self._connection() as conn:
            cur = conn.execute(
                "SELECT host FROM assets WHERE confidence >= ? AND is_live = 1 ORDER BY confidence DESC",
                (min_conf,)
            )
            return [r["host"] for r in cur.fetchall()]

    def has_run_tool(self, host, tool_name):
        """Return True if 'tool_name' appears in tools_run for host."""
        if not host:
            return False
        with self._connection() as conn:
            row = conn.execute("SELECT tools_run FROM assets WHERE host = ?", (host,)).fetchone()
            if not row or not row["tools_run"]:
                return False
            tools = [t.strip() for t in row["tools_run"].split(",") if t.strip()]
            return tool_name in tools

    def get_summary(self, min_conf=0):
        with self._connection() as conn:
            total = conn.execute("SELECT COUNT(*) AS cnt FROM assets").fetchone()["cnt"] or 0
            live = conn.execute("SELECT COUNT(*) AS cnt FROM assets WHERE is_live = 1").fetchone()["cnt"] or 0
            above = conn.execute("SELECT COUNT(*) AS cnt FROM assets WHERE confidence >= ?", (min_conf,)).fetchone()["cnt"] or 0

            cur = conn.execute(
                "SELECT host, ip, asn, cidr, cdn, confidence, status_code, open_ports, tools_run, first_seen, last_seen FROM assets WHERE confidence >= ? ORDER BY confidence DESC, host LIMIT 200",
                (min_conf,)
            )
            rows = [dict(r) for r in cur.fetchall()]

        return {"total": total, "live": live, "above": above, "rows": rows}

    def record_scan_start(self, domains):
        """Insert a scan row and return (scan_id, started_at)."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        domains_str = ", ".join(sorted(domains)) if domains else ""
        with self._connection() as conn:
            cur = conn.execute(
                "INSERT INTO scans (started_at, domains) VALUES (?, ?)", (now, domains_str)
            )
            conn.commit()
            return cur.lastrowid, now

    def record_scan_complete(self, scan_id):
        """Mark a scan row as completed."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with self._connection() as conn:
            conn.execute("UPDATE scans SET completed_at = ? WHERE id = ?", (now, scan_id))
            conn.commit()

    def write_snapshot(self, filepath):
        """Write a JSON snapshot of current asset state for delta comparison."""
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT host, ip, confidence, status_code, vulns, tech_stack, cdn, asn FROM assets"
            ).fetchall()
        snapshot = {
            "snapshot_time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "assets": {
                row["host"]: {
                    "ip": row["ip"] or "",
                    "confidence": row["confidence"] or 0,
                    "status_code": row["status_code"],
                    "vulns": row["vulns"] or "",
                    "tech_stack": row["tech_stack"] or "",
                    "cdn": row["cdn"] or "",
                    "asn": row["asn"] or "",
                }
                for row in rows
            },
        }
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(snapshot, f)
        except OSError as e:
            print_status(f"Failed to write snapshot: {e}", Colors.YELLOW, "[!]")

    def compute_delta(self, snapshot_path, scan_start):
        """Compare current DB state against pre-scan snapshot.
        Returns dict with keys: new, removed, changed."""
        prev = {}
        if os.path.exists(snapshot_path):
            try:
                with open(snapshot_path, "r", encoding="utf-8") as f:
                    prev = json.load(f).get("assets", {})
            except (OSError, json.JSONDecodeError):
                pass

        with self._connection() as conn:
            current_rows = conn.execute(
                "SELECT host, ip, confidence, status_code, vulns, tech_stack, cdn, asn, first_seen "
                "FROM assets"
            ).fetchall()

        current = {row["host"]: dict(row) for row in current_rows}

        new_assets, changed_assets = [], []
        for host, cur in current.items():
            if host not in prev:
                if (cur.get("first_seen") or "") >= scan_start:
                    new_assets.append(cur)
            else:
                p = prev[host]
                changes = []
                if (cur.get("ip") or "") != (p.get("ip") or ""):
                    changes.append(f"ip: {p.get('ip') or 'none'} → {cur.get('ip') or 'none'}")
                if (cur.get("confidence") or 0) != (p.get("confidence") or 0):
                    changes.append(f"confidence: {p.get('confidence') or 0} → {cur.get('confidence') or 0}")
                if str(cur.get("status_code") or "") != str(p.get("status_code") or ""):
                    changes.append(f"status: {p.get('status_code') or '-'} → {cur.get('status_code') or '-'}")
                if (cur.get("vulns") or "") != (p.get("vulns") or ""):
                    changes.append(f"vulns: {p.get('vulns') or 'none'} → {cur.get('vulns') or 'none'}")
                if changes:
                    changed_assets.append({"host": host, "changes": changes, "confidence": cur.get("confidence") or 0})

        removed_assets = [{"host": h, **v} for h, v in prev.items() if h not in current]
        return {"new": new_assets, "removed": removed_assets, "changed": changed_assets}

    def query_summary(self, min_conf=0):
        summary = self.get_summary(min_conf)

        def _t(s, w):
            s = "" if s is None else str(s)
            return s if len(s) <= w else s[: max(0, w - 3)] + "..."
 
        print_status(f"DB Summary: total={summary['total']}, live={summary['live']}, >=conf={min_conf}={summary['above']}", Colors.GREEN, "[=]")
        print()
        print("Argus — Asset Intelligence Report")
        hdr = ("Host", "IP Address", "ASN", "CIDR", "CDN", "Confidence", "Status Code", "Ports", "Tools Run", "First Seen", "Last Seen")
        widths = [30, 15, 10, 18, 8, 10, 12, 14, 25, 19, 19]
        # header line
        header_line = " | ".join(h.ljust(w) for h, w in zip(hdr, widths))
        sep = "-" * len(header_line)
        print(header_line)
        print(sep)

        for r in summary['rows']:
            host = _t(r.get("host", ""), widths[0])
            ip = _t(str((r.get("ip") or "")).replace(", ", ","), widths[1])
            asn = _t(r.get("asn", ""), widths[2])
            cidr = _t(r.get("cidr", ""), widths[3])
            cdn = _t(r.get("cdn", ""), widths[4])
            conf = _t(r.get("confidence", ""), widths[5])
            status = _t(r.get("status_code", ""), widths[6])
            ports = _t(r.get("open_ports", ""), widths[7])
            tools = _t(r.get("tools_run", ""), widths[8])
            first = _t(r.get("first_seen", ""), widths[9])
            last = _t(r.get("last_seen", ""), widths[10])

            row_line = f"{host.ljust(widths[0])} | {ip.ljust(widths[1])} | {asn.ljust(widths[2])} | {cidr.ljust(widths[3])} | {cdn.ljust(widths[4])} | {str(conf).rjust(widths[5])} | {str(status).rjust(widths[6])} | {ports.ljust(widths[7])} | {tools.ljust(widths[8])} | {first.ljust(widths[9])} | {last.ljust(widths[10])}"
            print(row_line)
        print()

    def export_csv(self, filepath, min_conf=0):
        """Export database to CSV file."""
        import csv
        with self._connection() as conn:
            cur = conn.execute(
                "SELECT host, ip, asn, cidr, cdn, confidence, cname, discovery_reason, "
                "web_title, status_code, tech_stack, open_ports, vulns, geolocation, "
                "is_live, first_seen, last_seen, last_scanned, tools_run, screenshot_path "
                "FROM assets WHERE confidence >= ? ORDER BY confidence DESC, host",
                (min_conf,)
            )
            rows = cur.fetchall()

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'host', 'ip', 'asn', 'cidr', 'cdn', 'confidence', 'cname',
                'discovery_reason', 'web_title', 'status_code', 'tech_stack',
                'open_ports', 'vulns', 'geolocation', 'is_live',
                'first_seen', 'last_seen', 'last_scanned', 'tools_run', 'screenshot_path',
            ])
            for row in rows:
                writer.writerow(row)
        print_status(f"CSV export saved: {filepath}", Colors.GREEN, "[+]")

    def export_json(self, filepath, min_conf=0):
        """Export database to JSON file."""
        with self._connection() as conn:
            cur = conn.execute(
                "SELECT host, ip, asn, cidr, cdn, confidence, cname, discovery_reason, "
                "web_title, status_code, tech_stack, open_ports, vulns, geolocation, "
                "is_live, first_seen, last_seen, last_scanned, tools_run, screenshot_path "
                "FROM assets WHERE confidence >= ? ORDER BY confidence DESC, host",
                (min_conf,)
            )
            rows = [dict(r) for r in cur.fetchall()]
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(rows, f, indent=2, default=str)
        print_status(f"JSON export saved: {filepath}", Colors.GREEN, "[+]")

    def generate_html_report(self, min_conf, outdir):
        """Generate a self-contained HTML report of the asset ledger."""
        from html import escape as he

        def _t(s):
            return "" if s is None else str(s)

        with self._connection() as conn:
            total  = conn.execute("SELECT COUNT(*) AS c FROM assets").fetchone()["c"] or 0
            live   = conn.execute("SELECT COUNT(*) AS c FROM assets WHERE is_live=1").fetchone()["c"] or 0
            above  = conn.execute("SELECT COUNT(*) AS c FROM assets WHERE confidence>=?", (min_conf,)).fetchone()["c"] or 0
            t_cand = conn.execute("SELECT COUNT(*) AS c FROM assets WHERE vulns LIKE '%takeover-risk%'").fetchone()["c"] or 0
            t_conf = conn.execute("SELECT COUNT(*) AS c FROM assets WHERE vulns LIKE '%subdomain-takeover:%'").fetchone()["c"] or 0
            rows = [dict(r) for r in conn.execute(
                "SELECT host, ip, asn, cidr, cdn, confidence, cname, tech_stack, "
                "web_title, status_code, open_ports, vulns, geolocation, discovery_reason, "
                "first_seen, last_seen, tools_run "
                "FROM assets WHERE confidence >= ? ORDER BY confidence DESC, host",
                (min_conf,)
            ).fetchall()]
            # CDN breakdown
            cdn_rows = conn.execute(
                "SELECT cdn, COUNT(*) AS c FROM assets WHERE cdn IS NOT NULL AND cdn != '' AND cdn != 'No' "
                "GROUP BY cdn ORDER BY c DESC LIMIT 10"
            ).fetchall()
            # ASN breakdown
            asn_rows = conn.execute(
                "SELECT asn, COUNT(*) AS c FROM assets WHERE asn IS NOT NULL AND asn != '' "
                "GROUP BY asn ORDER BY c DESC LIMIT 10"
            ).fetchall()

        scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        def conf_class(c):
            c = int(c or 0)
            if c >= 85: return "conf-high"
            if c >= 50: return "conf-mid"
            if c >= 25: return "conf-low"
            return "conf-vlow"

        def row_class(r):
            v = _t(r.get("vulns"))
            if "subdomain-takeover:" in v: return "row-takeover-confirmed"
            if "takeover-risk" in v:       return "row-takeover"
            return ""

        def badge(text, cls):
            return f'<span class="badge {cls}">{he(text)}</span>' if text else ""

        def vuln_cell(row):
            v      = _t(row.get("vulns"))
            cname  = _t(row.get("cname"))
            svc    = _t(row.get("tech_stack", "")).split(",")[0].strip() if row.get("tech_stack") else ""
            host   = _t(row.get("host"))
            if not v:
                return ""

            if "subdomain-takeover:" in v:
                tip = (
                    "CONFIRMED Subdomain Takeover&#10;"
                    "&#10;"
                    f"Host: {he(host)}&#10;"
                    f"CNAME: {he(cname)}&#10;"
                    "&#10;"
                    "This takeover was confirmed by Nuclei. An attacker can currently&#10;"
                    "serve arbitrary content from this subdomain — enabling phishing,&#10;"
                    "credential harvesting, or malware delivery under a trusted name.&#10;"
                    "&#10;"
                    "Immediate action required: remove or reclaim the CNAME target."
                )
                return (
                    f'<span class="badge badge-danger has-tip" data-tip="{tip}">⚠ CONFIRMED TAKEOVER</span>'
                    f'<br><small>{he(v)}</small>'
                )

            if "takeover-risk" in v:
                nxdomain = "(nxdomain)" in v
                nxd_line = (
                    "The CNAME target returned NXDOMAIN — the external resource does not&#10;"
                    "exist. This is a strong indicator of vulnerability."
                    if nxdomain else
                    "The CNAME target currently resolves. Manually verify that the&#10;"
                    f"account/page at {he(cname)} is still claimed by this organisation."
                )
                tip = (
                    "Subdomain Takeover Risk&#10;"
                    "&#10;"
                    f"Host:    {he(host)}&#10;"
                    f"CNAME:   {he(cname)}&#10;"
                    f"Service: {he(svc) if svc else 'Unknown'}&#10;"
                    "&#10;"
                    "A subdomain takeover occurs when a DNS CNAME points to a third-party&#10;"
                    "service (GitHub Pages, Netlify, Heroku, etc.) whose account or page&#10;"
                    "is no longer claimed by the organisation. An attacker can register&#10;"
                    "that external resource and serve arbitrary content from this subdomain.&#10;"
                    "&#10;"
                    f"{nxd_line}&#10;"
                    "&#10;"
                    "Attack potential: phishing, credential harvesting, malware delivery,&#10;"
                    "cookie theft (if subdomain shares a parent domain with auth cookies).&#10;"
                    "&#10;"
                    "To verify: confirm the external service account/page is actively&#10;"
                    "claimed and controlled by this organisation. Run --takeover to&#10;"
                    "confirm with Nuclei templates."
                )
                return (
                    f'<span class="badge badge-warning has-tip" data-tip="{tip}">⚠ Takeover Risk</span>'
                    f'<br><small class="cname-val">{he(cname)}</small>'
                )

            # Email audit findings — build tooltip per tag
            if "email:" in v:
                _email_tips = {
                    "spf-missing":       ("No SPF Record",           "Without SPF, any server on the internet can send email claiming to be from this domain. There is no technical barrier to spoofing. Enables direct brand impersonation for phishing and business email compromise."),
                    "spf-plus-all":      ("SPF +all (Critical)",      "+all explicitly authorises every IP on the internet to send as this domain. This is worse than no SPF record — it actively certifies spoofed mail as legitimate."),
                    "spf-soft-fail":     ("SPF ~all (Soft Fail)",     "~all marks unauthorised senders as suspicious but does not reject them. Without DMARC enforcement, this is effectively no protection — most receivers deliver the mail anyway."),
                    "spf-lookup-limit":  ("SPF Lookup Limit Exceeded","SPF allows a maximum of 10 DNS lookups. Exceeding this causes a permerror. Some receivers treat permerror as a pass, allowing spoofed mail through even though an SPF record exists."),
                    "dmarc-missing":     ("No DMARC Record",          "DMARC is the enforcement layer. Without it, SPF and DKIM results are informational only — receivers have no instruction to reject or quarantine failing mail. Even with SPF and DKIM configured, spoofed mail will be delivered."),
                    "dmarc-p-none":      ("DMARC p=none",             "p=none is monitoring mode only. Spoofed mail that fails SPF and DKIM is still delivered normally to recipients. This is the most common false sense of security — the record exists but provides zero protection."),
                    "dmarc-quarantine":  ("DMARC p=quarantine",       "Failing mail is sent to spam rather than rejected. Sophisticated phishing attacks may still succeed if recipients check their spam folder, or if the mail client displays spam with low visual distinction."),
                    "dkim-not-found":    ("No DKIM Selectors Found",  "DKIM was not found under any common selector names. Without DKIM, DMARC can only align on SPF — which breaks for forwarded mail. This can force the org toward weaker DMARC policies to avoid breaking legitimate forwarded mail."),
                    "dkim-weak-key":     ("Weak DKIM Key (≤1024-bit)","1024-bit RSA keys are considered breakable with sufficient compute. A compromised DKIM key allows an attacker to sign arbitrary mail as this domain with a valid cryptographic signature, bypassing p=reject DMARC enforcement entirely."),
                }
                tags_html = ""
                for tag in v.split(","):
                    tag = tag.strip()
                    matched_tip = None
                    for key, (title, explanation) in _email_tips.items():
                        if key in tag:
                            matched_tip = (title, explanation)
                            break
                    if matched_tip:
                        tip_text = f"{matched_tip[0]}&#10;&#10;{matched_tip[1]}"
                        tags_html += f'<span class="badge badge-warning has-tip" style="margin:1px" data-tip="{he(tip_text)}">{he(tag)}</span> '
                    else:
                        tags_html += f'<span class="badge badge-info" style="margin:1px">{he(tag)}</span> '
                return f'<div style="line-height:1.8">{tags_html}</div>'

            return f'<small>{he(v)}</small>'

        # Build CDN / ASN stat cards
        cdn_stats = "".join(f'<div class="stat-item"><span class="stat-label">{he(_t(r["cdn"]))}</span><span class="stat-num">{r["c"]}</span></div>' for r in cdn_rows)
        asn_stats = "".join(f'<div class="stat-item"><span class="stat-label">{he(_t(r["asn"]))}</span><span class="stat-num">{r["c"]}</span></div>' for r in asn_rows)

        # Build table rows
        tbody = ""
        for r in rows:
            rc = row_class(r)
            cc = conf_class(r.get("confidence"))
            cname_svc = ""
            if r.get("cname"):
                svc = _t(r.get("tech_stack")).split(",")[0] if r.get("tech_stack") else ""
                cname_svc = f'<small class="cname-val">{he(_t(r["cname"]))}</small>'
                if svc:
                    cname_svc += f'<br><span class="badge badge-info">{he(svc)}</span>'
            tbody += f"""<tr class="{rc}">
  <td class="host-cell" title="{he(_t(r.get('host')))}">{he(_t(r.get('host')))}</td>
  <td><small>{he(_t(r.get('ip')))}</small></td>
  <td><small>{he(_t(r.get('asn')))}</small></td>
  <td><small>{he(_t(r.get('cidr')))}</small></td>
  <td>{he(_t(r.get('cdn')))}</td>
  <td class="conf-cell"><span class="conf-badge {cc}">{he(_t(r.get('confidence')))}</span></td>
  <td>{cname_svc}</td>
  <td>{he(_t(r.get('web_title')))}</td>
  <td>{he(_t(r.get('status_code')))}</td>
  <td>{vuln_cell(r)}</td>
  <td><small>{he(_t(r.get('geolocation')))}</small></td>
  <td><small>{he(_t(r.get('first_seen', '')).split(' ')[0])}</small></td>
</tr>\n"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Argus — Asset Intelligence Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;font-size:13px}}
a{{color:#58a6ff}}
/* Header */
.header{{background:linear-gradient(135deg,#161b22 0%,#1f2937 100%);border-bottom:1px solid #30363d;padding:24px 32px;display:flex;align-items:center;gap:24px}}
.logo{{font-size:28px;font-weight:800;color:#58a6ff;letter-spacing:-1px}}
.logo span{{color:#e2e8f0}}
.header-meta{{color:#8b949e;font-size:12px;line-height:1.8}}
.header-meta strong{{color:#c9d1d9}}
/* Summary cards */
.summary{{display:flex;gap:16px;padding:20px 32px;flex-wrap:wrap;border-bottom:1px solid #21262d}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;min-width:120px;text-align:center}}
.card-num{{font-size:28px;font-weight:700;color:#58a6ff}}
.card-num.red{{color:#f85149}}
.card-num.orange{{color:#d29922}}
.card-num.green{{color:#3fb950}}
.card-label{{font-size:11px;color:#8b949e;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}}
/* Stats section */
.stats-row{{display:flex;gap:24px;padding:16px 32px;border-bottom:1px solid #21262d;flex-wrap:wrap}}
.stats-block{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;flex:1;min-width:200px}}
.stats-block h4{{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}}
.stat-item{{display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid #21262d}}
.stat-item:last-child{{border-bottom:none}}
.stat-label{{color:#c9d1d9;font-size:12px}}
.stat-num{{color:#58a6ff;font-weight:600;font-size:12px}}
/* Takeover alert */
.takeover-alert{{margin:16px 32px;background:#1a0a0a;border:1px solid #f85149;border-radius:8px;padding:16px}}
.takeover-alert h3{{color:#f85149;font-size:14px;margin-bottom:10px}}
/* Controls */
.controls{{padding:12px 32px;display:flex;gap:12px;align-items:center;border-bottom:1px solid #21262d;flex-wrap:wrap}}
.controls input{{background:#161b22;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;padding:6px 12px;font-size:12px;width:260px}}
.controls input:focus{{outline:none;border-color:#58a6ff}}
.controls select{{background:#161b22;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;padding:6px 10px;font-size:12px}}
.controls label{{font-size:12px;color:#8b949e}}
/* Table */
.table-wrap{{overflow-x:auto;padding:0 32px 32px}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}
thead th{{background:#161b22;color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.5px;padding:8px 10px;border-bottom:2px solid #30363d;white-space:nowrap;cursor:pointer;user-select:none}}
thead th:hover{{color:#c9d1d9}}
thead th::after{{content:' ⇅';opacity:.4}}
thead th.sort-asc::after{{content:' ↑';opacity:1;color:#58a6ff}}
thead th.sort-desc::after{{content:' ↓';opacity:1;color:#58a6ff}}
tbody tr{{border-bottom:1px solid #21262d;transition:background .1s}}
tbody tr:hover{{background:#1c2128}}
tbody td{{padding:7px 10px;vertical-align:top;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
tbody td.host-cell{{max-width:260px;font-weight:500;color:#e2e8f0;white-space:normal;word-break:break-all}}
/* Row classes */
tr.row-takeover{{background:rgba(210,153,34,.07)}}
tr.row-takeover:hover{{background:rgba(210,153,34,.14)}}
tr.row-takeover-confirmed{{background:rgba(248,81,73,.1)}}
tr.row-takeover-confirmed:hover{{background:rgba(248,81,73,.18)}}
/* Confidence badges */
.conf-badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700}}
.conf-high{{background:rgba(63,185,80,.2);color:#3fb950;border:1px solid rgba(63,185,80,.3)}}
.conf-mid{{background:rgba(210,153,34,.2);color:#d29922;border:1px solid rgba(210,153,34,.3)}}
.conf-low{{background:rgba(230,162,60,.15);color:#e6a23c;border:1px solid rgba(230,162,60,.25)}}
.conf-vlow{{background:rgba(139,148,158,.15);color:#8b949e;border:1px solid rgba(139,148,158,.2)}}
/* Badges */
.badge{{display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:600}}
.badge-info{{background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid rgba(88,166,255,.2)}}
.badge-warning{{background:rgba(210,153,34,.2);color:#d29922;border:1px solid rgba(210,153,34,.3)}}
.badge-danger{{background:rgba(248,81,73,.2);color:#f85149;border:1px solid rgba(248,81,73,.3)}}
.cname-val{{color:#8b949e}}
.hidden{{display:none!important}}
footer{{text-align:center;padding:16px;color:#484f58;font-size:11px;border-top:1px solid #21262d}}
.has-tip{{cursor:help}}
#argus-tip{{position:fixed;background:#1c2128;border:1px solid #d29922;border-radius:6px;padding:12px 14px;max-width:360px;font-size:11px;color:#c9d1d9;z-index:9999;pointer-events:none;line-height:1.7;display:none;white-space:pre-line;box-shadow:0 4px 24px rgba(0,0,0,.6)}}
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="logo">ARGUS<span>.</span></div>
    <div style="font-size:11px;color:#8b949e;margin-top:2px">Adaptive Reconnaissance, Gathering, and Understanding Suite</div>
  </div>
  <div class="header-meta">
    <div><strong>Generated:</strong> {scan_date}</div>
    <div><strong>Assets:</strong> {total} total / {live} live</div>
    <div><strong>Min Confidence:</strong> {min_conf}</div>
  </div>
</div>

<div class="summary">
  <div class="card"><div class="card-num">{total}</div><div class="card-label">Total Assets</div></div>
  <div class="card"><div class="card-num green">{live}</div><div class="card-label">Live</div></div>
  <div class="card"><div class="card-num">{above}</div><div class="card-label">≥Conf {min_conf}</div></div>
  <div class="card"><div class="card-num {'orange' if t_cand else ''}">{t_cand}</div><div class="card-label">Takeover Candidates</div></div>
  <div class="card"><div class="card-num {'red' if t_conf else ''}">{t_conf}</div><div class="card-label">Confirmed Takeovers</div></div>
</div>

<div class="stats-row">
  <div class="stats-block"><h4>CDN Distribution</h4>{cdn_stats or '<div style="color:#484f58;font-size:12px">No CDN data</div>'}</div>
  <div class="stats-block"><h4>ASN Distribution</h4>{asn_stats or '<div style="color:#484f58;font-size:12px">No ASN data</div>'}</div>
</div>

{'<div class="takeover-alert"><h3>⚠ Subdomain Takeover Candidates</h3><p style="font-size:12px;color:#8b949e">The following assets have CNAMEs pointing to services vulnerable to subdomain takeover. Rows are highlighted in the main table below.</p></div>' if t_cand or t_conf else ''}

<div class="controls">
  <input type="text" id="search" placeholder="Filter assets..." oninput="filterTable()">
  <select id="confFilter" onchange="filterTable()">
    <option value="">All confidence</option>
    <option value="85">≥85 (High)</option>
    <option value="50">≥50 (Medium+)</option>
    <option value="25">≥25</option>
  </select>
  <select id="takeoverFilter" onchange="filterTable()">
    <option value="">All assets</option>
    <option value="takeover">Takeover candidates only</option>
  </select>
  <label id="count-label" style="margin-left:auto"></label>
</div>

<div class="table-wrap">
<table id="assetTable">
<thead><tr>
  <th onclick="sortTable(0)">Host</th>
  <th onclick="sortTable(1)">IP</th>
  <th onclick="sortTable(2)">ASN</th>
  <th onclick="sortTable(3)">CIDR</th>
  <th onclick="sortTable(4)">CDN</th>
  <th onclick="sortTable(5)">Conf</th>
  <th>CNAME / Service</th>
  <th>Title</th>
  <th onclick="sortTable(8)">Status</th>
  <th>Vulns</th>
  <th>Geo</th>
  <th onclick="sortTable(11)">First Seen</th>
</tr></thead>
<tbody id="tableBody">
{tbody}
</tbody>
</table>
</div>

<footer>Argus — generated {scan_date} &nbsp;|&nbsp; {total} assets in recon.db</footer>
<div id="argus-tip"></div>

<script>
var sortDir = {{}};
function sortTable(col) {{
  var tb = document.getElementById('tableBody');
  var rows = Array.from(tb.querySelectorAll('tr'));
  var dir = sortDir[col] = !(sortDir[col]);
  rows.sort(function(a,b){{
    var av = a.cells[col] ? a.cells[col].innerText.trim() : '';
    var bv = b.cells[col] ? b.cells[col].innerText.trim() : '';
    var an = parseFloat(av), bn = parseFloat(bv);
    if(!isNaN(an) && !isNaN(bn)) return dir ? an-bn : bn-an;
    return dir ? av.localeCompare(bv) : bv.localeCompare(av);
  }});
  rows.forEach(function(r){{ tb.appendChild(r); }});
  document.querySelectorAll('thead th').forEach(function(th,i){{
    th.classList.remove('sort-asc','sort-desc');
    if(i===col) th.classList.add(dir?'sort-asc':'sort-desc');
  }});
  updateCount();
}}
function filterTable() {{
  var q = document.getElementById('search').value.toLowerCase();
  var minConf = parseInt(document.getElementById('confFilter').value) || 0;
  var takeoverOnly = document.getElementById('takeoverFilter').value === 'takeover';
  var rows = document.querySelectorAll('#tableBody tr');
  rows.forEach(function(r) {{
    var text = r.innerText.toLowerCase();
    var conf = parseInt(r.cells[5] ? r.cells[5].innerText : '0') || 0;
    var isTakeover = r.classList.contains('row-takeover') || r.classList.contains('row-takeover-confirmed');
    var show = text.includes(q) && conf >= minConf && (!takeoverOnly || isTakeover);
    r.classList.toggle('hidden', !show);
  }});
  updateCount();
}}
function updateCount() {{
  var visible = document.querySelectorAll('#tableBody tr:not(.hidden)').length;
  document.getElementById('count-label').textContent = visible + ' assets';
}}
updateCount();

// Tooltip system — position on mousemove so layout is already computed
var tip = document.getElementById('argus-tip');
document.addEventListener('mousemove', function(e) {{
  if (tip.style.display !== 'none') {{
    var x = e.clientX + 16, y = e.clientY + 16;
    var tw = tip.offsetWidth, th = tip.offsetHeight;
    if (x + tw + 10 > window.innerWidth)  x = e.clientX - tw - 16;
    if (y + th + 10 > window.innerHeight) y = e.clientY - th - 16;
    tip.style.left = Math.max(0, x) + 'px';
    tip.style.top  = Math.max(0, y) + 'px';
  }}
}});
document.querySelectorAll('.has-tip').forEach(function(el) {{
  el.addEventListener('mouseenter', function() {{
    tip.textContent = el.getAttribute('data-tip');
    tip.style.display = 'block';
  }});
  el.addEventListener('mouseleave', function() {{
    tip.style.display = 'none';
  }});
}});
</script>
</body>
</html>"""

        # Inject email security section if audit data exists
        email_section = ""
        email_audit_path = os.path.join(outdir, "email_audit.json")
        if os.path.exists(email_audit_path):
            try:
                with open(email_audit_path, "r", encoding="utf-8") as ef:
                    email_data = json.load(ef)
                risk_colors = {"CRITICAL": "#f85149", "HIGH": "#f85149", "MEDIUM": "#d29922", "LOW": "#3fb950", "PASS": "#3fb950"}
                email_section = '<div style="padding:16px 32px;border-bottom:1px solid #21262d"><h3 style="color:#c9d1d9;font-size:14px;margin-bottom:12px">Email Security Posture</h3>'
                for domain, r in email_data.items():
                    risk = r.get("spoofing_risk", "UNKNOWN")
                    rc   = risk_colors.get(risk, "#8b949e")
                    spf_ok    = r.get("spf",    {}).get("present") and not r.get("spf",  {}).get("issues")
                    dmarc_ok  = r.get("dmarc",  {}).get("present") and not r.get("dmarc",{}).get("issues")
                    dkim_ok   = any(not d.get("revoked") for d in r.get("dkim", []))
                    mta_ok    = r.get("mta_sts",{}).get("present")
                    provider  = r.get("provider") or ""

                    def _check(ok, label):
                        icon = "✓" if ok else "✗"
                        col  = "#3fb950" if ok else "#f85149"
                        return f'<span style="color:{col};margin-right:12px;font-size:12px">{icon} {label}</span>'

                    issues = []
                    for src in ("spf","dmarc","mta_sts"):
                        issues += r.get(src,{}).get("issues",[])
                    for d in r.get("dkim",[]):
                        issues += d.get("issues",[])

                    email_section += f"""
<div style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;margin-bottom:10px">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
    <span style="font-weight:600;color:#c9d1d9">{he(domain)}</span>
    <span style="background:{rc}22;color:{rc};border:1px solid {rc}44;border-radius:10px;padding:1px 10px;font-size:11px;font-weight:700">{risk}</span>
    {'<span style="font-size:11px;color:#8b949e">' + he(provider) + '</span>' if provider else ''}
  </div>
  <div style="margin-bottom:6px">
    {_check(spf_ok,'SPF')}{_check(dmarc_ok,'DMARC')}{_check(dkim_ok,'DKIM')}{_check(mta_ok,'MTA-STS')}
  </div>
  {'<ul style="margin:0;padding-left:16px">' + ''.join(f"<li style='color:#d29922;font-size:11px'>{he(i)}</li>" for i in issues[:5]) + '</ul>' if issues else ''}
</div>"""
                email_section += "</div>"
            except Exception:
                pass

        if email_section:
            html = html.replace('<div class="table-wrap">', email_section + '<div class="table-wrap">')

        report_path = os.path.join(outdir, "report.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)
        print_status(f"HTML report generated: {report_path}", Colors.GREEN, "[+]")

    def perform_reverse_dns(self, ips, resolvers):
        """Perform reverse DNS lookup on a list of IPs."""
        if not ips:
            return {}
        reverse_map = {}
        print_status(f"Performing reverse DNS on {len(ips)} IPs...", Colors.CYAN)
        
        # Use dnsx for reverse DNS
        ip_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        try:
            ip_file.write('\n'.join(ips))
            ip_file.close()
            
            reverse_out = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
            reverse_out.close()
            
            cmd = ["dnsx", "-ptr", "-l", ip_file.name, "-json", "-o", reverse_out.name, "-silent"]
            if resolvers:
                cmd.extend(["-r", resolvers])
            res = run_command(cmd, "Reverse DNS", verbose=False)
            
            if res.get("returncode") == 0 and os.path.exists(reverse_out.name):
                with open(reverse_out.name, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            ip = data.get("host")
                            ptr = data.get("ptr", [])
                            if ip and ptr:
                                reverse_map[ip] = ptr[0] if isinstance(ptr, list) else ptr
                        except json.JSONDecodeError:
                            pass
        finally:
            os.unlink(ip_file.name)
            if os.path.exists(reverse_out.name):
                os.unlink(reverse_out.name)
        
        print_status(f"Reverse DNS completed: {len(reverse_map)} PTR records found", Colors.GREEN, "[+]")
        return reverse_map

    def geolocate_ips(self, ips, geo_db_path=None):
        """Geolocate IPs using MaxMind GeoLite2 database."""
        if not ips:
            return {}
        
        # Try to import at runtime in case it was just installed
        try:
            import geoip2.database
            import geoip2.errors
        except ImportError:
            print_status("geoip2 not available. Install with: pip install geoip2", Colors.YELLOW, "[!]")
            return {}
        
        if not geo_db_path:
            # Try common locations for GeoLite2-City.mmdb
            common_paths = [
                "/usr/share/GeoIP/GeoLite2-City.mmdb",
                "/var/lib/GeoIP/GeoLite2-City.mmdb",
                "./GeoLite2-City.mmdb",
                os.path.expanduser("~/GeoLite2-City.mmdb")
            ]
            geo_db_path = None
            for path in common_paths:
                if os.path.exists(path):
                    geo_db_path = path
                    print_status(f"Found GeoLite2 database at: {geo_db_path}", Colors.GREEN, "[+]")
                    break
            
            # If not found, attempt to download
            if not geo_db_path:
                print_status("GeoLite2 database not found. MaxMind requires a free account for download.", Colors.YELLOW, "[!]")
                print_status("Follow these steps to set up geolocation:", Colors.CYAN, "[*]")
                print_status("  1. Visit: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data", Colors.CYAN)
                print_status("  2. Create a free account and generate a license key", Colors.CYAN)
                print_status("  3. Download GeoLite2-City.mmdb (MMDB format)", Colors.CYAN)
                print_status("  4. Place the file in one of these locations:", Colors.CYAN)
                print_status("     - /usr/share/GeoIP/GeoLite2-City.mmdb (recommended)", Colors.CYAN)
                print_status("     - /var/lib/GeoIP/GeoLite2-City.mmdb", Colors.CYAN)
                print_status("     - ./GeoLite2-City.mmdb (current directory)", Colors.CYAN)
                print_status("     - ~/GeoLite2-City.mmdb (home directory)", Colors.CYAN)
                return {}
        
        geo_map = {}
        try:
            with geoip2.database.Reader(geo_db_path) as reader:
                for ip in ips:
                    try:
                        response = reader.city(ip)
                        geo_map[ip] = {
                            "country": response.country.name,
                            "city": response.city.name,
                            "latitude": response.location.latitude,
                            "longitude": response.location.longitude
                        }
                    except geoip2.errors.AddressNotFoundError:
                        geo_map[ip] = {"country": "Unknown", "city": "Unknown"}
        except Exception as e:
            print_status(f"Geolocation error: {e}", Colors.YELLOW, "[!]")
        
        print_status(f"Geolocation completed: {len(geo_map)} IPs located", Colors.GREEN, "[+]")
        return geo_map

    def recalculate_confidence(self, domains, primary_asns, tls_sans, brand_keywords):
        """Recalculate confidence scores based on domain linkages."""
        domains = set(domains)
        primary_asns_norm = set(str(a).lstrip("AS").strip() for a in primary_asns if a)
        tls_sans = set(tls_sans)
        brand_keywords = set(brand_keywords)
        
        with self._connection() as conn:
            cur = conn.execute("SELECT host, asn FROM assets")
            for row in cur:
                host = row["host"]
                asn = row["asn"]
                conf = 40
                
                # Brand keyword match
                if any(bk in host for bk in brand_keywords):
                    conf = 85
                
                # Primary domain
                if host in domains:
                    conf = 100
                
                # Subdomain of primary
                if any(host.endswith('.' + d) for d in domains):
                    conf = max(conf, 85)
                
                # In TLS SAN
                if host in tls_sans:
                    conf = max(conf, 85)
                
                # Same ASN as primary
                if asn:
                    asn_norm = str(asn).lstrip("AS").strip()
                    if asn_norm in primary_asns_norm:
                        conf = max(conf, 70)
                
                conn.execute("UPDATE assets SET confidence = ? WHERE host = ?", (conf, host))
            conn.commit()

def generate_delta_report(delta, outdir, scan_id):
    """Print delta to terminal and write delta_report.md."""
    new = delta["new"]
    removed = delta["removed"]
    changed = delta["changed"]

    if not new and not removed and not changed:
        print_status("Delta: no changes detected since last scan", Colors.GREEN, "[=]")
        return

    sep = "─" * 60
    print(f"\n{Colors.BOLD}{sep}{Colors.END}")
    print(f"{Colors.BOLD}  DELTA REPORT — Scan #{scan_id}{Colors.END}")
    print(f"{Colors.BOLD}{sep}{Colors.END}")

    if new:
        print(f"\n{Colors.GREEN}{Colors.BOLD}  NEW ASSETS ({len(new)}){Colors.END}")
        for a in sorted(new, key=lambda x: x.get("confidence", 0), reverse=True):
            ip = (a.get("ip") or "").split(",")[0].strip()
            ip_str = f"[{ip}]" if ip else ""
            print(f"  {Colors.GREEN}+{Colors.END} {a['host']:<50} conf:{a.get('confidence', 0):<4} {ip_str}")

    if removed:
        print(f"\n{Colors.RED}{Colors.BOLD}  REMOVED ASSETS ({len(removed)}){Colors.END}")
        for a in sorted(removed, key=lambda x: x.get("confidence", 0), reverse=True):
            print(f"  {Colors.RED}-{Colors.END} {a['host']:<50} was conf:{a.get('confidence', 0)}")

    if changed:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}  CHANGED ASSETS ({len(changed)}){Colors.END}")
        for a in sorted(changed, key=lambda x: x.get("confidence", 0), reverse=True):
            for change in a["changes"]:
                print(f"  {Colors.YELLOW}~{Colors.END} {a['host']:<50} {change}")

    print(f"\n{Colors.BOLD}{sep}{Colors.END}\n")

    lines = [
        f"# Delta Report — Scan #{scan_id}",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
    ]
    if new:
        lines += [
            f"## New Assets ({len(new)})", "",
            "| Host | IP | Confidence | ASN |", "|------|-----|------------|-----|",
        ]
        for a in sorted(new, key=lambda x: x.get("confidence", 0), reverse=True):
            ip = (a.get("ip") or "").split(",")[0].strip()
            lines.append(f"| {a['host']} | {ip} | {a.get('confidence', 0)} | {a.get('asn', '')} |")
        lines.append("")
    if removed:
        lines += [
            f"## Removed Assets ({len(removed)})", "",
            "| Host | Last Confidence |", "|------|----------------|",
        ]
        for a in sorted(removed, key=lambda x: x.get("confidence", 0), reverse=True):
            lines.append(f"| {a['host']} | {a.get('confidence', 0)} |")
        lines.append("")
    if changed:
        lines += [
            f"## Changed Assets ({len(changed)})", "",
            "| Host | Changes |", "|------|---------|",
        ]
        for a in sorted(changed, key=lambda x: x.get("confidence", 0), reverse=True):
            lines.append(f"| {a['host']} | {'; '.join(a['changes'])} |")
        lines.append("")

    report_path = os.path.join(outdir, "delta_report.md")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print_status(f"Delta report written: {report_path}", Colors.GREEN, "[+]")
    except OSError as e:
        print_status(f"Failed to write delta report: {e}", Colors.YELLOW, "[!]")


def generate_llm_analysis(db, domains, outdir, args, email_results=None):
    """Write a structured markdown file for LLM-assisted analysis of discovered assets."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    with db._connection() as conn:
        all_assets = [dict(r) for r in conn.execute(
            "SELECT host, ip, asn, cidr, cdn, confidence, discovery_reason, web_title, "
            "status_code, tech_stack, open_ports, vulns, geolocation, tools_run, "
            "first_seen, last_seen, cname "
            "FROM assets ORDER BY confidence DESC, host"
        ).fetchall()]

    if not all_assets:
        print_status("No assets in DB — skipping LLM analysis output", Colors.YELLOW, "[!]")
        return

    total = len(all_assets)
    live = sum(1 for a in all_assets if a.get("is_live", 1))
    high_conf = [a for a in all_assets if (a.get("confidence") or 0) >= 85]
    med_conf  = [a for a in all_assets if 50 <= (a.get("confidence") or 0) < 85]
    low_conf  = [a for a in all_assets if (a.get("confidence") or 0) < 50]

    # ASN breakdown
    asn_counts = {}
    for a in all_assets:
        asn = (a.get("asn") or "Unknown").strip()
        asn_counts[asn] = asn_counts.get(asn, 0) + 1

    # CDN breakdown
    cdn_counts = {}
    for a in all_assets:
        cdn = a.get("cdn") or "None"
        if cdn in ("No", "no", "", None): cdn = "None"
        cdn_counts[cdn] = cdn_counts.get(cdn, 0) + 1

    # Tech stack breakdown
    tech_counts = {}
    for a in all_assets:
        for tech in (a.get("tech_stack") or "").split(", "):
            tech = tech.strip()
            if tech:
                tech_counts[tech] = tech_counts.get(tech, 0) + 1

    # Domain naming patterns
    env_keywords = {"dev", "develop", "development", "staging", "stage", "stg", "uat",
                    "qa", "test", "preprod", "pre-prod", "prod", "production", "demo",
                    "sandbox", "beta", "alpha", "preview", "canary", "lab", "temp"}
    infra_keywords = {"mail", "smtp", "mx", "ns", "dns", "vpn", "proxy", "fw", "firewall",
                      "gw", "gateway", "lb", "cdn", "static", "assets", "media", "img",
                      "api", "rest", "graphql", "ws", "auth", "login", "sso", "idp",
                      "admin", "mgmt", "manage", "portal", "dashboard", "panel", "console"}

    prefix_counts = {}
    env_hosts = []
    infra_hosts = []
    for a in all_assets:
        host = a.get("host", "")
        parts = host.split(".")
        if len(parts) > 2:
            prefix = parts[0].lower()
            prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 1
            if any(kw in prefix for kw in env_keywords):
                env_hosts.append(host)
            if any(kw in prefix for kw in infra_keywords):
                infra_hosts.append(host)

    top_prefixes = sorted(prefix_counts.items(), key=lambda x: x[1], reverse=True)[:20]

    # Geo breakdown
    geo_counts = {}
    for a in all_assets:
        geo = (a.get("geolocation") or "").strip()
        if geo:
            geo_counts[geo] = geo_counts.get(geo, 0) + 1

    # Tools run
    tools_used = set()
    for a in all_assets:
        for t in (a.get("tools_run") or "").split(", "):
            t = t.strip()
            if t: tools_used.add(t)

    # CIDR ranges
    cidrs = set()
    cidr_file = os.path.join(outdir, "cidrs.txt")
    if os.path.exists(cidr_file):
        with open(cidr_file) as f:
            cidrs = {l.strip() for l in f if l.strip()}

    def asset_table(assets, limit=200):
        if not assets:
            return "_None_\n"
        lines = ["| Host | IP | ASN | CDN | Conf | Status | Tech | Ports | Geo |",
                 "|------|-----|-----|-----|------|--------|------|-------|-----|"]
        for a in assets[:limit]:
            host  = (a.get("host") or "")[:40]
            ip    = ((a.get("ip") or "").split(",")[0]).strip()[:15]
            asn   = (a.get("asn") or "")[:12]
            cdn   = (a.get("cdn") or "")[:10]
            conf  = str(a.get("confidence") or "")
            sc    = str(a.get("status_code") or "")
            tech  = ((a.get("tech_stack") or "").split(",")[0]).strip()[:20]
            ports = (a.get("open_ports") or "")[:12]
            geo   = (a.get("geolocation") or "")[:20]
            lines.append(f"| {host} | {ip} | {asn} | {cdn} | {conf} | {sc} | {tech} | {ports} | {geo} |")
        if len(assets) > limit:
            lines.append(f"\n_... and {len(assets) - limit} more (see assets.json for full list)_")
        return "\n".join(lines) + "\n"

    lines = [
        f"# Argus — LLM Intelligence Brief",
        f"**Generated:** {now}  ",
        f"**Target domains:** {', '.join(sorted(domains)) if domains else 'N/A (DB-only run)'}  ",
        f"**Tools run:** {', '.join(sorted(tools_used))}  ",
        f"**Output directory:** {outdir}",
        "",
        "---",
        "",
        "## Instructions for Analysis",
        "",
        "This file contains structured OSINT data from passive and/or active reconnaissance.",
        "Please analyze for:",
        "",
        "1. **Domain naming conventions** — environment structure, service naming patterns, versioning schemes",
        "2. **Infrastructure footprint** — cloud providers, CDNs, ASNs, IP ranges, hosting patterns",
        "3. **Technology stack** — software, frameworks, web servers, languages, hardware indicators",
        "4. **Geographic distribution** — where assets are hosted, unusual locations",
        "5. **Interesting patterns** — admin/management interfaces, dev/staging exposure, legacy services",
        "6. **Potential attack surface** — exposed services, misconfigurations, anomalies worth investigating",
        "",
        "---",
        "",
        "## Scan Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total assets discovered | {total} |",
        f"| High confidence (>=85) | {len(high_conf)} |",
        f"| Medium confidence (50–84) | {len(med_conf)} |",
        f"| Low confidence (<50) | {len(low_conf)} |",
        f"| Unique ASNs | {len(asn_counts)} |",
        f"| Unique CDN providers | {len([k for k in cdn_counts if k != 'None'])} |",
        f"| Unique technologies detected | {len(tech_counts)} |",
        "",
    ]

    lines += [
        "## Network Infrastructure",
        "",
        "### ASN Breakdown",
        "",
        "| ASN | Asset Count |",
        "|-----|-------------|",
    ]
    for asn, cnt in sorted(asn_counts.items(), key=lambda x: x[1], reverse=True):
        lines.append(f"| {asn} | {cnt} |")

    lines += ["", "### CDN / Hosting Providers", "", "| Provider | Asset Count |", "|----------|-------------|"]
    for cdn, cnt in sorted(cdn_counts.items(), key=lambda x: x[1], reverse=True):
        lines.append(f"| {cdn} | {cnt} |")

    if cidrs:
        lines += ["", "### IP Ranges (from asnmap)", ""]
        for cidr in sorted(cidrs):
            lines.append(f"- `{cidr}`")

    lines += [
        "",
        "---",
        "",
        "## Asset Inventory",
        "",
        "### High Confidence Assets (>=85) — Primary Domains, Subdomains, Brand Matches",
        "",
        asset_table(high_conf),
        "",
        "### Medium Confidence Assets (50–84) — ASN Correlated, Reverse DNS",
        "",
        asset_table(med_conf),
        "",
        "### Low Confidence Assets (<50) — Baseline / Potential Wildcard",
        "",
        asset_table(low_conf, limit=50),
    ]

    if tech_counts:
        lines += [
            "",
            "---",
            "",
            "## Technology Observations",
            "",
            "| Technology | Occurrences | Example Host |",
            "|-----------|-------------|--------------|",
        ]
        tech_examples = {}
        for a in all_assets:
            for tech in (a.get("tech_stack") or "").split(", "):
                tech = tech.strip()
                if tech and tech not in tech_examples:
                    tech_examples[tech] = a.get("host", "")
        for tech, cnt in sorted(tech_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"| {tech} | {cnt} | {tech_examples.get(tech, '')} |")

    lines += [
        "",
        "---",
        "",
        "## Domain Naming Patterns",
        "",
        "### Most Common Subdomain Prefixes",
        "",
        "| Prefix | Count |",
        "|--------|-------|",
    ]
    for prefix, cnt in top_prefixes:
        lines.append(f"| {prefix} | {cnt} |")

    if env_hosts:
        lines += ["", "### Environment / SDLC Indicators", ""]
        for h in sorted(set(env_hosts))[:30]:
            lines.append(f"- {h}")

    if infra_hosts:
        lines += ["", "### Infrastructure / Service Indicators", ""]
        for h in sorted(set(infra_hosts))[:30]:
            lines.append(f"- {h}")

    if geo_counts:
        lines += [
            "",
            "---",
            "",
            "## Geographic Distribution",
            "",
            "| Location | Asset Count |",
            "|----------|-------------|",
        ]
        for geo, cnt in sorted(geo_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"| {geo} | {cnt} |")

    # Notable findings
    notable = []
    cloudflare_count = sum(v for k, v in cdn_counts.items() if "cloudflare" in k.lower())
    if cloudflare_count:
        notable.append(f"- **{cloudflare_count} assets behind Cloudflare** — origin IPs likely obfuscated")
    admin_hosts = [a["host"] for a in all_assets if any(kw in (a.get("host") or "") for kw in ("admin", "portal", "dashboard", "panel", "console", "mgmt", "manage"))]
    if admin_hosts:
        notable.append(f"- **{len(admin_hosts)} potential admin/management interfaces** — {', '.join(admin_hosts[:5])}")
    dev_exposed = [a["host"] for a in high_conf if any(kw in (a.get("host") or "") for kw in ("dev", "staging", "stage", "test", "uat", "preprod"))]
    if dev_exposed:
        notable.append(f"- **{len(dev_exposed)} high-confidence dev/staging assets** — {', '.join(dev_exposed[:5])}")
    confirmed_vuln_hosts = [a["host"] for a in all_assets
                            if a.get("vulns") and "takeover-risk" not in (a.get("vulns") or "")]
    takeover_risk_hosts = [a["host"] for a in all_assets
                           if "takeover-risk" in (a.get("vulns") or "")]
    if confirmed_vuln_hosts:
        notable.append(f"- **{len(confirmed_vuln_hosts)} assets with nuclei findings** — review vulns column in DB")
    if takeover_risk_hosts:
        notable.append(f"- **{len(takeover_risk_hosts)} subdomain takeover candidate(s)** — {', '.join(takeover_risk_hosts[:3])}")

    # CNAME service inventory
    cname_assets = [(a["host"], a.get("cname", ""), a.get("tech_stack", ""), a.get("discovery_reason", ""))
                    for a in all_assets if a.get("cname")]
    if cname_assets:
        cloud_storage = [(h, c, r) for h, c, t, r in cname_assets if r and "bucket" in r.lower()]
        other_services = [(h, c, t) for h, c, t, r in cname_assets if not (r and "bucket" in r.lower())]
        lines += ["", "---", "", "## CNAME Service Map", ""]
        if cloud_storage:
            lines += ["### Cloud Storage", "", "| Host | CNAME | Bucket |", "|------|-------|--------|"]
            for host, cname, reason in sorted(cloud_storage):
                bucket = reason.replace("Cloud storage bucket: ", "")
                lines.append(f"| {host} | {cname} | {bucket} |")
            lines.append("")
        if other_services:
            lines += ["### Third-party Services", "", "| Host | CNAME | Service |", "|------|-------|---------|"]
            for host, cname, service in sorted(other_services):
                lines.append(f"| {host} | {cname} | {service or ''} |")
            lines.append("")

    # Takeover candidates
    takeover_assets = [
        a for a in all_assets
        if any("takeover-risk" in (v or "") for v in [(a.get("vulns") or "")])
    ]
    confirmed_takeovers = [
        a for a in all_assets
        if any("subdomain-takeover:" in (v or "") for v in [(a.get("vulns") or "")])
    ]
    if confirmed_takeovers or takeover_assets:
        lines += ["", "---", "", "## Subdomain Takeover", ""]
        if confirmed_takeovers:
            lines += [
                f"### ⚠ Confirmed Takeovers ({len(confirmed_takeovers)})", "",
                "| Host | CNAME | Vuln |", "|------|-------|------|",
            ]
            for a in confirmed_takeovers:
                lines.append(f"| {a['host']} | {a.get('cname','')} | {a.get('vulns','')} |")
            lines.append("")
        if takeover_assets:
            lines += [
                f"### Candidates for Manual Verification ({len(takeover_assets)})", "",
                "The following subdomains have CNAMEs pointing to services known to be vulnerable",
                "to subdomain takeover. Verify whether the external account/page is still claimed.", "",
                "| Host | CNAME | Service | Signal |", "|------|-------|---------|--------|",
            ]
            for a in takeover_assets:
                vuln = a.get("vulns") or ""
                nxdomain = "(nxdomain)" in vuln
                signal = "NXDOMAIN — unclaimed" if nxdomain else "Resolves — verify manually"
                lines.append(f"| {a['host']} | {a.get('cname','')} | {a.get('tech_stack','')} | {signal} |")
            lines.append("")

    # Email security posture
    if email_results:
        lines += ["", "---", "", "## Email Security Posture", ""]
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "PASS": 4}
        for domain, r in sorted(email_results.items(), key=lambda x: risk_order.get(x[1].get("spoofing_risk", "PASS"), 4)):
            risk = r.get("spoofing_risk", "UNKNOWN")
            provider = r.get("provider") or "Unknown"
            lines += [f"### {domain} — Spoofing Risk: **{risk}**", ""]
            lines.append(f"**Mail Provider:** {provider}")
            if r.get("mx"):
                lines.append(f"**MX Records:** {', '.join(ex for _, ex in r['mx'][:3])}")
            lines.append("")

            spf = r.get("spf", {})
            if not spf.get("present"):
                lines.append("- ❌ **SPF**: Missing")
            elif spf.get("issues"):
                for issue in spf["issues"]:
                    lines.append(f"- ⚠ **SPF**: {issue}")
            else:
                lines.append(f"- ✓ **SPF**: `{spf.get('record','')[:80]}`")

            dmarc = r.get("dmarc", {})
            if not dmarc.get("present"):
                lines.append("- ❌ **DMARC**: Missing")
            elif dmarc.get("issues"):
                for issue in dmarc["issues"]:
                    lines.append(f"- ⚠ **DMARC**: {issue}")
            else:
                lines.append(f"- ✓ **DMARC**: p={dmarc.get('policy')} pct={dmarc.get('pct',100)}")

            dkim = r.get("dkim", [])
            valid_dkim = [d for d in dkim if not d.get("revoked")]
            if not dkim:
                lines.append("- ⚠ **DKIM**: No selectors found under common names")
            else:
                for d in dkim:
                    if d.get("issues"):
                        lines.append(f"- ⚠ **DKIM [{d['selector']}]**: {d['issues'][0]}")
                if valid_dkim:
                    lines.append(f"- ✓ **DKIM**: {len(valid_dkim)} valid selector(s): {', '.join(d['selector'] for d in valid_dkim)}")

            mta = r.get("mta_sts", {})
            if not mta.get("present"):
                lines.append("- ⚠ **MTA-STS**: Not configured")
            else:
                lines.append("- ✓ **MTA-STS**: Configured")

            if r.get("bimi_present"):
                lines.append("- ✓ **BIMI**: Present")
            if r.get("tlsrpt_present"):
                lines.append("- ✓ **TLS-RPT**: Present")
            lines.append("")

    if notable:
        lines += ["", "---", "", "## Notable Findings for Follow-up", ""]
        lines += notable

    lines += ["", "---", "", f"_Generated by Argus — raw data in recon.db, assets.json, assets.csv_", ""]

    out_path = os.path.join(outdir, "llm_analysis.md")
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print_status(f"LLM analysis file written: {out_path}", Colors.GREEN, "[+]")
    except OSError as e:
        print_status(f"Failed to write LLM analysis file: {e}", Colors.YELLOW, "[!]")


def main():
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print(r"    _    ____  ____  _   _ ____")
    print(r"   / \  |  _ \/ ___|| | | / ___|")
    print(r"  / _ \ | |_) | |  _| | | \___ \ ")
    print(r" / ___ \|  _ <| |_| | |_| |___) |")
    print(r"/_/   \_\_| \_\\____|\___/|____/")
    print(f"{Colors.END}{Colors.BOLD}  Adaptive Reconnaissance, Gathering, and Understanding Suite{Colors.END}")
    print()

    parser = argparse.ArgumentParser(
        description=f"{Colors.BOLD}ARGUS — Adaptive Reconnaissance, Gathering, and Understanding Suite{Colors.END}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Confidence Scoring Summary:

- 100: Primary domains or web pages with brand keywords in title
- 85: Subdomains of primary domains, domains containing brand keywords, or domains in TLS SAN certificates  
- 70: Domains sharing ASN with primary domains
- 50: Domains discovered via reverse DNS
- 40: Default baseline

New Features:
- --reverse-dns: Perform reverse DNS enumeration on discovered IPs
- --geolocate: Add IP geolocation data (requires geoip2 and MaxMind GeoLite2 DB - downloads automatically if not found)
- --export-csv/--export-json: Export database to CSV/JSON
- --preset: Use built-in presets (passive/active/full)
- --resume: Resume from existing database
- --proxy/--user-agent/--rate-limit/--stealth: OPSEC enhancements

Geolocation Setup:
1. Install geoip2: pip install geoip2
2. Download free GeoLite2-City.mmdb from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
3. Place in: /usr/share/GeoIP/GeoLite2-City.mmdb or ./GeoLite2-City.mmdb
   (Tool will attempt auto-download on first use if not found)
"""
    )
    
    # Configuration
    parser.add_argument("--config", help="Load configuration from YAML or JSON file (command line args override config values)")
    
    # General options
    parser.add_argument("-d", "--domain", nargs='*', help="Target domains (space-separated)")
    parser.add_argument("-f", "--domain-file", help="File containing list of target domains (one per line)")
    parser.add_argument("-o", "--outdir", default="recon_results", help="Directory to store results")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--target-conf", type=int, default=None, help="Confidence level to use when doing additional scanning")
    parser.add_argument("--merge-dirs", nargs="+", help="Directories containing recon.db files to merge into the output DB")
    parser.add_argument("--merge-recursive", nargs="+", help="Directories to recursively scan for recon.db files and merge them into the output DB")
    parser.add_argument("--merge-only", action="store_true", help="Merge specified recon.db files and exit without scanning")
    parser.add_argument("--webhook", action="append", help="Webhook URL to post final scan summary to. Can be specified multiple times.")
    parser.add_argument("--webhook-include-assets", action="store_true", help="Include a limited set of asset rows in webhook payloads")
    parser.add_argument("--webhook-max-assets", type=int, default=50, help="Maximum number of assets to include in webhook payloads")
    parser.add_argument("--ports", default="80,443", help="Ports to use for scanning")
    parser.add_argument("--query", action="store_true", help="Requery the database")
    parser.add_argument("--min-conf", type=int, default=0, help="Minimum confidence level to store in database")
    parser.add_argument("--workers", type=int, default=8, help="Parallel workers for subfinder")
    parser.add_argument("--html-report", action="store_true", help="Generate an HTML report of the asset ledger")
    parser.add_argument("--export-csv", action="store_true", help="Export database to CSV file")
    parser.add_argument("--export-json", action="store_true", help="Export database to JSON file")
    parser.add_argument("--llm-analysis", action="store_true", help="Generate a structured markdown file for LLM-assisted analysis of discovered assets")
    parser.add_argument("--diff", action="store_true", help="Show delta report comparing this scan against the previous run")
    parser.add_argument("--preset", choices=['passive', 'active', 'full'], help="Use a built-in preset configuration")
    parser.add_argument("--resume", action="store_true", help="Resume from existing database without re-scanning")
    
    # OPSEC and stealth options
    parser.add_argument("--proxy", help="HTTP proxy URL (e.g., http://127.0.0.1:8080) for tools that support it")
    parser.add_argument("--user-agent", help="Custom User-Agent string for HTTP requests")
    parser.add_argument("--rate-limit", type=float, default=0, help="Rate limit in seconds between requests (0 = no limit)")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode: slower scans, random delays, UA rotation")
    
    # New reconnaissance options
    parser.add_argument("--reverse-dns", action="store_true", help="Perform reverse DNS enumeration on discovered IPs")
    parser.add_argument("--geolocate", action="store_true", help="Add IP geolocation data (requires geoip2 and MaxMind GeoLite2 DB - downloads automatically if not found)")
    parser.add_argument("--asnmap", action="store_true", help="Enumerate full CIDR ranges for discovered ASNs using asnmap (requires asnmap)")
    parser.add_argument("--audit-email", action="store_true", help="Audit email security posture: SPF, DMARC, DKIM, MTA-STS (passive DNS only, requires dig)")
    
    # API keys — hidden from --help, settable via config file or env vars
    parser.add_argument("--pdcp-api-key",       default=None, help=argparse.SUPPRESS)
    parser.add_argument("--shodan-api-key",      default=None, help=argparse.SUPPRESS)
    parser.add_argument("--censys-api-token",    default=None, help=argparse.SUPPRESS)
    parser.add_argument("--censys-api-id",       default=None, help=argparse.SUPPRESS)
    parser.add_argument("--censys-api-secret",   default=None, help=argparse.SUPPRESS)
    parser.add_argument("--virustotal-api-key",  default=None, help=argparse.SUPPRESS)

    # OPSEC Warning group for tools that touch targets
    opsec_group = parser.add_argument_group('OPSEC WARNING: Tools that directly interact with target systems')
    opsec_group.add_argument("--httpx", action="store_true", help="Run HTTPX against domains")
    opsec_group.add_argument("--gowitness", action="store_true", help="Run Gowitness for screenshots")
    opsec_group.add_argument("--tech-stack-enum", action="store_true", help="Run Nuclei technology templates")
    opsec_group.add_argument("--nuclei", action="store_true", help="Run full Nuclei scan")
    opsec_group.add_argument("--takeover", action="store_true", help="Confirm subdomain takeover candidates using Nuclei takeover templates (requires nuclei)")
    
    # Parse arguments to check for config file
    args = parser.parse_args()
    
    # Apply preset if specified
    if args.preset:
        apply_preset(args, args.preset)
    
    # Load config file if specified
    if args.config:
        config = load_config_file(args.config)
        # Apply all config values to args. Command line args take precedence:
        # only set a config value when the arg is still at its default (or unset).
        for key, value in config.items():
            key = key.replace('-', '_')  # normalise dashes to underscores
            try:
                current = getattr(args, key, None)
                default = parser.get_default(key)
                # Set from config if the arg was not supplied on the command line
                # (i.e. it's still None or at its argparse default).
                # For keys not known to argparse, current==None and default==None,
                # so we always apply the config value.
                if current is None or current == default:
                    setattr(args, key, value)
            except Exception:
                pass

    # Export API keys from config file to environment so Go tools pick them up.
    # Environment variables always take precedence over config file values.
    _key_exports = {
        "PDCP_API_KEY":        getattr(args, "pdcp_api_key",       None),
        "SHODAN_API_KEY":      getattr(args, "shodan_api_key",      None),
        "CENSYS_API_TOKEN":    getattr(args, "censys_api_token",    None),
        "CENSYS_API_ID":       getattr(args, "censys_api_id",       None),
        "CENSYS_API_SECRET":   getattr(args, "censys_api_secret",   None),
        "VIRUSTOTAL_API_KEY":  getattr(args, "virustotal_api_key",  None),
    }
    for env_var, value in _key_exports.items():
        if value and not os.environ.get(env_var):
            os.environ[env_var] = str(value)

    abs_outdir = os.path.abspath(args.outdir)
    if not os.path.exists(abs_outdir): os.makedirs(abs_outdir)
    recon_db_path = os.path.join(abs_outdir, "recon.db")
    report_db_path = os.path.join(abs_outdir, "report.db")
    db_path = recon_db_path if os.path.exists(recon_db_path) else report_db_path if os.path.exists(report_db_path) else recon_db_path

    merge_sources = []
    if args.merge_dirs:
        merge_sources.extend(find_recon_db_files(args.merge_dirs, recursive=False))
    if args.merge_recursive:
        merge_sources.extend(find_recon_db_files(args.merge_recursive, recursive=True))
    merge_sources = sorted(set(merge_sources))

    if merge_sources:
        db_path = recon_db_path
        print_status(f"Merging {len(merge_sources)} recon.db source(s) into {recon_db_path}", Colors.CYAN)
        merge_recon_databases(recon_db_path, merge_sources, brand_hint=None)
        if args.merge_only or (not args.domain and not args.domain_file and not args.httpx and not args.gowitness and not args.tech_stack_enum and not args.nuclei and not args.query):
            print_status("Merge completed; exiting.", Colors.GREEN, "[+]")
            return

    db = ReconDB(db_path)

    if args.query:
        db.query_summary(args.min_conf)
        return

    check_dependencies(['subfinder', 'dnsx', 'tlsx', 'httpx', 'gowitness', 'nuclei'])
    if args.asnmap:
        check_dependencies(['asnmap'])
    # pre-check helpful environment variables
    check_env_vars(['PDCP_API_KEY'])

    # Warn once if no passive API enrichment keys are configured
    _has_api_keys = any([
        os.environ.get("SHODAN_API_KEY")     or getattr(args, "shodan_api_key",    None),
        os.environ.get("CENSYS_API_TOKEN")   or getattr(args, "censys_api_token",  None),
        os.environ.get("CENSYS_API_ID")      or getattr(args, "censys_api_id",     None),
        os.environ.get("VIRUSTOTAL_API_KEY") or getattr(args, "virustotal_api_key", None),
    ])
    if not _has_api_keys:
        print_status(
            "No Shodan/Censys/VirusTotal API keys detected — "
            "set SHODAN_API_KEY, CENSYS_API_TOKEN (free) or CENSYS_API_ID/CENSYS_API_SECRET (paid), "
            "or VIRUSTOTAL_API_KEY to enable passive API enrichment",
            Colors.YELLOW, "[!]"
        )
    
    # Check if geoip2 is available when geolocation is requested
    if args.geolocate and not HAS_GEOIP:
        print_status("Geolocation requested but geoip2 is not available in the current Python environment", Colors.YELLOW, "[!]")
        print_status("If you used install.sh, activate the correct venv first: source domain_osint_env/bin/activate", Colors.YELLOW, "[!]")
        print_status("Otherwise install it: pip install geoip2", Colors.YELLOW, "[!]")
        args.geolocate = False
    
    domains = []
    if args.domain_file:
        try:
            with open(args.domain_file, 'r') as f:
                domains = [line.strip().lower() for line in f if line.strip()]
        except OSError as e:
            print_status(f"Failed to read domain file {args.domain_file}: {e}", Colors.RED, "[!]")
            return
    if args.domain:
        domains.extend(d.lower() for d in args.domain)
    domains = list(set(domains))  # deduplicate
    
    has_existing_db = os.path.exists(recon_db_path) or os.path.exists(report_db_path)
    scan_only = args.httpx or args.gowitness or args.tech_stack_enum or args.nuclei

    if not domains:
        if not has_existing_db:
            print_status("No domains provided and no existing recon.db found in the output directory. Use -d domain1 domain2 ... or -f domains.txt, or place recon.db into -o", Colors.RED, "[!]")
            return

        if args.target_conf is None and scan_only:
            args.target_conf = 85
            print_status("No domains provided; using existing DB and default target confidence 85 for additional scanning", Colors.GREEN, "[+]")
        elif args.target_conf is None:
            args.target_conf = 0
            print_status("No domains provided; using existing DB in the output directory", Colors.GREEN, "[+]")

    if args.target_conf is None:
        args.target_conf = 0

    brand_keywords = set(d.split('.')[-2] for d in domains if len(d.split('.')) >= 2)

    # Record scan start and snapshot pre-scan DB state for delta reporting
    scan_id, scan_start = db.record_scan_start(domains)
    snapshot_path = os.path.join(abs_outdir, "snapshot_prev.json")
    db.write_snapshot(snapshot_path)

    if domains and not args.resume:
        res_path = os.path.join(abs_outdir, "resolvers.txt")
        if not os.path.exists(res_path):
            # add a simple retry for resolver download
            for attempt in range(2):
                try:
                    urllib.request.urlretrieve("https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt", res_path)
                    break
                except urllib.error.URLError as e:
                    print_status(f"Resolver download failed (attempt {attempt+1}): {e}", Colors.YELLOW, "[!]")
                    time.sleep(1)

        # 1. Tenant Discovery
        tenant_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "tenant_domains", "tenant-domains.sh")
        tenant_out = os.path.join(abs_outdir, "tenants.txt")
        run_command([tenant_script, "-d", domains[0], "-o", tenant_out], "Initial Tenant Search", args.verbose)
        
        seeds = set(domains)
        if os.path.exists(tenant_out):
            try:
                # report how many tenant domains were found
                with open(tenant_out, "r") as tf:
                    lines = [l.strip() for l in tf if l.strip()]
                    for l in lines:
                        t = l.lower()
                        seeds.add(t)
                        # record tenant discovery in DB
                        try:
                            db.update_asset(t, tool_name="tenant", confidence=50)
                        except Exception:
                            pass
                print_status(f"Tenant: {len(lines)} entries added to seeds", Colors.GREEN, "[+]")
            except OSError:
                pass

        # API enrichment — add discovered hosts to seeds before enumeration
        api_hosts = run_api_enrichment(domains, args, args.verbose)
        for h in api_hosts:
            h = h.lower()
            seeds.add(h)
            try:
                db.update_asset(h, tool_name="api-enrichment", confidence=60)
            except Exception:
                pass

        # Detect wildcard DNS for initial seeds before enumeration starts
        wildcard_ips = {}  # domain -> set of IPs that are wildcard responses
        wildcard_checked = set()
        for seed in list(seeds):
            wc_ips = detect_wildcard_dns(seed, res_path if os.path.exists(res_path) else None)
            wildcard_checked.add(seed)
            if wc_ips:
                wildcard_ips[seed] = wc_ips
                print_status(f"Wildcard DNS detected for {seed} — resolves random subdomains to {wc_ips}. Subfinder results will be validated.", Colors.YELLOW, "[!]")

        cname_announced = set()  # (host, cname) pairs already printed this run
        iteration = 1
        processed_seeds = set()

        while True:
            print_status(f"Starting Discovery Iteration {iteration}...", Colors.MAGENTA, "[∞]")
            before_count = db.get_total_count()
            seeds_to_scan = seeds - processed_seeds
            
            if not seeds_to_scan: break
            
            batch_file = os.path.join(abs_outdir, f"batch_{iteration}.txt")
            try:
                with open(batch_file, "w") as f: f.write("\n".join(seeds_to_scan))
            except OSError:
                print_status(f"Failed to write batch file {batch_file}", Colors.YELLOW, "[!]")
                break
            
            tls_raw = os.path.join(abs_outdir, f"tls_{iteration}.txt")
            # limit TLS extraction duration to avoid very long blocking runs
            tls_res = run_command(["tlsx", "-l", batch_file, "-san", "-cn", "-silent", "-o", tls_raw], f"TLS Extraction", args.verbose, timeout=30)
            if tls_res.get("returncode", 0) != 0:
                print_status("tlsx: failed or timed out — continuing to subdomain enumeration", Colors.YELLOW, "[!]")
            else:
                print_status("tlsx: complete", Colors.GREEN, "[+]")

            # mark the seeds as having been scanned by TLS
            for s in seeds_to_scan:
                try:
                    db.update_asset(s, tool_name="tlsx")
                except Exception:
                    pass

            if os.path.exists(tls_raw):
                try:
                    count_tls = 0
                    with open(tls_raw, "r") as f:
                        for line in f:
                            clean = re.sub(r'^(https?://)', '', line.strip()).split(":")[0].lower()
                            if clean:
                                seeds.add(clean)
                                count_tls += 1
                    print_status(f"tlsx: {count_tls} entries added to seeds", Colors.GREEN, "[+]")
                except OSError:
                    pass

            # parallel subfinder with controlled, prefixed streaming (works with -v)
            print_status(f"Launching subfinder for {len(seeds_to_scan)} seed(s) using {args.workers} worker(s)", Colors.CYAN, "[subfinder]")
            print_lock = threading.Lock()

            def _safe_filename(domain):
                safe = re.sub(r'[^A-Za-z0-9_.-]', '_', domain.lower())
                base = os.path.join(abs_outdir, f"subfinder_{safe}.txt")
                return base if not os.path.exists(base) else f"{base}.{int(time.time())}"

            def _worker(domain, timeout=120):  # increased timeout for subfinder
                tf_name = _safe_filename(domain)
                cmd = ["subfinder", "-d", domain, "-all", "-silent", "-r", res_path, "-o", tf_name]
                # streaming mode: capture stdout and print prefixed lines (thread-safe)
                try:
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                except OSError as e:
                    with print_lock:
                        print_status(f"Failed to start subfinder for {domain}: {e}", Colors.YELLOW, "[!]")
                    return domain, None, 1

                start = time.time()
                # ensure file exists for audit while we stream
                try:
                    with open(tf_name, "a", encoding="utf-8") as fout:
                        while True:
                            line = proc.stdout.readline()
                            if line:
                                # write to file and print prefixed line
                                try:
                                    fout.write(line)
                                    fout.flush()
                                except OSError:
                                    pass
                                if args.verbose:
                                    with print_lock:
                                        print(f"[{domain}] {line.rstrip()}")
                            elif proc.poll() is not None:
                                break
                            # timeout handling
                            if timeout and (time.time() - start) > timeout:
                                proc.kill()
                                with print_lock:
                                    print_status(f"subfinder for {domain} timed out after {timeout}s", Colors.YELLOW, "[!]")
                                break
                except Exception as e:
                    proc.kill()
                    with print_lock:
                        print_status(f"Error during subfinder stream for {domain}: {e}", Colors.YELLOW, "[!]")
                    return domain, tf_name, 1

                returncode = proc.wait()
                if returncode != 0:
                    with print_lock:
                        print_status(f"subfinder for {domain} exited with code {returncode}", Colors.YELLOW, "[!]")
                return domain, tf_name, returncode

            workers = max(1, min(args.workers, (os.cpu_count() or 2) * 2))
            # filter out seeds already recorded as run by subfinder to avoid redundant runs
            to_run = [s for s in seeds_to_scan if not db.has_run_tool(s, "subfinder")]
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futures = {ex.submit(_worker, s): s for s in to_run}
                for fut in as_completed(futures):
                    try:
                        domain, tf_name, rc = fut.result()
                        try:
                            db.update_asset(domain, tool_name="subfinder")
                        except Exception:
                            pass

                        if tf_name and os.path.exists(tf_name):
                            try:
                                subfinder_count = 0
                                with open(tf_name, "r", encoding="utf-8") as f:
                                    for l in f:
                                        sub = l.strip().lower()
                                        if sub:
                                            seeds.add(sub)
                                            subfinder_count += 1
                                            try:
                                                conf = 85 if any(bk in sub for bk in brand_keywords) else 60
                                                db.update_asset(sub, tool_name="subfinder", confidence=conf)
                                            except Exception:
                                                pass
                                print_status(f"subfinder [{domain}]: {subfinder_count} entries added to seeds", Colors.GREEN, "[+]")
                            except OSError:
                                pass
                    except Exception as e:
                        print_status(f"subfinder worker error: {e}", Colors.YELLOW, "[!]")
            
            resolve_file = os.path.join(abs_outdir, "to_resolve.txt")
            try:
                with open(resolve_file, "w") as f: f.write("\n".join(seeds))
            except OSError:
                print_status("Failed to write resolve file", Colors.YELLOW, "[!]")

            dns_json = os.path.join(abs_outdir, "dns.json")
            dnsx_res = run_command(["dnsx", "-l", resolve_file, "-json", "-cdn", "-asn", "-r", res_path, "-a", "-o", dns_json, "-silent"], "DNSX Resolution", args.verbose)
            if dnsx_res.get("returncode", 0) != 0:
                print_status("dnsx: failed or returned non-zero", Colors.YELLOW, "[!]")
            else:
                print_status("dnsx: complete", Colors.GREEN, "[+]")

            if os.path.exists(dns_json):
                try:
                    with open(dns_json, 'r') as f:
                        for line in f:
                            try:
                                d = json.loads(line)
                                host = d.get("host")
                                if not host:
                                    continue

                                ip_list = d.get("a") or d.get("ips") or d.get("ip") or []
                                if isinstance(ip_list, str):
                                    ip_list = [ip_list]
                                ip_list = [str(x) for x in ip_list if x]

                                asn_info = d.get("asn") or {}
                                asn_val = asn_info.get("as-number") or asn_info.get("asn") or asn_info.get("as") or ""
                                cidr = asn_info.get("as-prefix") or asn_info.get("prefix") or asn_info.get("as-prefixes") or asn_info.get("cidr") or asn_info.get("network") or asn_info.get("net") or d.get("cidr") or d.get("prefix") or ""
                                if not cidr and ip_list:
                                    try:
                                        ip0 = ip_list[0]
                                        ipobj = ipaddress.ip_address(ip0)
                                        cidr = str(ipaddress.ip_network(f"{ip0}/24", strict=False)) if ipobj.version == 4 else str(ipaddress.ip_network(f"{ip0}/64", strict=False))
                                    except Exception:
                                        cidr = ""

                                cdn_val = "Yes" if d.get("cdn") else "No"
                                if d.get("cdn-name"):
                                    cdn_val = d.get("cdn-name")

                                # CNAME extraction and service classification
                                cname_list = d.get("cname") or []
                                cname_val = cname_list[0].rstrip(".") if cname_list else ""
                                cname_service = None
                                cname_bucket = None
                                cname_takeover_vuln = None
                                if cname_val:
                                    svc_label, is_storage, is_takeover, bucket = _classify_cname(cname_val)
                                    if svc_label:
                                        cname_service = svc_label
                                        if is_storage and bucket:
                                            cname_bucket = bucket
                                            if (host, cname_val) not in cname_announced:
                                                cname_announced.add((host, cname_val))
                                                print_status(
                                                    f"Cloud storage CNAME: {host} → {cname_val} [{svc_label}, bucket: {bucket}]",
                                                    Colors.YELLOW, "[!]"
                                                )
                                        elif is_takeover:
                                            # Check if the CNAME target itself resolves
                                            resolves = _check_resolves(cname_val)
                                            svc_key = svc_label.lower().replace(" ", "-")
                                            if resolves:
                                                cname_takeover_vuln = f"takeover-risk:{svc_key}"
                                            else:
                                                cname_takeover_vuln = f"takeover-risk:{svc_key}(nxdomain)"
                                            if (host, cname_val) not in cname_announced:
                                                cname_announced.add((host, cname_val))
                                                nxdomain_note = " — CNAME target is NXDOMAIN" if not resolves else ""
                                                print_status(
                                                    f"Takeover candidate: {host} → {cname_val} [{svc_label}]{nxdomain_note}",
                                                    Colors.RED, "[!]"
                                                )
                                        else:
                                            if (host, cname_val) not in cname_announced:
                                                cname_announced.add((host, cname_val))
                                                print_status(
                                                    f"Service CNAME: {host} → {cname_val} [{svc_label}]",
                                                    Colors.CYAN, "[*]"
                                                )

                                # Wildcard false-positive check: if all resolved IPs match
                                # a known wildcard IP for the parent domain, mark as low confidence
                                conf = 85 if any(bk in host for bk in brand_keywords) else 40
                                for wc_domain, wc_ips in wildcard_ips.items():
                                    if host.endswith('.' + wc_domain) and ip_list and set(ip_list).issubset(wc_ips):
                                        conf = 25
                                        break

                                asset_kwargs = dict(
                                    tool_name="dnsx",
                                    ip=ip_list,
                                    asn=asn_val,
                                    cidr=cidr,
                                    cdn=cdn_val,
                                    confidence=conf,
                                )
                                if cname_val:
                                    asset_kwargs["cname"] = cname_val
                                if cname_service:
                                    asset_kwargs["tech_stack"] = [cname_service]
                                if cname_bucket:
                                    asset_kwargs["discovery_reason"] = f"Cloud storage bucket: {cname_bucket}"
                                if cname_takeover_vuln:
                                    asset_kwargs["vulns"] = [cname_takeover_vuln]

                                try:
                                    db.update_asset(host, **asset_kwargs)
                                except Exception:
                                    pass
                            except json.JSONDecodeError:
                                continue
                except OSError:
                    pass

            for s in seeds:
                try:
                    db.update_asset(s, tool_name="dnsx")
                except Exception:
                    pass

            processed_seeds.update(seeds_to_scan)
            if db.get_total_count() == before_count and iteration > 1: break
            iteration += 1

    # ASN/CIDR enumeration via asnmap
    if args.asnmap and domains:
        print_status("Running ASN/CIDR enumeration via asnmap...", Colors.CYAN)
        with db._connection() as conn:
            primary_asns_for_map = set()
            for d in domains:
                row = conn.execute("SELECT asn FROM assets WHERE host = ?", (d,)).fetchone()
                if row and row[0]:
                    primary_asns_for_map.add(str(row[0]).lstrip("AS").strip())

        all_cidrs = set()
        for asn in primary_asns_for_map:
            asn_out = os.path.join(abs_outdir, f"asnmap_{asn}.json")
            run_command(["asnmap", "-a", f"AS{asn}", "-json", "-o", asn_out, "-silent"], f"ASNmap AS{asn}", args.verbose)
            if os.path.exists(asn_out):
                try:
                    with open(asn_out, 'r') as f:
                        for line in f:
                            try:
                                entry = json.loads(line)
                                for cidr in (entry.get("as_range") or []):
                                    all_cidrs.add(cidr)
                            except json.JSONDecodeError:
                                continue
                except OSError:
                    pass

        if all_cidrs:
            cidr_file = os.path.join(abs_outdir, "cidrs.txt")
            try:
                with open(cidr_file, "w") as f:
                    f.write("\n".join(sorted(all_cidrs)))
            except OSError:
                pass
            print_status(f"ASNmap found {len(all_cidrs)} CIDR ranges — saved to {cidr_file}", Colors.GREEN, "[+]")

            # Update cidr column on assets whose IPs fall within discovered ranges
            with db._connection() as conn:
                rows = conn.execute("SELECT host, ip FROM assets WHERE ip IS NOT NULL AND ip != ''").fetchall()
                for row in rows:
                    ips = [x.strip() for x in row["ip"].split(",") if x.strip()]
                    for cidr in all_cidrs:
                        try:
                            network = ipaddress.ip_network(cidr, strict=False)
                            for ip in ips:
                                try:
                                    if ipaddress.ip_address(ip) in network:
                                        conn.execute("UPDATE assets SET cidr = ? WHERE host = ?", (cidr, row["host"]))
                                        break
                                except ValueError:
                                    continue
                        except ValueError:
                            continue
                conn.commit()
            print_status("Updated CIDR assignments on existing assets", Colors.GREEN, "[+]")
        else:
            print_status("ASNmap returned no CIDR ranges for discovered ASNs", Colors.YELLOW, "[!]")

    hosts = db.get_hosts_by_confidence(args.target_conf)
    if hosts:
        targets_file = os.path.join(abs_outdir, "targets.txt")
        try:
            with open(targets_file, "w") as f: f.write("\n".join(hosts))
        except OSError:
            print_status("Failed to write targets file", Colors.YELLOW, "[!]")

        if args.httpx:
            print_status("Initiating HTTPX Probing...", Colors.CYAN)
            for h in hosts: db.update_asset(h, tool_name="httpx")
            httpx_out = os.path.join(abs_outdir, "httpx_final.json")
            httpx_cmd = ["httpx", "-l", targets_file, "-p", args.ports, "-json", "-title", "-sc", "-o", httpx_out, "-silent"]
            if args.proxy:
                httpx_cmd.extend(["--proxy", args.proxy])
            if args.user_agent:
                httpx_cmd.extend(["-H", f"User-Agent: {args.user_agent}"])
            if args.rate_limit > 0:
                httpx_cmd.extend(["--rate-limit", str(args.rate_limit)])
            if args.stealth:
                httpx_cmd.extend(["--delay", "1"])  # Add delay for stealth
            run_command(httpx_cmd, "Httpx", args.verbose)
            
            if os.path.exists(httpx_out):
                try:
                    with open(httpx_out, 'r') as f:
                        for line in f:
                            try:
                                d = json.loads(line)
                                db.update_asset(d.get("host"), tool_name="httpx", brand_hint=brand_keywords, web_title=d.get("title"), status_code=d.get("status_code"), tech_stack=d.get("tech", []), open_ports=[d.get("port")])
                            except json.JSONDecodeError:
                                continue
                except OSError:
                    pass

        # --- OPTION A: Tech Fingerprinting Only ---
        if args.tech_stack_enum:
            print_status("Fingerprinting Tech Stacks...", Colors.MAGENTA)
            tech_stack_out = os.path.join(abs_outdir, "tech_stack.json")
            run_command(["nuclei", "-l", targets_file, "-tags", "tech,exposed-panels", "-p", args.ports, "-json", "-o", tech_stack_out, "-silent"], "Nuclei-Tech", args.verbose)
            if os.path.exists(tech_stack_out):
                try:
                    with open(tech_stack_out, 'r') as f:
                        for line in f:
                            try:
                                d = json.loads(line)
                                host = d.get("host", "").split("//")[-1].split(":")[0]
                                template_id = d.get("template-id", "")
                                if host:
                                    db.update_asset(host, tool_name="nuclei-tech", tech_stack=[template_id] if template_id else [])
                            except json.JSONDecodeError:
                                continue
                except OSError:
                    pass

        # --- OPTION B: Full Vulnerability Scan ---
        if args.nuclei:
            print_status("Initiating Full Nuclei Scan...", Colors.RED)
            nuclei_out = os.path.join(abs_outdir, "nuclei_full.json")
            run_command(["nuclei", "-l", targets_file, "-p", args.ports, "-json", "-o", nuclei_out, "-silent"], "Nuclei-Full", args.verbose)
            if os.path.exists(nuclei_out):
                try:
                    with open(nuclei_out, 'r') as f:
                        for line in f:
                            try:
                                d = json.loads(line)
                                host = d.get("host", "").split("//")[-1].split(":")[0]
                                vuln_info = f"{d.get('template-id')}({d.get('info', {}).get('severity')})"
                                db.update_asset(host, tool_name="nuclei", vulns=[vuln_info])
                            except json.JSONDecodeError:
                                continue
                except OSError:
                    pass

        # --- OPTION C: Takeover Confirmation ---
        if args.takeover:
            with db._connection() as conn:
                takeover_rows = conn.execute(
                    "SELECT host FROM assets WHERE vulns LIKE '%takeover-risk%'"
                ).fetchall()
            takeover_hosts = [r["host"] for r in takeover_rows]
            if takeover_hosts:
                print_status(f"Checking {len(takeover_hosts)} takeover candidate(s) with Nuclei...", Colors.RED)
                takeover_targets_file = os.path.join(abs_outdir, "takeover_candidates.txt")
                try:
                    with open(takeover_targets_file, "w") as f:
                        f.write("\n".join(takeover_hosts))
                except OSError:
                    pass
                takeover_out = os.path.join(abs_outdir, "takeover_results.json")
                run_command(
                    ["nuclei", "-l", takeover_targets_file, "-tags", "takeover",
                     "-json", "-o", takeover_out, "-silent"],
                    "Nuclei-Takeover", args.verbose
                )
                confirmed = 0
                if os.path.exists(takeover_out):
                    try:
                        with open(takeover_out, 'r') as f:
                            for line in f:
                                try:
                                    d = json.loads(line)
                                    host = d.get("host", "").split("//")[-1].split(":")[0]
                                    template_id = d.get("template-id", "")
                                    severity = d.get("info", {}).get("severity", "unknown")
                                    vuln_info = f"subdomain-takeover:{template_id}({severity})"
                                    db.update_asset(host, tool_name="nuclei-takeover", vulns=[vuln_info])
                                    print_status(f"CONFIRMED TAKEOVER: {host} [{template_id}] ({severity})", Colors.RED, "[!!]")
                                    confirmed += 1
                                except json.JSONDecodeError:
                                    continue
                    except OSError:
                        pass
                if confirmed == 0:
                    print_status("Nuclei-Takeover: no confirmed takeovers found", Colors.GREEN, "[+]")
                else:
                    print_status(f"Nuclei-Takeover: {confirmed} confirmed takeover(s)", Colors.RED, "[!!]")
            else:
                print_status("No takeover candidates in DB — run a discovery scan first", Colors.YELLOW, "[!]")

        if args.gowitness:
            print_status("Initiating Gowitness Scan...", Colors.CYAN)
            screenshot_dir = os.path.join(abs_outdir, "screenshots")
            os.makedirs(screenshot_dir, exist_ok=True)
            gowitness_out = os.path.join(abs_outdir, "gowitness.jsonl")
            gowitness_db = os.path.join(abs_outdir, "gowitness.db")
            gowitness_cmd = [
                "gowitness", "scan", "file",
                "-f", targets_file,
                "--screenshot-path", screenshot_dir,
                "--threads", str(max(2, min(args.workers, 20))),
                "--write-db",
                "--write-db-uri", f"sqlite://{gowitness_db}",
                "--write-jsonl",
                "--write-jsonl-file", gowitness_out,
                "--quiet"
            ]
            if args.proxy:
                gowitness_cmd.extend(["--proxy", args.proxy])
            if args.user_agent:
                gowitness_cmd.extend(["--user-agent", args.user_agent])
            if args.stealth:
                gowitness_cmd.extend(["--delay", "2000"])  # 2 second delay for stealth
            run_command(gowitness_cmd, "Gowitness", args.verbose)
            # parse gowitness JSONL output to associate screenshots with specific domains
            if os.path.exists(gowitness_out):
                try:
                    with open(gowitness_out, 'r', encoding='utf-8') as f:
                        for line in f:
                            try:
                                d = json.loads(line)
                                url = d.get("url") or d.get("target") or ""
                                host = url.split("//")[-1].split("/")[0].split(":")[0] if url else ""
                                screenshot_path = d.get("screenshot-path") or d.get("screenshot_path")
                                if host and screenshot_path:
                                    db.update_asset(host, tool_name="gowitness", screenshot_path=screenshot_path)
                                elif host:
                                    db.update_asset(host, tool_name="gowitness")
                            except json.JSONDecodeError:
                                continue
                except OSError:
                    pass
            else:
                # fallback: mark tool run even if JSON parsing fails
                for h in hosts:
                    db.update_asset(h, tool_name="gowitness")

    # Recalculate confidence based on linkages
    if domains:
        primary_asns = set()
        tls_sans = set()
        
        # Collect primary ASNs
        with db._connection() as conn:
            for d in domains:
                row = conn.execute("SELECT asn FROM assets WHERE host = ?", (d,)).fetchone()
                if row and row[0]:
                    primary_asns.add(row[0])
        
        # Collect TLS SANs
        tls_files = glob.glob(os.path.join(abs_outdir, "tls_*.txt"))
        for tls_file in tls_files:
            try:
                with open(tls_file, 'r') as f:
                    for line in f:
                        clean = re.sub(r'^(https?://)', '', line.strip()).split(":")[0].lower()
                        if clean:
                            tls_sans.add(clean)
            except OSError:
                pass
        
        db.recalculate_confidence(domains, primary_asns, tls_sans, brand_keywords)

    # Perform reverse DNS if requested
    if args.reverse_dns:
        # Get all IPs from DB
        with db._connection() as conn:
            cur = conn.execute("SELECT DISTINCT ip FROM assets WHERE ip IS NOT NULL AND ip != ''")
            all_ips = []
            for row in cur:
                ips = row[0].split(", ")
                all_ips.extend(ips)
            all_ips = list(set(all_ips))
        
        resolvers = os.path.join(abs_outdir, "resolvers.txt") if os.path.exists(os.path.join(abs_outdir, "resolvers.txt")) else None
        reverse_map = db.perform_reverse_dns(all_ips, resolvers)
        
        # Update discovery_reason and collect new PTR assets in one pass,
        # then add new assets after the connection is closed to avoid lock conflicts
        new_ptr_assets = []
        with db._connection() as conn:
            for ip, ptr in reverse_map.items():
                conn.execute("UPDATE assets SET discovery_reason = ? WHERE ip LIKE ?", (f"Reverse DNS: {ptr}", f"%{ip}%"))
                if not conn.execute("SELECT 1 FROM assets WHERE host = ?", (ptr,)).fetchone():
                    new_ptr_assets.append((ptr, ip))
            conn.commit()
        seed_domains_lower = {d.lower() for d in domains}
        skipped_ptr = 0
        added_ptr_hosts = []
        for ptr, ip in new_ptr_assets:
            skip, conf = _ptr_confidence(ptr, seed_domains_lower)
            if skip:
                skipped_ptr += 1
                continue
            db.update_asset(ptr, tool_name="reverse_dns", ip=ip, confidence=conf)
            added_ptr_hosts.append(ptr)
        if skipped_ptr:
            print_status(f"Reverse DNS: filtered {skipped_ptr} root/infrastructure PTR records", Colors.CYAN, "[*]")

        # Enrich PTR assets with ASN/CDN via a targeted dnsx pass
        if added_ptr_hosts:
            ptr_resolve_file = os.path.join(abs_outdir, "ptr_enrich.txt")
            ptr_dns_json     = os.path.join(abs_outdir, "ptr_dns.json")
            try:
                with open(ptr_resolve_file, "w") as f:
                    f.write("\n".join(added_ptr_hosts))
                res_path_ptr = os.path.join(abs_outdir, "resolvers.txt")
                ptr_cmd = ["dnsx", "-l", ptr_resolve_file, "-json", "-cdn", "-asn", "-a",
                           "-o", ptr_dns_json, "-silent"]
                if os.path.exists(res_path_ptr):
                    ptr_cmd.extend(["-r", res_path_ptr])
                run_command(ptr_cmd, "PTR Enrichment", args.verbose)
                if os.path.exists(ptr_dns_json):
                    with open(ptr_dns_json, "r") as f:
                        for line in f:
                            try:
                                d = json.loads(line)
                                host = d.get("host")
                                if not host:
                                    continue
                                asn_info = d.get("asn") or {}
                                asn_val  = asn_info.get("as-number") or ""
                                cidr     = asn_info.get("as-prefix") or ""
                                if not cidr:
                                    ips = d.get("a") or []
                                    if ips:
                                        try:
                                            ip0 = ips[0]
                                            cidr = str(ipaddress.ip_network(f"{ip0}/24", strict=False))
                                        except Exception:
                                            pass
                                cdn_val = d.get("cdn-name") or ("Yes" if d.get("cdn") else "No")
                                db.update_asset(host, tool_name="dnsx", asn=asn_val, cidr=cidr, cdn=cdn_val)
                            except json.JSONDecodeError:
                                continue
                print_status(f"PTR enrichment: {len(added_ptr_hosts)} hosts enriched with ASN/CDN", Colors.GREEN, "[+]")
            except OSError:
                pass

    # Perform geolocation if requested
    if args.geolocate:
        # Get all IPs
        with db._connection() as conn:
            cur = conn.execute("SELECT DISTINCT ip FROM assets WHERE ip IS NOT NULL AND ip != ''")
            all_ips = []
            for row in cur:
                ips = row[0].split(", ")
                all_ips.extend(ips)
            all_ips = list(set(all_ips))
        
        geo_map = db.geolocate_ips(all_ips)

        with db._connection() as conn:
            for ip, geo in geo_map.items():
                geo_str = f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}"
                conn.execute("UPDATE assets SET geolocation = ? WHERE ip LIKE ?", (geo_str, f"%{ip}%"))
            conn.commit()

    summary = db.get_summary(0)
    db.query_summary(0)

    # Handle exports
    if args.export_csv:
        csv_path = os.path.join(abs_outdir, "assets.csv")
        db.export_csv(csv_path, args.min_conf)
    
    if args.export_json:
        json_path = os.path.join(abs_outdir, "assets.json")
        db.export_json(json_path, args.min_conf)

    if args.html_report:
        db.generate_html_report(0, abs_outdir)

    email_results = {}
    if getattr(args, "audit_email", False) and domains:
        email_results = audit_email_security(domains, db, abs_outdir, args.verbose) or {}

    if args.llm_analysis:
        generate_llm_analysis(db, domains, abs_outdir, args, email_results=email_results)

    db.record_scan_complete(scan_id)

    if args.diff:
        delta = db.compute_delta(snapshot_path, scan_start)
        generate_delta_report(delta, abs_outdir, scan_id)

    if args.webhook:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "outdir": abs_outdir,
            "db_path": os.path.abspath(db.db_path),
            "summary": {
                "total": summary["total"],
                "live": summary["live"],
                "above_target_conf": summary["above"],
                "target_conf": args.target_conf,
            },
            "report_html": os.path.join(abs_outdir, "report.html") if args.html_report else None,
        }
        if args.webhook_include_assets:
            payload["assets"] = [
                {
                    "host": r.get("host"),
                    "ip": r.get("ip"),
                    "asn": r.get("asn"),
                    "cdn": r.get("cdn"),
                    "confidence": r.get("confidence"),
                    "status_code": r.get("status_code"),
                    "open_ports": r.get("open_ports"),
                    "tools_run": r.get("tools_run"),
                }
                for r in summary["rows"][: args.webhook_max_assets]
            ]
        send_webhook_notifications(args.webhook, payload)

if __name__ == "__main__":
    main()