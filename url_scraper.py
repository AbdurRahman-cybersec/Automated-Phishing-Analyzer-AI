#!/usr/bin/env python3
"""
URL Scraper & AI Phishing Analyzer
Downloads a page AND all its assets (JS, CSS, images), extracts phishing-relevant
fields, runs static analysis on JS/CSS for suspicious patterns, saves everything
to a domain folder, and calls OpenRouter or DeepSeek API for AI analysis.
"""

import os
import sys
import json
import re
import ssl
import socket
import hashlib
import sqlite3
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin

try:
    import requests
    from bs4 import BeautifulSoup
    from dotenv import load_dotenv
except ImportError:
    print("Missing dependencies. Install with:")
    print("  pip3 install requests beautifulsoup4 python-dotenv")
    sys.exit(1)

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False
    print("⚠ python-whois not installed — WHOIS lookups disabled")

try:
    from PIL import Image
    import io as _io_module
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False

# Load .env from same directory as this script
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY')
OPENROUTER_MODEL = os.getenv('OPENROUTER_MODEL', 'google/gemini-2.5-flash-lite:free')
DEEPSEEK_API_KEY = os.getenv('DEEPSEEK_API_KEY')
DEEPSEEK_MODEL = os.getenv('DEEPSEEK_MODEL', 'deepseek-chat')
AI_PROVIDER = os.getenv('AI_PROVIDER', 'openrouter')  # 'openrouter' or 'deepseek'

# Top 3 OpenRouter free models (used for fallback if primary fails)
OPENROUTER_FREE_MODELS = [
    'google/gemini-2.5-flash-lite:free',
    'meta-llama/llama-4-maverick:free',
    'deepseek/deepseek-chat-v3-0324:free',
]


def set_api_key(key: str):
    """Override the OpenRouter API key at runtime (called from the GUI)."""
    global OPENROUTER_API_KEY
    OPENROUTER_API_KEY = key.strip() if key and key.strip() else None


def set_openrouter_model(model: str):
    """Override the OpenRouter model at runtime (called from the GUI)."""
    global OPENROUTER_MODEL
    if model and model.strip():
        OPENROUTER_MODEL = model.strip()


def set_deepseek_key(key: str):
    """Override the DeepSeek API key at runtime (called from the GUI)."""
    global DEEPSEEK_API_KEY
    DEEPSEEK_API_KEY = key.strip() if key and key.strip() else None


def set_ai_provider(provider: str):
    """Set the AI provider ('openrouter' or 'deepseek')."""
    global AI_PROVIDER
    if provider and provider.strip().lower() in ('openrouter', 'deepseek'):
        AI_PROVIDER = provider.strip().lower()


def set_virustotal_key(key: str):
    """Override the VirusTotal API key at runtime."""
    global VIRUSTOTAL_API_KEY
    VIRUSTOTAL_API_KEY = key.strip() if key and key.strip() else ''


def set_phishtank_key(key: str):
    """Override the PhishTank API key at runtime."""
    global PHISHTANK_API_KEY
    PHISHTANK_API_KEY = key.strip() if key and key.strip() else ''


SCRAPED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scraped_sites')

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
}

# ── Asset-type specific accept headers ───────────────────────────
JS_HEADERS = {**HEADERS, 'Accept': '*/*'}
CSS_HEADERS = {**HEADERS, 'Accept': 'text/css,*/*;q=0.1'}
IMG_HEADERS = {**HEADERS, 'Accept': 'image/avif,image/webp,image/apng,image/*,*/*;q=0.8'}


# ── Optional API keys ───────────────────────────────────────────
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
PHISHTANK_API_KEY = os.getenv('PHISHTANK_API_KEY', '')  # free tier

# ── Reputation DB (SQLite) ─────────────────────────────────────
REPUTATION_DB = os.path.join(SCRAPED_DIR, 'reputation.db')

# ══════════════════════════════════════════════════════════════════
#  URL NORMALIZATION
# ══════════════════════════════════════════════════════════════════

def normalize_url(url):
    """Ensure URL has a scheme."""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def get_domain(url):
    """Extract clean domain name for folder naming."""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    domain = domain.split(':')[0]
    domain = re.sub(r'[^\w\-.]', '_', domain)
    return domain


def safe_filename(url_path):
    """Turn a URL path into a safe filesystem name."""
    # Remove query string and fragment
    path = url_path.split('?')[0].split('#')[0]
    # Get the filename part
    name = os.path.basename(path) or 'index'
    # If no extension, try to guess
    if '.' not in name:
        name = name + '.dat'
    # Make safe
    name = re.sub(r'[^\w\-.]', '_', name)
    # Truncate long names
    if len(name) > 120:
        base, ext = os.path.splitext(name)
        name = base[:110] + ext
    return name


# ══════════════════════════════════════════════════════════════════
#  PAGE DOWNLOAD
# ══════════════════════════════════════════════════════════════════

def download_page(url):
    """Download a page and return (response, download_errors) tuple.
    Always returns something — even on failure — so AI analysis can proceed."""
    errors = []
    print(f"  ↳ Downloading {url} ...")
    try:
        resp = requests.get(url, headers=HEADERS, timeout=15,
                            allow_redirects=True, verify=True)
        print(f"  ↳ HTTP {resp.status_code} | {len(resp.text):,} characters")
        if resp.status_code == 403:
            errors.append("HTTP 403 Forbidden — site may be blocked by hosting provider")
        elif resp.status_code >= 400:
            errors.append(f"HTTP {resp.status_code} error")
        return resp, errors
    except requests.exceptions.SSLError as e:
        errors.append(f"SSL certificate error: {str(e)[:100]}")
        print("  ↳ SSL error — retrying without verification...")
        try:
            resp = requests.get(url, headers=HEADERS, timeout=15,
                                allow_redirects=True, verify=False)
            print(f"  ↳ HTTP {resp.status_code} | {len(resp.text):,} characters")
            if resp.status_code == 403:
                errors.append("HTTP 403 Forbidden — site blocked/flagged as dangerous")
            return resp, errors
        except requests.exceptions.RequestException as e2:
            errors.append(f"Download failed after SSL bypass: {e2}")
            return None, errors
    except requests.exceptions.ConnectionError as e:
        errors.append(f"Connection refused: {e}")
        print(f"  ✗ Connection failed: {e}")
        return None, errors
    except requests.exceptions.RequestException as e:
        errors.append(f"Download failed: {e}")
        print(f"  ✗ Download failed: {e}")
        return None, errors


# ══════════════════════════════════════════════════════════════════
#  ASSET DOWNLOADING (JS, CSS, IMAGES)
# ══════════════════════════════════════════════════════════════════

def download_asset(asset_url, folder, asset_type='js', timeout=10):
    """Download a single asset and save to folder. Returns (local_path, content, error)."""
    try:
        headers = {'js': JS_HEADERS, 'css': CSS_HEADERS, 'img': IMG_HEADERS}.get(asset_type, HEADERS)
        resp = requests.get(asset_url, headers=headers, timeout=timeout,
                            allow_redirects=True, verify=True)
        resp.raise_for_status()

        filename = safe_filename(asset_url)
        # Avoid overwriting files with same name from different URLs
        local_path = os.path.join(folder, filename)
        counter = 1
        base, ext = os.path.splitext(filename)
        while os.path.exists(local_path):
            local_path = os.path.join(folder, f"{base}_{counter}{ext}")
            counter += 1

        with open(local_path, 'w', encoding='utf-8', errors='replace') as f:
            f.write(resp.text)

        return local_path, resp.text, None
    except Exception as e:
        return None, None, str(e)[:120]


def download_all_assets(soup, base_url, domain_folder):
    """
    Find and download all linked JS, CSS, and image assets.
    Creates subdirectories: js/, css/, img/ inside the domain folder.
    Returns summary dict.
    """
    # Create asset subdirectories
    js_dir = os.path.join(domain_folder, 'js')
    css_dir = os.path.join(domain_folder, 'css')
    img_dir = os.path.join(domain_folder, 'img')
    for d in [js_dir, css_dir, img_dir]:
        os.makedirs(d, exist_ok=True)

    results = {
        'js': {'downloaded': [], 'failed': [], 'total': 0},
        'css': {'downloaded': [], 'failed': [], 'total': 0},
        'img': {'downloaded': [], 'failed': [], 'total': 0},
    }

    # ── JavaScript files ─────────────────────────────────────────
    js_urls = set()
    for script in soup.find_all('script', src=True):
        src = script.get('src', '')
        if src:
            full_url = urljoin(base_url, src)
            js_urls.add(full_url)

    results['js']['total'] = len(js_urls)
    for js_url in js_urls:
        path, content, err = download_asset(js_url, js_dir, 'js')
        if path:
            results['js']['downloaded'].append({'url': js_url, 'path': path, 'size': len(content)})
            print(f"  ↳ JS: {os.path.basename(path)} ({len(content):,} chars)")
        else:
            results['js']['failed'].append({'url': js_url, 'error': err})

    # ── CSS files ────────────────────────────────────────────────
    css_urls = set()
    for link in soup.find_all('link', rel='stylesheet', href=True):
        full_url = urljoin(base_url, link['href'])
        css_urls.add(full_url)
    # Also catch inline @import in <style> tags
    for style in soup.find_all('style'):
        imports = re.findall(r'@import\s+(?:url\()?["\']?([^"\')\s]+)', style.string or '')
        for imp in imports:
            css_urls.add(urljoin(base_url, imp))

    results['css']['total'] = len(css_urls)
    for css_url in css_urls:
        path, content, err = download_asset(css_url, css_dir, 'css')
        if path:
            results['css']['downloaded'].append({'url': css_url, 'path': path, 'size': len(content)})
            print(f"  ↳ CSS: {os.path.basename(path)} ({len(content):,} chars)")
        else:
            results['css']['failed'].append({'url': css_url, 'error': err})

    # ── Images ───────────────────────────────────────────────────
    img_urls = set()
    for img in soup.find_all('img', src=True):
        full_url = urljoin(base_url, img['src'])
        # Only download if it's an actual image URL (skip data: URIs)
        if full_url.startswith('http'):
            img_urls.add(full_url)
    # Limit images to 30 to avoid excessive downloads
    img_urls = set(list(img_urls)[:30])

    results['img']['total'] = len(img_urls)
    for img_url in img_urls:
        path, content, err = download_asset(img_url, img_dir, 'img')
        if path:
            results['img']['downloaded'].append({'url': img_url, 'path': path, 'size': len(content)})
            print(f"  ↳ IMG: {os.path.basename(path)} ({len(content):,} chars)")
        else:
            results['img']['failed'].append({'url': img_url, 'error': err})

    return results


# ══════════════════════════════════════════════════════════════════
#  STATIC ANALYSIS — JAVASCRIPT
# ══════════════════════════════════════════════════════════════════

def _score_js_finding(finding_type, match_text, context_lines=1):
    """Helper to build a JS finding dict."""
    return {
        'type': finding_type,
        'match': match_text[:200],
    }


def analyze_js_content(js_code, filename=''):
    """
    Static analysis of JavaScript for phishing / malicious indicators.
    Returns a dict with findings and a suspicion score.
    """
    findings = []
    score = 0

    if not js_code or len(js_code) < 10:
        return {'findings': [], 'score': 0, 'suspicion_level': 'none'}

    # ── 1. eval() usage — HIGH severity ──────────────────────────
    eval_matches = re.findall(r'\beval\s*\(', js_code)
    if eval_matches:
        findings.append(_score_js_finding(
            'eval_usage',
            f'eval() called {len(eval_matches)} time(s) — dynamic code execution'
        ))
        score += 20 * len(eval_matches)

    # ── 2. document.write() — overwrites page ────────────────────
    dw_matches = re.findall(r'document\.write\s*\(', js_code)
    if dw_matches:
        findings.append(_score_js_finding(
            'document_write',
            f'document.write() called {len(dw_matches)} time(s) — can inject phishing content'
        ))
        score += 15 * len(dw_matches)

    # ── 3. atob() / btoa() — base64 obfuscation ──────────────────
    b64_matches = re.findall(r'\b(?:atob|btoa)\s*\(', js_code)
    if b64_matches:
        findings.append(_score_js_finding(
            'base64_encoding',
            f'atob()/btoa() called {len(b64_matches)} time(s) — possible obfuscation'
        ))
        score += 10 * len(b64_matches)

    # ── 4. window.location redirects ─────────────────────────────
    redirect_matches = re.findall(
        r'(?:window\.location|location\.href|location\.replace|location\.assign)\s*[=\(]',
        js_code
    )
    if redirect_matches:
        findings.append(_score_js_finding(
            'redirect',
            f'URL redirect found {len(redirect_matches)} time(s)'
        ))
        score += 15 * len(redirect_matches)

    # ── 5. document.cookie access — credential theft ─────────────
    cookie_matches = re.findall(r'document\.cookie', js_code)
    if cookie_matches:
        findings.append(_score_js_finding(
            'cookie_access',
            f'document.cookie accessed {len(cookie_matches)} time(s) — possible credential theft'
        ))
        score += 15 * len(cookie_matches)

    # ── 6. innerHTML / outerHTML manipulation ────────────────────
    inner_matches = re.findall(r'\.innerHTML\s*=', js_code)
    if inner_matches:
        findings.append(_score_js_finding(
            'innerHTML_manipulation',
            f'.innerHTML assignment found {len(inner_matches)} time(s) — DOM injection risk'
        ))
        score += 8 * len(inner_matches)

    # ── 7. String.fromCharCode obfuscation ─────────────────────
    charcode_matches = re.findall(r'String\.fromCharCode', js_code)
    if charcode_matches:
        findings.append(_score_js_finding(
            'fromCharCode',
            f'String.fromCharCode found {len(charcode_matches)} time(s) — obfuscation technique'
        ))
        score += 12

    # ── 8. Obfuscation heuristics ────────────────────────────────
    # Long hex strings
    hex_matches = re.findall(r'["\'](?:\\x[0-9a-fA-F]{2}){5,}["\']', js_code)
    if hex_matches:
        findings.append(_score_js_finding(
            'hex_obfuscation',
            f'Long hex-encoded string(s) found — obfuscation indicator'
        ))
        score += 20

    # Very long variable/function names (often packed/obfuscated)
    long_names = re.findall(r'\b(?:var|let|const|function)\s+([a-zA-Z_$][\w$]{30,})', js_code)
    if long_names:
        findings.append(_score_js_finding(
            'suspicious_names',
            f'{len(long_names)} unusually long identifier(s) — possible obfuscation'
        ))
        score += 5

    # Unescape/escape usage
    unescape_matches = re.findall(r'\b(?:unescape|escape)\s*\(', js_code)
    if unescape_matches:
        findings.append(_score_js_finding(
            'escape_usage',
            f'escape()/unescape() found {len(unescape_matches)} time(s)'
        ))
        score += 8

    # ── 9. iframe creation ─────────────────────────────────────
    iframe_matches = re.findall(r'createElement\s*\(\s*["\']iframe["\']', js_code, re.I)
    if iframe_matches:
        findings.append(_score_js_finding(
            'iframe_creation',
            f'dynamic iframe creation found {len(iframe_matches)} time(s)'
        ))
        score += 10

    # ── 10. fetch/XHR to external URLs ──────────────────────────
    external_fetch = re.findall(r'fetch\s*\(\s*["\']https?://', js_code)
    external_xhr = re.findall(r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE)', js_code)
    if external_fetch or external_xhr:
        total = len(external_fetch) + len(external_xhr)
        findings.append(_score_js_finding(
            'external_requests',
            f'{total} external network request(s) — data exfiltration risk'
        ))
        score += 8 * total

    # ── 11. Password/credential related strings ──────────────────
    cred_patterns = re.findall(
        r'(?:password|passwd|pwd|creditcard|ssn|social.security)\s*[:=]',
        js_code, re.I
    )
    if cred_patterns:
        findings.append(_score_js_finding(
            'credential_strings',
            f'{len(cred_patterns)} credential-related string(s) found'
        ))
        score += 12 * len(cred_patterns)

    # Determine suspicion level
    if score >= 40:
        level = 'high'
    elif score >= 15:
        level = 'medium'
    elif score >= 5:
        level = 'low'
    else:
        level = 'none'

    return {
        'filename': filename,
        'findings': findings,
        'score': score,
        'suspicion_level': level,
        'size': len(js_code),
    }


# ══════════════════════════════════════════════════════════════════
#  STATIC ANALYSIS — CSS
# ══════════════════════════════════════════════════════════════════

def analyze_css_content(css_code, filename=''):
    """
    Static analysis of CSS for phishing indicators
    (hidden elements, brand impersonation, overlay tricks).
    """
    findings = []
    score = 0

    if not css_code or len(css_code) < 10:
        return {'findings': [], 'score': 0, 'suspicion_level': 'none'}

    # ── 1. display:none — hiding legitimate content ──────────────
    display_none = re.findall(r'display\s*:\s*none\b', css_code, re.I)
    if display_none:
        findings.append(_score_js_finding(
            'hidden_elements',
            f'display:none found {len(display_none)} time(s) — may hide real content'
        ))
        score += 3 * len(display_none)

    # ── 2. visibility:hidden ─────────────────────────────────────
    vis_hidden = re.findall(r'visibility\s*:\s*hidden', css_code, re.I)
    if vis_hidden:
        findings.append(_score_js_finding(
            'visibility_hidden',
            f'visibility:hidden found {len(vis_hidden)} time(s)'
        ))
        score += 2 * len(vis_hidden)

    # ── 3. opacity:0 — invisible but present ─────────────────────
    opacity_zero = re.findall(r'opacity\s*:\s*0\b', css_code, re.I)
    if opacity_zero:
        findings.append(_score_js_finding(
            'opacity_zero',
            f'opacity:0 found {len(opacity_zero)} time(s) — invisible overlay risk'
        ))
        score += 5 * len(opacity_zero)

    # ── 4. Negative/off-screen positioning ──────────────────────
    offscreen_count = 0
    for pattern in [r'position\s*:\s*absolute', r'position\s*:\s*fixed']:
        matches = re.findall(pattern, css_code, re.I)
        for _ in matches:
            nearby = css_code[max(0, css_code.find(_, 0)-50):css_code.find(_, 0)+200]
            if re.search(r'(?:left|top|right|bottom)\s*:\s*-?\d{3,}px', nearby):
                offscreen_count += 1
    if offscreen_count:
        findings.append(_score_js_finding(
            'offscreen_positioning',
            f'{offscreen_count} element(s) positioned off-screen — may hide phishing forms'
        ))
        score += 10 * offscreen_count

    # ── 5. Brand impersonation in selectors ──────────────────────
    brand_names = [
        'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook',
        'instagram', 'twitter', 'linkedin', 'netflix', 'dropbox', 'adobe',
        'bank', 'chase', 'wells.?fargo', 'citi', 'amex', 'visa', 'mastercard',
        'outlook', 'office365', 'gmail', 'yahoo', 'steam', 'discord', 'epic',
        'roblox', 'fortnite', 'coinbase', 'binance', 'metamask', 'trust.?wallet',
    ]
    brand_found = set()
    for brand in brand_names:
        if re.search(rf'[.#]?-?{brand}', css_code, re.I):
            brand_found.add(brand)
    if brand_found:
        findings.append(_score_js_finding(
            'brand_selectors',
            f'Brand-related CSS selectors: {", ".join(sorted(brand_found)[:8])}'
        ))
        score += 3 * len(brand_found)

    # ── 6. z-index abuse (very high z-index for overlays) ───────
    high_z = re.findall(r'z-index\s*:\s*(\d{4,})', css_code, re.I)
    if high_z:
        findings.append(_score_js_finding(
            'high_z_index',
            f'Very high z-index values: {", ".join(high_z[:5])}'
        ))
        score += 5

    # ── 7. Fake overlay / modal patterns ────────────────────────
    overlay_keywords = re.findall(
        r'(?:overlay|modal|popup|lightbox|splash|interstitial)',
        css_code, re.I
    )
    if len(overlay_keywords) > 3:
        findings.append(_score_js_finding(
            'overlay_patterns',
            f'{len(overlay_keywords)} overlay/modal references — possible fake login overlay'
        ))
        score += 5

    # ── 8. Content injection via pseudo-elements ─────────────────
    pseudo_content = re.findall(r'::?(?:before|after)\s*\{[^}]*content\s*:', css_code, re.I)
    if len(pseudo_content) > 5:
        findings.append(_score_js_finding(
            'pseudo_content',
            f'{len(pseudo_content)} pseudo-element content injections — may spoof UI elements'
        ))
        score += 3

    if score >= 20:
        level = 'high'
    elif score >= 10:
        level = 'medium'
    elif score >= 3:
        level = 'low'
    else:
        level = 'none'

    return {
        'filename': filename,
        'findings': findings,
        'score': score,
        'suspicion_level': level,
        'size': len(css_code),
    }


# ══════════════════════════════════════════════════════════════════
#  SSL CHECK
# ══════════════════════════════════════════════════════════════════

def check_ssl(hostname):
    """Check if SSL certificate is valid."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            return {
                "valid": True,
                "issuer": dict(x[0] for x in cert.get('issuer', [])).get(
                    'organizationName', 'Unknown'),
                "expires": cert.get('notAfter', 'Unknown'),
            }
    except Exception as e:
        return {"valid": False, "error": str(e)}


# ══════════════════════════════════════════════════════════════════
#  FEATURE 1: WHOIS LOOKUP (no API key needed)
# ══════════════════════════════════════════════════════════════════

def whois_lookup(domain):
    """
    Look up WHOIS info for a domain.
    Returns dict with: created_date, registrar, expires_date, country, error.
    """
    result = {
        'created_date': None,
        'registrar': None,
        'expires_date': None,
        'country': None,
        'age_days': None,
        'error': None,
    }

    if not HAS_WHOIS:
        result['error'] = 'python-whois not installed'
        return result

    # Clean domain: strip www. prefix
    clean = re.sub(r'^www\.', '', domain)

    try:
        w = whois.whois(clean)

        # Creation date (might be list or single)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            result['created_date'] = created.isoformat() if hasattr(created, 'isoformat') else str(created)
            try:
                # Normalize: strip timezone to naive for safe subtraction
                c = created.replace(tzinfo=None) if hasattr(created, 'replace') else created
                age = (datetime.now() - c).days
                result['age_days'] = age
            except Exception:
                result['age_days'] = None

        result['registrar'] = w.registrar or ''
        if isinstance(result['registrar'], list):
            result['registrar'] = result['registrar'][0]

        expires = w.expiration_date
        if isinstance(expires, list):
            expires = expires[0]
        if expires:
            result['expires_date'] = expires.isoformat() if hasattr(expires, 'isoformat') else str(expires)

        result['country'] = w.country or ''
        if isinstance(result['country'], list):
            result['country'] = result['country'][0]

        print(f"  ↳ WHOIS: registered {result.get('age_days', '?')}d ago, registrar: {result.get('registrar', '?')}")

    except Exception as e:
        result['error'] = str(e)[:120]
        print(f"  ↳ WHOIS lookup failed: {e}")

    return result


# ══════════════════════════════════════════════════════════════════
#  FEATURE 2: REDIRECT CHAIN ANALYSIS (no API key needed)
# ══════════════════════════════════════════════════════════════════

def analyze_redirect_chain(resp, original_url):
    """
    Analyze the HTTP redirect chain for suspicious patterns.
    Returns dict with: chain, hop_count, cross_domain, suspicious, reasons.
    """
    result = {
        'chain': [],
        'hop_count': 0,
        'cross_domain': False,
        'suspicious': False,
        'reasons': [],
    }

    if not resp:
        return result

    original_domain = urlparse(original_url).netloc
    history = getattr(resp, 'history', [])

    if not history:
        return result

    prev_domain = original_domain
    for i, h in enumerate(history):
        hop_url = h.url
        hop_code = h.status_code
        hop_domain = urlparse(hop_url).netloc
        hop_info = {
            'step': i + 1,
            'url': hop_url,
            'status': hop_code,
            'domain': hop_domain,
            'cross_domain': hop_domain != prev_domain and hop_domain != original_domain,
        }
        result['chain'].append(hop_info)
        prev_domain = hop_domain

    result['hop_count'] = len(result['chain'])

    # Check cross-domain redirects (ignore www/non-www normalisation)
    def _strip_www(d): return d[4:] if d.startswith('www.') else d

    final_domain = urlparse(resp.url).netloc
    if final_domain != original_domain and _strip_www(final_domain) != _strip_www(original_domain) and final_domain:
        result['cross_domain'] = True
        result['suspicious'] = True
        result['reasons'].append(
            f"Redirected from '{original_domain}' to '{final_domain}' — possible cloaking"
        )

    # Multiple hops through different domains
    domains_seen = set(
        urlparse(h['url']).netloc for h in result['chain']
        if urlparse(h['url']).netloc
    )
    if len(domains_seen) > 2:
        result['suspicious'] = True
        result['reasons'].append(
            f"Redirect chain passes through {len(domains_seen)} different domains — suspicious"
        )

    return result


# ══════════════════════════════════════════════════════════════════
#  FEATURE 3: CERTIFICATE TRANSPARENCY LOGS (crt.sh — free, no key)
# ══════════════════════════════════════════════════════════════════

def check_certificate_transparency(domain):
    """
    Query crt.sh for certificate transparency logs for a domain.
    Returns dict with: total_certs, recent_certs, issuers, suspicious, error.
    """
    result = {
        'total_certs': 0,
        'recent_certs': [],
        'issuers': [],
        'first_seen': None,
        'last_seen': None,
        'suspicious': False,
        'error': None,
    }

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, headers=HEADERS, timeout=15,
                            allow_redirects=True, verify=True)
        if resp.status_code != 200:
            result['error'] = f"crt.sh returned {resp.status_code}"
            return result

        data = resp.json()

        seen = set()
        issuers_set = set()
        timestamps = []

        for entry in data[:200]:  # limit to last 200 entries
            issuer = entry.get('issuer_name', '')
            name = entry.get('name_value', '')
            ts = entry.get('entry_timestamp', '')

            if name not in seen:
                seen.add(name)
                if len(result['recent_certs']) < 20:
                    result['recent_certs'].append({
                        'name': name,
                        'issuer': issuer[:100],
                        'timestamp': ts,
                    })

            if issuer and issuer not in issuers_set:
                issuers_set.add(issuer)
                result['issuers'].append(issuer[:120])

            if ts:
                try:
                    timestamps.append(datetime.strptime(ts[:10], '%Y-%m-%d'))
                except Exception:
                    pass

        result['total_certs'] = len(data)

        if timestamps:
            result['first_seen'] = min(timestamps).strftime('%Y-%m-%d')
            result['last_seen'] = max(timestamps).strftime('%Y-%m-%d')

        # Suspicious: very few certs (phishing domains are short-lived)
        if result['total_certs'] == 0:
            result['suspicious'] = True
        elif result['total_certs'] < 3:
            result['suspicious'] = True

        # Suspicious: first cert very recent (< 30 days)
        if result['first_seen']:
            try:
                age = (datetime.now() - datetime.strptime(result['first_seen'], '%Y-%m-%d')).days
                if age < 30:
                    result['suspicious'] = True
            except Exception:
                pass

        print(f"  ↳ crt.sh: {result['total_certs']} certs, first seen {result.get('first_seen', '?')}")

    except Exception as e:
        result['error'] = str(e)[:120]
        print(f"  ↳ crt.sh query failed: {e}")

    return result


# ══════════════════════════════════════════════════════════════════
#  FEATURE 4: DOMAIN REPUTATION DATABASE (SQLite — local, no key)
# ══════════════════════════════════════════════════════════════════

class DomainReputationDB:
    """Local SQLite database tracking domain reputation over time."""

    def __init__(self, db_path=REPUTATION_DB):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS domains (
                    domain TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    scan_count INTEGER DEFAULT 1,
                    risk_scores TEXT DEFAULT '[]',   -- JSON array of past scores
                    avg_risk REAL DEFAULT 0,
                    verdicts TEXT DEFAULT '[]',       -- JSON array of verdicts
                    tld TEXT,
                    has_ssl INTEGER DEFAULT 0,
                    has_login INTEGER DEFAULT 0,
                    notes TEXT DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    risk_score INTEGER DEFAULT 0,
                    verdict TEXT DEFAULT '',
                    url TEXT DEFAULT '',
                    source TEXT DEFAULT ''
                )
            """)
            conn.commit()

    def get_reputation(self, domain):
        """Get stored reputation for a domain. Returns dict or None."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM domains WHERE domain = ?", (domain,)
            ).fetchone()
            if not row:
                return None
            cols = [c[0] for c in conn.execute("PRAGMA table_info(domains)")]
            data = dict(zip(cols, row))
            data['risk_scores'] = json.loads(data.get('risk_scores', '[]'))
            data['verdicts'] = json.loads(data.get('verdicts', '[]'))
            return data

    def record_scan(self, domain, tld, risk_score, verdict, has_ssl, has_login, url, source):
        """Record a scan result, updating or inserting the domain."""
        now = datetime.now().isoformat()

        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute(
                "SELECT scan_count, risk_scores, verdicts FROM domains WHERE domain = ?",
                (domain,)
            ).fetchone()

            if existing:
                count = existing[0] + 1
                scores = json.loads(existing[1])
                scores.append(risk_score)
                # Keep last 20 scores
                scores = scores[-20:]
                avg = sum(scores) / len(scores)

                verdicts = json.loads(existing[2])
                verdicts.append(verdict)
                verdicts = verdicts[-20:]

                conn.execute("""
                    UPDATE domains SET
                        last_seen = ?, scan_count = ?, risk_scores = ?,
                        avg_risk = ?, verdicts = ?, has_ssl = ?, has_login = ?
                    WHERE domain = ?
                """, (now, count, json.dumps(scores), avg, json.dumps(verdicts),
                      int(has_ssl), int(has_login), domain))
            else:
                avg = float(risk_score)
                conn.execute("""
                    INSERT INTO domains (domain, first_seen, last_seen, scan_count,
                        risk_scores, avg_risk, verdicts, tld, has_ssl, has_login)
                    VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
                """, (domain, now, now, json.dumps([risk_score]), avg,
                      json.dumps([verdict]), tld, int(has_ssl), int(has_login)))

            # Insert scan history
            conn.execute("""
                INSERT INTO scan_history (domain, timestamp, risk_score, verdict, url, source)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (domain, now, risk_score, verdict, url, source))

            conn.commit()

    def get_recent_scans(self, limit=50):
        """Get recently scanned domains with summary."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT domain, last_seen, scan_count, avg_risk, tld,
                       json_array_length(verdicts) as v_count
                FROM domains
                ORDER BY last_seen DESC
                LIMIT ?
            """, (limit,)).fetchall()

            results = []
            for r in rows:
                # Get latest verdict
                verdicts = conn.execute(
                    "SELECT verdicts FROM domains WHERE domain = ?", (r[0],)
                ).fetchone()
                latest = "UNKNOWN"
                if verdicts:
                    try:
                        vlist = json.loads(verdicts[0])
                        latest = vlist[-1] if vlist else "UNKNOWN"
                    except Exception:
                        pass

                results.append({
                    'domain': r[0],
                    'last_seen': r[1],
                    'scan_count': r[2],
                    'avg_risk': round(r[3], 1),
                    'tld': r[4] or '',
                    'latest_verdict': latest,
                })

            return results

    def get_stats(self):
        """Get high-level stats."""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
            phishing = conn.execute(
                "SELECT COUNT(*) FROM domains WHERE json_extract(verdicts, '$[#-1]') = 'PHISHING'"
            ).fetchone()[0]
            suspicious = conn.execute(
                "SELECT COUNT(*) FROM domains WHERE json_extract(verdicts, '$[#-1]') = 'SUSPICIOUS'"
            ).fetchone()[0]
            safe = conn.execute(
                "SELECT COUNT(*) FROM domains WHERE json_extract(verdicts, '$[#-1]') = 'SAFE'"
            ).fetchone()[0]
            total_scans = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
            return {
                'total_domains': total,
                'phishing': phishing,
                'suspicious': suspicious,
                'safe': safe,
                'total_scans': total_scans,
            }


# Global reputation DB instance
_reputation_db = None


def get_reputation_db():
    global _reputation_db
    if _reputation_db is None:
        _reputation_db = DomainReputationDB()
    return _reputation_db


# ══════════════════════════════════════════════════════════════════
#  FEATURE 5: VIRUSTOTAL INTEGRATION (needs API key)
# ══════════════════════════════════════════════════════════════════

def check_virustotal(url):
    """
    Check URL against VirusTotal API.
    Requires VIRUSTOTAL_API_KEY in .env.
    Returns dict with: positives, total, permalink, error.
    """
    result = {
        'positives': None,
        'total': None,
        'scan_date': None,
        'permalink': None,
        'error': None,
    }

    if not VIRUSTOTAL_API_KEY:
        result['error'] = 'No VIRUSTOTAL_API_KEY set in .env'
        return result

    try:
        # First, submit URL for scanning
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY,
        }

        # URL identifier (base64url of URL hash)
        url_encoded = hashlib.sha256(url.encode()).hexdigest()

        vt_resp = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_encoded}',
            headers=headers,
            timeout=15,
        )

        if vt_resp.status_code == 200:
            data = vt_resp.json()
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            result['positives'] = stats.get('malicious', 0) + stats.get('suspicious', 0)
            result['total'] = sum(stats.values())
            result['scan_date'] = attrs.get('last_analysis_date', '')
            result['permalink'] = f"https://www.virustotal.com/gui/url/{url_encoded}"

            print(f"  ↳ VirusTotal: {result['positives']}/{result['total']} detections")
        elif vt_resp.status_code == 404:
            result['error'] = 'URL not yet scanned on VirusTotal'

            # Submit URL for scanning
            submit_resp = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers=headers,
                data={'url': url},
                timeout=10
            )
            if submit_resp.status_code == 200:
                result['error'] = 'URL submitted to VirusTotal for scanning (check back later)'
            else:
                result['error'] = f'VirusTotal submission failed: {submit_resp.status_code}'
        else:
            result['error'] = f'VirusTotal returned {vt_resp.status_code}'

    except Exception as e:
        result['error'] = str(e)[:120]
        print(f"  ↳ VirusTotal check failed: {e}")

    return result


# ══════════════════════════════════════════════════════════════════
#  FEATURE 6: PHISHTANK INTEGRATION (free API — no key needed)
# ══════════════════════════════════════════════════════════════════

def check_phishtank(url):
    """
    Check if URL/domain is in the PhishTank database.
    PhishTank has a free API with optional API key.
    Returns dict with: in_database, phish_id, verified, verified_at, error.
    """
    result = {
        'in_database': False,
        'phish_id': None,
        'verified': None,
        'verified_at': None,
        'details': None,
        'error': None,
    }

    try:
        # Encode URL for the lookup
        encoded = requests.utils.quote(url, safe='')
        api_url = f'https://checkurl.phishtank.com/checkurl/'

        headers_pt = {
            'User-Agent': 'phish-analyzer/1.0',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        # PhishTank uses POST with the URL and optional app_key
        data = {
            'url': url,
            'format': 'json',
        }
        if PHISHTANK_API_KEY:
            data['app_key'] = PHISHTANK_API_KEY

        pt_resp = requests.post(
            api_url, data=data, headers=headers_pt, timeout=15,
        )

        if pt_resp.status_code == 200:
            data = pt_resp.json()
            meta = data.get('meta', {})
            results = data.get('results', {})

            result['in_database'] = results.get('in_database', False)
            result['phish_id'] = results.get('phish_id')
            result['verified'] = results.get('verified', False)
            result['verified_at'] = results.get('verified_at')
            result['details'] = results.get('url', '')

            if result['in_database']:
                print(f"  ↳ PhishTank: IN DATABASE — verified={result['verified']}")
            else:
                print(f"  ↳ PhishTank: not in database")
        else:
            result['error'] = f'PhishTank returned {pt_resp.status_code}'

    except Exception as e:
        result['error'] = str(e)[:120]
        print(f"  ↳ PhishTank check failed: {e}")

    return result


# ══════════════════════════════════════════════════════════════════
#  FEATURE 7: FAVICON ANALYSIS (brand-spoofing via perceptual hash)
# ══════════════════════════════════════════════════════════════════

def analyze_favicon(html, base_url, domain_folder):
    """
    Download and analyze the site's favicon.
    Uses Pillow to compute a simple perceptual hash and check for
    known-brand favicon characteristics.
    Returns dict with: found, url, width, height, dominant_colors, error.
    """
    result = {
        'found': False,
        'url': None,
        'local_path': None,
        'width': None,
        'height': None,
        'dominant_colors': [],
        'suspicious': False,
        'reasons': [],
        'error': None,
    }

    if not HAS_PILLOW:
        result['error'] = 'Pillow not installed'
        return result

    soup = BeautifulSoup(html, 'html.parser')

    # Find favicon URL
    favicon_url = None
    for link in soup.find_all('link'):
        rel = (link.get('rel') or [] if isinstance(link.get('rel'), list)
               else [link.get('rel', '')])
        rel_lower = [r.lower() for r in rel]
        if any(r in rel_lower for r in ['icon', 'shortcut icon', 'apple-touch-icon']):
            favicon_url = link.get('href', '')
            break

    # Fallback to /favicon.ico
    if not favicon_url:
        favicon_url = urljoin(base_url, '/favicon.ico')

    if not favicon_url:
        return result

    full_url = urljoin(base_url, favicon_url)
    result['url'] = full_url

    try:
        # Download favicon
        img_resp = requests.get(full_url, headers=HEADERS, timeout=10,
                                allow_redirects=True, verify=True)
        img_resp.raise_for_status()

        # Save to disk
        img_dir = os.path.join(domain_folder, 'img')
        os.makedirs(img_dir, exist_ok=True)
        local_path = os.path.join(img_dir, 'favicon.ico')
        with open(local_path, 'wb') as f:
            f.write(img_resp.content)
        result['local_path'] = local_path

        # Analyze with Pillow
        img = Image.open(_io_module.BytesIO(img_resp.content))
        result['width'], result['height'] = img.size

        # Get dominant colors (simplified: average of quadrants)
        if img.mode != 'RGB':
            img = img.convert('RGB')

        # Simple color analysis — sample corners and center
        w, h = img.size
        samples = [
            img.getpixel((w // 4, h // 4)),
            img.getpixel((3 * w // 4, h // 4)),
            img.getpixel((w // 2, h // 2)),
            img.getpixel((w // 4, 3 * h // 4)),
            img.getpixel((3 * w // 4, 3 * h // 4)),
        ]

        # Quantize to named-ish colors
        color_names = []
        for r, g, b in samples:
            hex_color = f"#{r:02x}{g:02x}{b:02x}"
            color_names.append(hex_color)
        result['dominant_colors'] = color_names[:5]

        # Suspicious: favicon loaded from different domain
        favicon_domain = urlparse(full_url).netloc
        page_domain = urlparse(base_url).netloc
        if favicon_domain != page_domain:
            result['suspicious'] = True
            result['reasons'].append(
                f"Favicon loaded from '{favicon_domain}' (different from page domain '{page_domain}')"
            )

        print(f"  ↳ Favicon: {result['width']}x{result['height']}, {len(color_names)} colors")

    except Exception as e:
        result['error'] = str(e)[:120]
        print(f"  ↳ Favicon analysis failed: {e}")

    return result


# ══════════════════════════════════════════════════════════════════
#  FIELD EXTRACTION (comprehensive)
# ══════════════════════════════════════════════════════════════════

def extract_fields(url, html, status_code, download_errors=None):
    """Extract all phishing-relevant fields from HTML."""
    soup = BeautifulSoup(html, 'html.parser')
    parsed = urlparse(url)
    domain = parsed.netloc

    # ── Title ──────────────────────────────────────────────────
    title = soup.title.string.strip() if soup.title and soup.title.string else ""

    # ── Meta tags ──────────────────────────────────────────────
    meta_desc = ""
    meta_kw = ""
    meta_author = ""
    meta_viewport = ""
    for meta in soup.find_all('meta'):
        name = (meta.get('name') or meta.get('property') or meta.get('http-equiv') or '').lower()
        content = meta.get('content', '')
        if name == 'description':
            meta_desc = content
        elif name == 'keywords':
            meta_kw = content
        elif name == 'author':
            meta_author = content
        elif name == 'viewport':
            meta_viewport = content

    # ── Favicon ────────────────────────────────────────────────
    favicon = ""
    for link in soup.find_all('link', rel=lambda r: r and 'icon' in r.lower()):
        favicon = link.get('href', '')
        break

    # ── Visible text (cleaned) ─────────────────────────────────
    # Remove script and style elements
    for tag in soup(['script', 'style', 'noscript', 'iframe']):
        tag.decompose()
    visible_text = soup.get_text(separator=' ', strip=True)
    visible_text_trimmed = visible_text[:3000] if len(visible_text) > 3000 else visible_text

    # ── Forms ──────────────────────────────────────────────────
    forms = []
    for form in soup.find_all('form'):
        fields = []
        for inp in form.find_all(['input', 'select', 'textarea']):
            inp_type = inp.get('type', 'text').lower()
            inp_name = inp.get('name', inp.get('id', inp.get('placeholder', '')))
            inp_value = inp.get('value', '')
            if inp_type not in ('hidden', 'submit', 'button'):
                fields.append({
                    "type": inp_type,
                    "name": inp_name,
                    "value": inp_value,
                })
        forms.append({
            "action": form.get('action', ''),
            "method": (form.get('method') or 'GET').upper(),
            "fields": fields,
            "field_count": len(fields),
        })

    # ── Detect login-type forms ────────────────────────────────
    has_login_form = False
    password_fields = False
    email_fields = False
    login_keywords = ['login', 'signin', 'sign-in', 'logon', 'username', 'user', 'email',
                      'password', 'passwd', 'pwd', 'pin', 'secret']
    for form in forms:
        for field in form['fields']:
            if field['type'] == 'password':
                password_fields = True
                has_login_form = True
            if field['type'] == 'email' or 'email' in field['name'].lower():
                email_fields = True
                has_login_form = True
        # Also check form action for login keywords
        action_lower = form['action'].lower()
        if any(kw in action_lower for kw in login_keywords):
            has_login_form = True

    # ── External links ─────────────────────────────────────────
    external_links = []
    internal_links = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        link_text = a.get_text(strip=True)[:80]
        if href.startswith(('http://', 'https://')):
            link_domain = urlparse(href).netloc
            if link_domain and link_domain != domain:
                external_links.append({'url': href, 'text': link_text})
        elif not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
            internal_links.append(href[:120])
    external_links_deduped = list({e['url']: e for e in external_links}.values())[:30]
    internal_links = list(set(internal_links))[:30]

    # ── Script sources (re-parse since we decomposed scripts) ──
    soup2 = BeautifulSoup(html, 'html.parser')
    script_sources = []
    inline_scripts = []
    for script in soup2.find_all('script'):
        src = script.get('src', '')
        if src:
            script_sources.append(src)
        elif script.string and script.string.strip():
            inline_scripts.append(script.string.strip()[:500])
    script_sources = list(set(script_sources))[:20]

    # ── Image sources ──────────────────────────────────────────
    image_sources = []
    for img in soup2.find_all('img', src=True):
        alt = img.get('alt', '')
        image_sources.append({'src': img['src'], 'alt': alt})
    image_sources = list({i['src']: i for i in image_sources}.values())[:20]

    # ── Iframes ────────────────────────────────────────────────
    iframes = []
    for iframe in soup2.find_all('iframe', src=True):
        iframes.append(iframe['src'])
    iframes = list(set(iframes))[:10]

    # ── SSL info ───────────────────────────────────────────────
    ssl_info = check_ssl(domain) if domain else {"valid": False, "error": "No domain"}

    return {
        "url": url,
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "http_status": status_code,
        "title": title,
        "meta_description": meta_desc,
        "meta_keywords": meta_kw,
        "meta_author": meta_author,
        "meta_viewport": meta_viewport,
        "favicon": favicon,
        "visible_text": visible_text_trimmed,
        "forms": forms,
        "has_login_form": has_login_form,
        "has_password_field": password_fields,
        "has_email_field": email_fields,
        "external_links": external_links_deduped,
        "internal_links_count": len(internal_links),
        "script_sources": script_sources,
        "inline_scripts": inline_scripts[:5],  # First 5 inline scripts
        "image_sources": image_sources,
        "iframes": iframes,
        "html_length": len(html),
        "ssl": ssl_info,
        "download_errors": download_errors or [],
    }


# ══════════════════════════════════════════════════════════════════
#  SAVE TO DOMAIN FOLDER
# ══════════════════════════════════════════════════════════════════

def save_to_folder(domain, html, extracted_data, asset_results=None,
                    js_analyses=None, css_analyses=None,
                    whois_data=None, ct_data=None, redirect_data=None,
                    vt_data=None, pt_data=None, favicon_data=None,
                    reputation=None):
    """Save HTML, extracted data, and all analysis results to a domain-named folder."""
    folder = os.path.join(SCRAPED_DIR, domain)
    os.makedirs(folder, exist_ok=True)

    # Save raw HTML
    html_path = os.path.join(folder, 'page.html')
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"  ↳ Saved HTML → {html_path}")

    # Save extracted data (full, including all analysis summaries)
    data = dict(extracted_data)
    if asset_results:
        data['_assets'] = {
            'js_downloaded': len(asset_results['js']['downloaded']),
            'js_failed': len(asset_results['js']['failed']),
            'css_downloaded': len(asset_results['css']['downloaded']),
            'css_failed': len(asset_results['css']['failed']),
            'img_downloaded': len(asset_results['img']['downloaded']),
            'img_failed': len(asset_results['img']['failed']),
        }
    if js_analyses:
        data['_js_analysis'] = js_analyses
    if css_analyses:
        data['_css_analysis'] = css_analyses
    if whois_data:
        data['_whois'] = whois_data
    if ct_data:
        data['_cert_transparency'] = ct_data
    if redirect_data:
        data['_redirect_chain'] = redirect_data
    if vt_data:
        data['_virustotal'] = vt_data
    if pt_data:
        data['_phishtank'] = pt_data
    if favicon_data:
        data['_favicon'] = favicon_data
    if reputation:
        data['_reputation'] = {
            'avg_risk': reputation.get('avg_risk'),
            'scan_count': reputation.get('scan_count'),
            'first_seen': reputation.get('first_seen'),
        }

    data_path = os.path.join(folder, 'extracted_data.json')
    with open(data_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  ↳ Saved fields → {data_path}")

    return folder


# ══════════════════════════════════════════════════════════════════
#  OFFLINE HEURISTIC ENGINEE (no API key needed)
# ══════════════════════════════════════════════════════════════════

# ── Suspicious TLDs commonly used in phishing ──────────────────
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq',          # Free domains (Freenom)
    'xyz', 'top', 'club', 'work', 'date', 'review', 'country',
    'stream', 'download', 'win', 'bid', 'trade', 'webcam',
    'loan', 'racing', 'accountant', 'science', 'party', 'site',
    'online', 'pw', 'cc', 'su',
}

# ── Commonly impersonated brands ───────────────────────────────
TARGET_BRANDS = [
    'paypal', 'google', 'facebook', 'microsoft', 'apple', 'amazon',
    'netflix', 'instagram', 'whatsapp', 'twitter', 'linkedin',
    'dropbox', 'adobe', 'spotify', 'steam', 'discord', 'roblox',
    'fortnite', 'epicgames', 'coinbase', 'binance', 'metamask',
    'bankofamerica', 'chase', 'wellsfargo', 'citibank', 'usbank',
    'amex', 'americanexpress', 'mastercard', 'visa', 'payoneer',
    'outlook', 'office365', 'gmail', 'yahoo', 'protonmail',
    'dhl', 'fedex', 'ups', 'usps', 'amazonaws', 'azure',
]

URGENCY_PHRASES = [
    'verify your account', 'account suspended', 'security alert',
    'unauthorized login', 'update your information', 'limited account',
    'confirm your identity', 'unusual activity', 'login attempt',
    'password expired', 'action required', 'verify now',
    'suspicious activity', 'account locked', 'urgent action',
    'click here to restore', 'validate your account',
    'your account will be deleted', 'verify your email',
]


def _levenshtein(s1, s2):
    """Quick edit-distance for typosquatting detection (max dist 2)."""
    if abs(len(s1) - len(s2)) > 2:
        return 999
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    # s1 is longer
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr.append(min(prev[j+1] + 1, curr[j] + 1, prev[j] + cost))
        if min(curr) > 2:
            return 999  # early exit
        prev = curr
    return prev[-1]


def _brand_typo_match(domain_part):
    """
    Check if a domain part closely resembles a target brand.
    Returns (brand_name, distance) or None.
    """
    part = domain_part.lower().strip()
    for brand in TARGET_BRANDS:
        if len(part) >= len(brand) - 1 and len(part) <= len(brand) + 2:
            dist = _levenshtein(part, brand)
            if dist <= 2 and dist > 0:  # dist=0 means exact match (not typo)
                return brand, dist
    return None


def heuristic_analyze(extracted_data, js_analyses=None, css_analyses=None,
                       whois_data=None, redirect_data=None, ct_data=None,
                       vt_data=None, pt_data=None, favicon_data=None,
                       reputation=None):
    """
    Offline rule-based phishing detection engine.
    Category-based scoring: URL(25) + SSL(10) + Forms(15) + Content(15)
                           + Static(10) + WHOIS(10) + CT(5) + Redirects(5)
                           + External Intel(10) + Favicon(5) = 100 max.

    Works without any API key — always returns a verdict.
    Returns dict: {verdict, confidence, risk_score, reasons}
    """
    reasons = []

    url = extracted_data.get('url', '')
    domain = extracted_data.get('domain', '')
    parsed = urlparse(url)
    scheme = parsed.scheme
    path = parsed.path
    domain_lower = domain.lower()

    # Extract domain without subdomain for brand matching
    domain_parts = domain_lower.split('.')
    root_domain = domain_parts[0] if domain_parts else domain_lower

    # ═══════════════════════════════════════════════════════════
    #  CATEGORY 1: URL Structure (max 30 points)
    # ═══════════════════════════════════════════════════════════
    url_score = 0

    # IP address as domain — strong phish indicator
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        url_score += 25
        reasons.append("IP address used instead of domain name — strong phishing indicator")

    # Suspicious TLD
    tld = domain_parts[-1] if len(domain_parts) >= 2 else ''
    if tld in SUSPICIOUS_TLDS:
        url_score += 18
        reasons.append(f"Domain uses suspicious TLD '.{tld}' — frequently abused in phishing")

    # Excessive subdomains
    dots = domain.count('.')
    if dots > 3:
        url_score += 8
        reasons.append(f"Excessive subdomain depth ({dots} levels) — may obscure real domain")

    # URL contains @ symbol
    if '@' in url:
        url_score += 25
        reasons.append("URL contains '@' symbol — classic credential-redirect technique")

    # Non-standard port
    if parsed.port and parsed.port not in (80, 443, None):
        url_score += 8
        reasons.append(f"Non-standard port {parsed.port} — unusual for legitimate sites")

    # ── Brand impersonation / typosquatting ───────────────────
    # Exact brand substring match (e.g. "paypal-login.com")
    brand_matched = False
    for brand in TARGET_BRANDS:
        brand_domain = {
            'google': 'google.com', 'youtube': 'youtube.com',
            'paypal': 'paypal.com', 'facebook': 'facebook.com',
            'microsoft': 'microsoft.com', 'apple': 'apple.com',
            'amazon': 'amazon.com', 'netflix': 'netflix.com',
            'instagram': 'instagram.com', 'whatsapp': 'whatsapp.com',
            'twitter': 'twitter.com', 'linkedin': 'linkedin.com',
            'dropbox': 'dropbox.com', 'adobe': 'adobe.com',
            'spotify': 'spotify.com', 'steam': 'steampowered.com',
            'discord': 'discord.com', 'coinbase': 'coinbase.com',
            'binance': 'binance.com', 'metamask': 'metamask.io',
            'bankofamerica': 'bankofamerica.com', 'chase': 'chase.com',
            'wellsfargo': 'wellsfargo.com', 'outlook': 'outlook.com',
            'gmail': 'gmail.com', 'yahoo': 'yahoo.com', 'dhl': 'dhl.com',
            'fedex': 'fedex.com', 'ups': 'ups.com', 'usps': 'usps.com',
        }.get(brand, f'{brand}.com')

        if brand in domain_lower and brand_domain != domain_lower:
            url_score += 20
            reasons.append(f"Brand '{brand}' in domain '{domain}' — likely impersonating {brand_domain}")
            brand_matched = True
            break

    # Typosquatting detection (e.g. paypa1, g00gle, facebok)
    # Check root domain and each hyphen-separated segment
    if not brand_matched:
        segments = root_domain.replace('-', ' ').split()
        for seg in segments:
            typo = _brand_typo_match(seg)
            if typo:
                brand, dist = typo
                url_score += 18
                reasons.append(f"Typosquatting: '{root_domain}' resembles '{brand}' (edit distance {dist}) — brand impersonation")
                brand_matched = True
                break

    # Excessive hyphens
    if domain.count('-') >= 3:
        url_score += 5
        reasons.append(f"Excessive hyphens in domain — typosquatting indicator")

    # HTTP (not HTTPS) with a login form
    if scheme == 'http' and extracted_data.get('has_login_form'):
        url_score += 12
        reasons.append("Login form served over HTTP — credentials sent in cleartext")
    elif scheme == 'http' and not ssl_info_valid(extracted_data):
        url_score += 5
        reasons.append("Site served over HTTP (no encryption)")

    url_score = min(url_score, 30)

    # ═══════════════════════════════════════════════════════════
    #  CATEGORY 2: SSL (max 15 points)
    # ═══════════════════════════════════════════════════════════
    ssl_score = 0
    ssl_info = extracted_data.get('ssl', {})
    if not ssl_info.get('valid', False):
        err = ssl_info.get('error', '')
        if err:
            ssl_score += 10
            reasons.append(f"SSL invalid: {err[:80]}")
        else:
            ssl_score += 8
            reasons.append("No valid SSL certificate")
    ssl_score = min(ssl_score, 15)

    # ═══════════════════════════════════════════════════════════
    #  CATEGORY 3: Forms (max 20 points)
    # ═══════════════════════════════════════════════════════════
    form_score = 0
    forms = extracted_data.get('forms', [])

    if extracted_data.get('has_login_form'):
        form_score += 6
        reasons.append("Login form detected on page")

    if extracted_data.get('has_password_field'):
        form_score += 3

    # Login form submits to external domain
    for form in forms:
        action = form.get('action', '')
        if action and 'http' in action:
            action_domain = urlparse(action).netloc
            if action_domain and action_domain != domain:
                form_score += 12
                reasons.append(f"Login form submits to external domain '{action_domain}' — credential exfiltration risk")
                break

    # Hidden fields
    hidden_count = sum(
        1 for form in forms
        for f in form.get('fields', [])
        if f.get('type') == 'hidden'
    )
    if hidden_count > 2:
        form_score += 4
        reasons.append(f"{hidden_count} hidden form fields — may contain tracking/replay tokens")

    form_score = min(form_score, 20)

    # ═══════════════════════════════════════════════════════════
    #  CATEGORY 4: Content (max 20 points)
    # ═══════════════════════════════════════════════════════════
    content_score = 0
    title = extracted_data.get('title', '').lower()
    visible = extracted_data.get('visible_text', '').lower()

    # Brand impersonation in page title
    for brand in TARGET_BRANDS:
        if brand in title and brand not in domain_lower:
            content_score += 15
            reasons.append(f"Title mentions '{brand}' but domain doesn't match — brand impersonation")
            break

    # Urgency/fear language
    hits = sum(1 for phrase in URGENCY_PHRASES if phrase in visible)
    if hits >= 2:
        content_score += 12
        reasons.append(f"{hits} urgency/fear phrases detected — social engineering pressure tactic")
    elif hits == 1:
        content_score += 5
        reasons.append("Urgency language detected — common phishing social-engineering")

    # Favicon from external domain
    favicon = extracted_data.get('favicon', '')
    if favicon and favicon.startswith('http'):
        fav_domain = urlparse(favicon).netloc
        if fav_domain and fav_domain != domain:
            content_score += 4
            reasons.append(f"Favicon loaded from '{fav_domain}' — may spoof trusted brand icon")

    # Download-errors-as-red-flags
    for err in extracted_data.get('download_errors', []):
        if any(kw in err.lower() for kw in ('403', 'block', 'flag', 'danger')):
            content_score += 10
            reasons.append("Site flagged as dangerous by hosting provider (403/blocked)")
            break

    # Iframes from external sources
    iframes = extracted_data.get('iframes', [])
    if iframes:
        content_score += 8
        reasons.append(f"{len(iframes)} iframe(s) detected — may load malicious content invisibly")

    content_score = min(content_score, 20)

    # ═══════════════════════════════════════════════════════════
    #  CATEGORY 5: JS/CSS Static Analysis (max 15 points)
    # ═══════════════════════════════════════════════════════════
    static_score = 0

    if js_analyses:
        js_total = sum(a['score'] for a in js_analyses)
        js_contrib = min(js_total / 5, 10)
        if js_contrib > 2:
            reasons.append(f"JS analysis: suspicion score {js_total} across {len(js_analyses)} file(s)")
        static_score += js_contrib

    if css_analyses:
        css_total = sum(a['score'] for a in css_analyses)
        css_contrib = min(css_total / 4, 5)
        if css_contrib > 1:
            reasons.append(f"CSS analysis: suspicion score {css_total} across {len(css_analyses)} file(s)")
        static_score += css_contrib

    static_score = min(static_score, 10)

    # ═══════════════════════════════════════════════════════════
    #  CATEGORY 6: WHOIS (max 10 points)
    # ═══════════════════════════════════════════════════════════
    whois_score = 0
    if whois_data and not whois_data.get('error'):
        age = whois_data.get('age_days')
        if age is not None:
            if age < 7:
                whois_score += 10
                reasons.append(f"Domain registered {age} days ago — very new, strong phishing signal")
            elif age < 30:
                whois_score += 7
                reasons.append(f"Domain registered {age} days ago — recently created (suspicious)")
            elif age < 90:
                whois_score += 3
                reasons.append(f"Domain only {age} days old — relatively new")
            elif age > 365:
                whois_score -= 3  # older domains are more trustworthy
        else:
            whois_score += 0
    elif whois_data and whois_data.get('error'):
        whois_score += 2  # WHOIS unavailable is slightly suspicious
    whois_score = max(0, min(whois_score, 10))

    # ═══════════════════════════════════════════════════════════
    #  CATEGORY 7: Certificate Transparency (max 5 points)
    # ═══════════════════════════════════════════════════════════
    ct_score = 0
    if ct_data and not ct_data.get('error'):
        total_certs = ct_data.get('total_certs', 0)
        first_seen = ct_data.get('first_seen')
        if total_certs == 0:
            ct_score += 5
            reasons.append("No certificates in CT logs — domain has no HTTPS history")
        elif total_certs < 3 and first_seen:
            try:
                age = (datetime.now() - datetime.strptime(first_seen, '%Y-%m-%d')).days
                if age < 30:
                    ct_score += 4
                    reasons.append(f"First certificate only {age} days ago — domain likely created for phishing")
                elif age < 90:
                    ct_score += 2
            except Exception:
                pass
    ct_score = min(ct_score, 5)

    # ═══════════════════════════════════════════════════════════
    #  CATEGORY 8: Redirect Chain (max 5 points)
    # ═══════════════════════════════════════════════════════════
    redirect_score = 0
    if redirect_data and redirect_data.get('suspicious'):
        redirect_score += min(redirect_data.get('hop_count', 0) * 2, 5)
        for r in redirect_data.get('reasons', []):
            reasons.append(r)
    redirect_score = min(redirect_score, 5)

    # ═══════════════════════════════════════════════════════════
    #  CATEGORY 9: External Threat Intel (max 10 points)
    # ═══════════════════════════════════════════════════════════
    intel_score = 0

    # VirusTotal
    if vt_data and not vt_data.get('error'):
        positives = vt_data.get('positives', 0)
        if positives and positives > 0:
            intel_score += min(positives * 2, 8)
            reasons.append(f"VirusTotal: {positives} engines detected this URL as malicious")
    elif vt_data and vt_data.get('error'):
        # Don't penalize — VT just might not have scanned it
        pass

    # PhishTank
    if pt_data and pt_data.get('in_database'):
        verified = pt_data.get('verified', False)
        intel_score += 8 if verified else 5
        vstr = "verified phishing" if verified else "reported phishing (unverified)"
        reasons.append(f"PhishTank: URL is in database as {vstr}")

    # Reputation DB
    if reputation:
        avg_risk = reputation.get('avg_risk', 0)
        scan_count = reputation.get('scan_count', 1)
        if scan_count > 1 and avg_risk > 50:
            intel_score += 5
            reasons.append(f"Previously flagged as high-risk ({scan_count} past scans, avg risk {avg_risk:.0f})")
        elif scan_count > 1 and avg_risk > 20:
            intel_score += 2
            reasons.append(f"Previously flagged as suspicious ({scan_count} past scans)")

    intel_score = min(intel_score, 10)

    # ═══════════════════════════════════════════════════════════
    #  CATEGORY 10: Favicon Analysis (max 5 points)
    # ═══════════════════════════════════════════════════════════
    favicon_score = 0
    if favicon_data and favicon_data.get('suspicious'):
        favicon_score += 3
        for r in favicon_data.get('reasons', []):
            reasons.append(r)
    if favicon_data and favicon_data.get('found'):
        if not favicon_data.get('error'):
            pass  # favicon exists and is normal
    favicon_score = min(favicon_score, 5)

    # ═══════════════════════════════════════════════════════════
    #  FINAL SCORE & VERDICT
    # ═══════════════════════════════════════════════════════════
    total_score = (url_score + ssl_score + form_score + content_score +
                   static_score + whois_score + ct_score + redirect_score +
                   intel_score + favicon_score)

    if total_score >= 45:
        verdict = "PHISHING"
    elif total_score >= 18:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    # Confidence: how much of the 100-point evidence pool we collected
    confidence = min(int(total_score * 1.3) + 15, 95)

    return {
        "verdict": verdict,
        "confidence": confidence,
        "risk_score": int(total_score),
        "reasons": reasons[:10],
        "source": "heuristic",
    }


def ssl_info_valid(extracted_data):
    return extracted_data.get('ssl', {}).get('valid', False)


# ══════════════════════════════════════════════════════════════════
#  OPENROUTER AI ANALYSIS (comprehensive prompt)
# ══════════════════════════════════════════════════════════════════

def build_ai_prompt(extracted_data, js_analyses=None, css_analyses=None, asset_results=None):
    """Build a rich, structured prompt for the AI model."""

    parts = []

    # ── Basic URL Info ───────────────────────────────────────────
    parts.append(f"""URL: {extracted_data['url']}
Domain: {extracted_data['domain']}
HTTP Status: {extracted_data['http_status']}
HTML Size: {extracted_data['html_length']:,} characters
Page Title: "{extracted_data['title']}"
Meta Description: "{extracted_data['meta_description']}"
Meta Keywords: "{extracted_data['meta_keywords']}"
Meta Author: "{extracted_data['meta_author']}"
SSL Valid: {extracted_data['ssl'].get('valid', 'Unknown')}
Has Login Form: {extracted_data['has_login_form']}
Has Password Field: {extracted_data['has_password_field']}
Has Email Field: {extracted_data.get('has_email_field', False)}""")

    # ── Download errors ──────────────────────────────────────────
    dl_errors = extracted_data.get('download_errors', [])
    if dl_errors:
        parts.append("\n--- DOWNLOAD ISSUES (important context) ---")
        for err in dl_errors:
            parts.append(f"  - {err}")
        parts.append("NOTE: These errors may indicate the site is flagged as dangerous.")

    # ── Forms ────────────────────────────────────────────────────
    if extracted_data['forms']:
        parts.append(f"\n--- FORMS ({len(extracted_data['forms'])} found) ---")
        for i, form in enumerate(extracted_data['forms']):
            field_names = [f"{f['type']}:{f['name']}" for f in form['fields']]
            parts.append(
                f"  Form {i+1}: action={form['action']}, method={form['method']}, "
                f"fields=[{', '.join(field_names[:10])}]"
            )
    else:
        parts.append("\n--- FORMS ---\n  None found")

    # ── External Links ───────────────────────────────────────────
    ext_links = extracted_data.get('external_links', [])
    if ext_links:
        parts.append(f"\n--- EXTERNAL LINKS ({len(ext_links)} found) ---")
        for link in ext_links[:10]:
            parts.append(f"  - {link['url']} (text: \"{link.get('text', '')}\")")

    # ── Iframes ──────────────────────────────────────────────────
    iframes = extracted_data.get('iframes', [])
    if iframes:
        parts.append(f"\n--- IFRAMES ({len(iframes)} found) ---")
        for iframe in iframes:
            parts.append(f"  - {iframe}")

    # ── Script Sources ───────────────────────────────────────────
    script_srcs = extracted_data.get('script_sources', [])
    if script_srcs:
        parts.append(f"\n--- SCRIPT SOURCES ({len(script_srcs)} found) ---")
        for src in script_srcs[:15]:
            parts.append(f"  - {src}")

    # ── Page text ────────────────────────────────────────────────
    parts.append(f"\n--- PAGE TEXT (visible content, first 2000 chars) ---")
    parts.append(extracted_data['visible_text'][:2000])

    # ── Downloaded Assets Summary ────────────────────────────────
    if asset_results:
        parts.append("\n--- DOWNLOADED ASSETS ---")
        parts.append(f"  JavaScript files: {len(asset_results['js']['downloaded'])} downloaded, "
                     f"{len(asset_results['js']['failed'])} failed")
        parts.append(f"  CSS files: {len(asset_results['css']['downloaded'])} downloaded, "
                     f"{len(asset_results['css']['failed'])} failed")
        parts.append(f"  Images: {len(asset_results['img']['downloaded'])} downloaded, "
                     f"{len(asset_results['img']['failed'])} failed")

        # List downloaded JS files
        if asset_results['js']['downloaded']:
            parts.append("  JS files:")
            for f in asset_results['js']['downloaded'][:10]:
                parts.append(f"    - {os.path.basename(f['path'])} ({f['size']:,} chars)")

        # List downloaded CSS files
        if asset_results['css']['downloaded']:
            parts.append("  CSS files:")
            for f in asset_results['css']['downloaded'][:10]:
                parts.append(f"    - {os.path.basename(f['path'])} ({f['size']:,} chars)")

    # ── JS Static Analysis Results ───────────────────────────────
    if js_analyses:
        parts.append("\n--- JAVASCRIPT STATIC ANALYSIS ---")
        total_js_score = 0
        for analysis in js_analyses:
            if analysis['findings']:
                parts.append(f"\n  File: {analysis['filename']} "
                             f"(score: {analysis['score']}, level: {analysis['suspicion_level']})")
                for finding in analysis['findings']:
                    parts.append(f"    - [{finding['type']}] {finding['match']}")
                total_js_score += analysis['score']
        if total_js_score > 0:
            parts.append(f"\n  TOTAL JS SUSPICION SCORE: {total_js_score}")
        else:
            parts.append("\n  No suspicious JS patterns detected.")

    # ── CSS Static Analysis Results ──────────────────────────────
    if css_analyses:
        parts.append("\n--- CSS STATIC ANALYSIS ---")
        total_css_score = 0
        for analysis in css_analyses:
            if analysis['findings']:
                parts.append(f"\n  File: {analysis['filename']} "
                             f"(score: {analysis['score']}, level: {analysis['suspicion_level']})")
                for finding in analysis['findings']:
                    parts.append(f"    - [{finding['type']}] {finding['match']}")
                total_css_score += analysis['score']
        if total_css_score > 0:
            parts.append(f"\n  TOTAL CSS SUSPICION SCORE: {total_css_score}")
        else:
            parts.append("\n  No suspicious CSS patterns detected.")

    # ── Instructions ─────────────────────────────────────────────
    parts.append("""

Analyze this URL and all the above data for phishing indicators. Consider:
1. URL structure and domain (typosquatting, lookalike domains, suspicious TLDs)
2. SSL certificate validity and issuer
3. Presence of login forms and where they submit to
4. Page content — does it impersonate a known brand?
5. External links — do they point to legitimate or suspicious domains?
6. JavaScript analysis — any obfuscation, redirects, credential theft patterns?
7. CSS analysis — any hidden elements, fake overlays, brand spoofing?
8. Download errors — do they suggest the site is flagged/blocked?
9. Iframes — are they loading content from suspicious sources?

Respond ONLY in valid JSON format:
{
  "verdict": "SAFE" or "PHISHING" or "SUSPICIOUS",
  "confidence": 0-100,
  "risk_score": 0-100,
  "reasons": ["reason1", "reason2", "reason3", ...],
  "explanation": "A 2-3 sentence plain-language summary explaining the verdict in simple terms a non-technical person would understand."
}""")

    return "\n".join(parts)


def analyze_with_ai(extracted_data, js_analyses=None, css_analyses=None, asset_results=None):
    """Call AI API (OpenRouter or DeepSeek) for phishing analysis.
    For OpenRouter: tries primary model, then falls back through free models list.
    Returns analysis dict with 'ai_explanation' field containing the raw AI text."""
    provider = AI_PROVIDER

    if provider == 'deepseek':
        if not DEEPSEEK_API_KEY:
            print("  ✗ DEEPSEEK_API_KEY not set — skipping AI analysis")
            return None
        api_key = DEEPSEEK_API_KEY
        models = [DEEPSEEK_MODEL]
        endpoint = 'https://api.deepseek.com/v1/chat/completions'
        provider_label = 'DeepSeek'
        extra_headers = {'Content-Type': 'application/json'}
    else:
        if not OPENROUTER_API_KEY:
            print("  ✗ OPENROUTER_API_KEY not set — skipping AI analysis")
            return None
        api_key = OPENROUTER_API_KEY
        # Build model list: primary first, then fallbacks (deduped)
        models = [OPENROUTER_MODEL]
        for m in OPENROUTER_FREE_MODELS:
            if m not in models:
                models.append(m)
        endpoint = 'https://openrouter.ai/api/v1/chat/completions'
        provider_label = 'OpenRouter'
        extra_headers = {
            'Content-Type': 'application/json',
            'HTTP-Referer': 'https://github.com/abdur/phishing-analyzer',
            'X-Title': 'Phishing Analyzer',
        }

    prompt = build_ai_prompt(extracted_data, js_analyses, css_analyses, asset_results)

    last_error = None
    for attempt, model in enumerate(models):
        prefix = f"↳ [{attempt+1}/{len(models)}]" if len(models) > 1 else "↳"
        if attempt == 0:
            print(f"\n🤖 Calling {provider_label} API ({model})...")
        else:
            print(f"  {prefix} Primary model failed — falling back to {model}...")

        try:
            headers = {'Authorization': f'Bearer {api_key}', **extra_headers}
            resp = requests.post(
                endpoint,
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}]
                },
                headers=headers,
                timeout=90
            )
            resp.raise_for_status()

            result_text = resp.json()['choices'][0]['message']['content']

            # Try to parse JSON from the response
            try:
                json_match = re.search(r'\{[\s\S]*\}', result_text)
                if json_match:
                    analysis = json.loads(json_match.group())
                else:
                    analysis = {"raw_response": result_text}
            except json.JSONDecodeError:
                analysis = {"raw_response": result_text}

            # Always include the raw text for GUI explanation display
            analysis['ai_explanation'] = result_text
            analysis['ai_model_used'] = model
            print(f"  ✓ Response from {model} ({len(result_text):,} chars)")
            return analysis

        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if hasattr(e, 'response') and e.response else '?'
            last_error = f"HTTP {status}: {e}"
            if status == 401 or status == 403:
                # Auth error — no point retrying with other models
                print(f"  ✗ Auth error ({status}) — invalid API key, skipping remaining models")
                break
            if status == 404:
                # Model doesn't exist on this provider — try next
                print(f"  ✗ Model {model} returned 404 — trying next model...")
                continue
            # Other HTTP errors — try next
            print(f"  ✗ {model} failed: {last_error}")
            continue

        except requests.exceptions.Timeout:
            last_error = "Request timed out"
            print(f"  ✗ {model} timed out — trying next model...")
            continue

        except requests.exceptions.RequestException as e:
            last_error = str(e)
            print(f"  ✗ {model} failed: {e}")
            continue

    # All models failed
    print(f"  ✗ All models exhausted. Last error: {last_error}")
    return {"error": last_error or "All AI models failed"}


def save_analysis(folder, analysis):
    """Save AI analysis result to the domain folder."""
    path = os.path.join(folder, 'analysis.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)
    print(f"  ↳ Saved analysis → {path}")


# ══════════════════════════════════════════════════════════════════
#  DISPLAY RESULTS
# ══════════════════════════════════════════════════════════════════

def display_results(extracted_data, analysis, js_analyses=None, css_analyses=None,
                    asset_results=None, whois_data=None, ct_data=None,
                    redirect_data=None, vt_data=None, pt_data=None,
                    favicon_data=None, reputation=None):
    """Print a formatted summary of the complete analysis."""
    print("\n" + "═" * 60)
    print("  PHISHING ANALYSIS RESULTS")
    print("═" * 60)
    print(f"  URL:     {extracted_data['url']}")
    print(f"  Domain:  {extracted_data['domain']}")
    print(f"  Title:   {extracted_data['title']}")
    print(f"  HTTP:    {extracted_data['http_status']}")
    print(f"  SSL:     {'✅ Valid' if extracted_data['ssl'].get('valid') else '❌ Invalid'}")

    # WHOIS summary
    if whois_data and not whois_data.get('error') and whois_data.get('age_days') is not None:
        age = whois_data['age_days']
        age_icon = '⚠️' if age < 30 else ('📝' if age < 90 else '✅')
        print(f"  WHOIS:   {age_icon} Registered {age}d ago")
    elif whois_data and whois_data.get('error'):
        print(f"  WHOIS:   ⚠ {whois_data['error'][:60]}")

    # CT summary
    if ct_data and not ct_data.get('error'):
        first = ct_data.get('first_seen', '?')
        total = ct_data.get('total_certs', 0)
        ico = '⚠️' if total < 3 else '✅'
        print(f"  CT Log:  {ico} {total} certs, first seen {first}")

    # Redirect summary
    if redirect_data and redirect_data.get('hop_count', 0) > 0:
        hops = redirect_data['hop_count']
        cross = '⚠ CROSS-DOMAIN' if redirect_data.get('cross_domain') else ''
        print(f"  Redirect: {hops} hop(s) {cross}")

    print(f"  Forms:   {len(extracted_data['forms'])} found "
              f"{'(⚠ LOGIN FORM)' if extracted_data['has_login_form'] else ''}")
    print(f"  Links:   {len(extracted_data.get('external_links', []))} external")
    print(f"  Iframes: {len(extracted_data.get('iframes', []))}")

    # Asset summary
    if asset_results:
        js_ok = len(asset_results['js']['downloaded'])
        js_fail = len(asset_results['js']['failed'])
        css_ok = len(asset_results['css']['downloaded'])
        css_fail = len(asset_results['css']['failed'])
        img_ok = len(asset_results['img']['downloaded'])
        print(f"  Assets:  JS:{js_ok}+{js_fail}fail  CSS:{css_ok}+{css_fail}fail  IMG:{img_ok}")

    # JS/CSS analysis summary
    if js_analyses:
        high_js = [a for a in js_analyses if a['suspicion_level'] == 'high']
        med_js = [a for a in js_analyses if a['suspicion_level'] == 'medium']
        if high_js or med_js:
            print(f"  JS:      ⚠ {len(high_js)} high, {len(med_js)} medium suspicion files")
    if css_analyses:
        high_css = [a for a in css_analyses if a['suspicion_level'] == 'high']
        med_css = [a for a in css_analyses if a['suspicion_level'] == 'medium']
        if high_css or med_css:
            print(f"  CSS:     ⚠ {len(high_css)} high, {len(med_css)} medium suspicion files")

    # External intel
    if vt_data and not vt_data.get('error') and vt_data.get('positives') is not None:
        print(f"  VT:      ⚠ {vt_data['positives']}/{vt_data['total']} engines detected")
    if pt_data and pt_data.get('in_database'):
        v = '✅ verified' if pt_data.get('verified') else '⚠ unverified'
        print(f"  PhishTank: 🚨 IN DATABASE ({v})")

    # Reputation
    if reputation:
        avg = reputation.get('avg_risk', 0)
        scans = reputation.get('scan_count', 1)
        if scans > 1:
            print(f"  Reputation: {scans} past scans, avg risk {avg:.0f}/100")

    print("─" * 60)

    if analysis and 'error' not in analysis and 'raw_response' not in analysis:
        verdict = analysis.get('verdict', 'UNKNOWN')
        confidence = analysis.get('confidence', '?')
        risk = analysis.get('risk_score', '?')
        reasons = analysis.get('reasons', [])

        if verdict == 'SAFE':
            icon = '✅'
        elif verdict == 'PHISHING':
            icon = '🚨'
        else:
            icon = '⚠️'

        print(f"  {icon} VERDICT:    {verdict}")
        print(f"     Confidence: {confidence}%")
        print(f"     Risk Score: {risk}/100")
        if reasons:
            print(f"     Reasons:")
            for r in reasons:
                print(f"       • {r}")
    elif analysis and 'raw_response' in analysis:
        print(f"  🤖 AI Response:\n{analysis['raw_response']}")
    elif analysis and 'error' in analysis:
        print(f"  ❌ AI Error: {analysis['error']}")
    else:
        print("  ⏭  AI analysis skipped (no API key)")

    print("═" * 60 + "\n")


# ══════════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ══════════════════════════════════════════════════════════════════

def analyze_url(url, progress_callback=None):
    """
    Full pipeline: download → WHOIS → cert transparency → extract →
    download assets → static analyze JS/CSS → favicon analysis →
    redirect analysis → VirusTotal → PhishTank → reputation DB →
    heuristic scoring → AI analysis → save → return results.
    """
    def _status(msg):
        print(msg)
        if progress_callback:
            progress_callback(msg)

    url = normalize_url(url)
    domain = get_domain(url)
    folder = os.path.join(SCRAPED_DIR, domain)
    os.makedirs(folder, exist_ok=True)

    _status(f"🔍 Analyzing: {url}")

    # Step 1: Download page
    _status(f"⏳  Downloading {domain}...")
    resp, dl_errors = download_page(url)

    if dl_errors:
        _status(f"⚠  Download issues: {'; '.join(dl_errors)}")

    if resp:
        html = resp.text
        status_code = resp.status_code
    else:
        html = ""
        status_code = 0
        _status("⚠  No page content — analyzing URL pattern only...")

    # Step 2: WHOIS lookup
    _status("📋  Looking up WHOIS registration data...")
    whois_data = whois_lookup(domain)

    # Step 3: Certificate Transparency logs
    _status("🔐  Checking certificate transparency logs (crt.sh)...")
    ct_data = check_certificate_transparency(domain)

    # Step 4: Extract fields from HTML
    _status("⏳  Extracting page data...")
    extracted = extract_fields(url, html, status_code, dl_errors)

    # Step 5: Download all assets (JS, CSS, images)
    asset_results = None
    js_analyses = []
    css_analyses = []
    favicon_data = None
    redirect_data = None

    if html:
        soup = BeautifulSoup(html, 'html.parser')

        # Download assets
        js_count = len(soup.find_all('script', src=True))
        css_count = len(soup.find_all('link', rel='stylesheet', href=True))
        img_count = min(len(soup.find_all('img', src=True)), 30)

        _status(f"⏳  Downloading assets ({js_count} JS, {css_count} CSS, {img_count} IMG)...")
        asset_results = download_all_assets(soup, url, folder)

        # Static analysis of downloaded JS
        js_files = asset_results['js']['downloaded']
        if js_files:
            _status(f"🔬  Analyzing {len(js_files)} JavaScript file(s)...")
            for js_file in js_files:
                try:
                    with open(js_file['path'], 'r', encoding='utf-8', errors='replace') as f:
                        js_content = f.read()
                    a = analyze_js_content(js_content, os.path.basename(js_file['path']))
                    js_analyses.append(a)
                except Exception as e:
                    _status(f"  ⚠ JS analysis error: {e}")

        # Static analysis of downloaded CSS
        css_files = asset_results['css']['downloaded']
        if css_files:
            _status(f"🔬  Analyzing {len(css_files)} CSS file(s)...")
            for css_file in css_files:
                try:
                    with open(css_file['path'], 'r', encoding='utf-8', errors='replace') as f:
                        css_content = f.read()
                    a = analyze_css_content(css_content, os.path.basename(css_file['path']))
                    css_analyses.append(a)
                except Exception as e:
                    _status(f"  ⚠ CSS analysis error: {e}")

        # Favicon analysis
        _status("🖼️  Analyzing favicon...")
        favicon_data = analyze_favicon(html, url, folder)

    # Step 6: Redirect chain analysis
    _status("🔗  Analyzing redirect chain...")
    redirect_data = analyze_redirect_chain(resp, url)

    # Step 7: External threat intel (VirusTotal + PhishTank)
    _status("🌐  Checking VirusTotal & PhishTank...")
    vt_data = check_virustotal(url)
    pt_data = check_phishtank(url)

    # Step 8: Reputation DB lookup
    _status("🗄️  Checking local reputation database...")
    rep_db = get_reputation_db()
    reputation = rep_db.get_reputation(domain)

    # Step 9: Save everything
    _status("⏳  Saving to folder...")
    os.makedirs(folder, exist_ok=True)
    folder = save_to_folder(domain, html or "<!-- download failed -->",
                            extracted, asset_results, js_analyses, css_analyses,
                            whois_data, ct_data, redirect_data,
                            vt_data, pt_data, favicon_data, reputation)

    # Step 10: Heuristic analysis (always runs, uses all data)
    _status("🔍  Running heuristic analysis (10 categories)...")
    heuristic = heuristic_analyze(extracted, js_analyses, css_analyses,
                                   whois_data, redirect_data, ct_data,
                                   vt_data, pt_data, favicon_data,
                                   reputation)

    # Step 11: Record scan in reputation DB
    tld = domain.rsplit('.', 1)[-1] if '.' in domain else ''
    rep_db.record_scan(
        domain=domain,
        tld=tld,
        risk_score=heuristic['risk_score'],
        verdict=heuristic['verdict'],
        has_ssl=extracted.get('ssl', {}).get('valid', False),
        has_login=extracted.get('has_login_form', False),
        url=url,
        source='heuristic',
    )

    # Step 12: AI Analysis (overrides heuristic if available)
    _status("🤖  Calling AI model for comprehensive analysis...")
    ai_analysis = analyze_with_ai(extracted, js_analyses, css_analyses, asset_results)
    if ai_analysis:
        save_analysis(folder, ai_analysis)

    # AI overrides heuristic if it returned valid structured data
    if ai_analysis and 'error' not in ai_analysis and 'raw_response' not in ai_analysis:
        analysis = ai_analysis
        # Also record AI verdict
        rep_db.record_scan(
            domain=domain, tld=tld,
            risk_score=ai_analysis.get('risk_score', heuristic['risk_score']),
            verdict=ai_analysis.get('verdict', heuristic['verdict']),
            has_ssl=extracted.get('ssl', {}).get('valid', False),
            has_login=extracted.get('has_login_form', False),
            url=url, source='ai',
        )
        analysis['source'] = 'ai'
    else:
        # Use heuristic as the primary result with AI error context
        analysis = dict(heuristic)
        if ai_analysis and 'error' in ai_analysis:
            analysis['ai_error'] = ai_analysis['error']
            analysis['source'] = 'heuristic (AI unavailable)'
        elif ai_analysis and 'raw_response' in ai_analysis:
            analysis = dict(heuristic)
            analysis['ai_raw'] = ai_analysis['raw_response'][:300]
            analysis['source'] = 'heuristic (AI parse failed)'

    # Always save the effective analysis
    save_analysis(folder, analysis)

    # Step 9: Display
    display_results(extracted, analysis, js_analyses, css_analyses, asset_results,
                    whois_data, ct_data, redirect_data, vt_data, pt_data,
                    favicon_data, reputation)

    # Attach extra analysis data to extracted for GUI consumption
    extracted['_whois'] = whois_data or {}
    extracted['_cert_transparency'] = ct_data or {}
    extracted['_redirect_chain'] = redirect_data or {}
    extracted['_virustotal'] = vt_data or {}
    extracted['_phishtank'] = pt_data or {}
    extracted['_favicon'] = favicon_data or {}
    extracted['_reputation'] = reputation or {}

    _status(f"✅  Analysis complete — saved to {folder}/")

    return extracted, analysis, js_analyses, css_analyses, asset_results


def main():
    print("╔══════════════════════════════════════════════════╗")
    print("║   URL Phishing Analyzer - Full Asset Analysis   ║")
    print("║   Type a URL to analyze, or 'quit' to exit      ║")
    print("╚══════════════════════════════════════════════════╝\n")

    if AI_PROVIDER == 'deepseek':
        if not DEEPSEEK_API_KEY:
            print("⚠  DEEPSEEK_API_KEY not found in .env — AI analysis disabled\n")
    else:
        if not OPENROUTER_API_KEY:
            print("⚠  OPENROUTER_API_KEY not found in .env — AI analysis disabled\n")

    while True:
        try:
            url = input("Enter URL → ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n👋 Goodbye!")
            break

        if not url:
            continue
        if url.lower() in ('quit', 'exit', 'q'):
            print("👋 Goodbye!")
            break

        try:
            analyze_url(url)
        except Exception as e:
            print(f"❌ Error: {e}\n")


if __name__ == "__main__":
    main()
