import asyncio
import html as html_lib
import ipaddress
import json
import logging
import os
import re
import socket
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
import trafilatura
import uvicorn
from bs4 import BeautifulSoup
from deep_translator import GoogleTranslator
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from readability import Document as ReadabilityDocument

app = FastAPI()

logger = logging.getLogger("app")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)

try:
    import curl_cffi as _curl_cffi_mod
    logger.info("curl_cffi %s imported OK", getattr(_curl_cffi_mod, "__version__", "?"))
except Exception as exc:
    logger.warning("curl_cffi unavailable: %r", exc)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class FetchRequest(BaseModel):
    url: str

class FetchResponse(BaseModel):
    html: str
    clean_html: str
    status_code: int
    final_url: str
    strategy_used: str
    reader_mode: bool = False   # True when content came from a reader proxy (limited full view)
    partial: bool = False       # True when the recovered content looks like a paywall teaser
    access_status: str = "public"
    notice: Optional[str] = None

class ExtractRequest(BaseModel):
    html: str
    url: Optional[str] = None

class ExtractResponse(BaseModel):
    title: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    text: str
    description: Optional[str] = None
    sitename: Optional[str] = None
    language: Optional[str] = None
    language_name: Optional[str] = None
    word_count: int = 0
    reading_minutes: int = 0
    source_url: Optional[str] = None

class TranslateRequest(BaseModel):
    text: str
    source_lang: str = "auto"
    target_lang: str = "en"

class TranslateResponse(BaseModel):
    translated_text: str
    source_lang: str
    target_lang: str

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

LANG_NAMES = {
    "en": "English", "fr": "French", "de": "German", "es": "Spanish",
    "it": "Italian", "pt": "Portuguese", "nl": "Dutch", "ru": "Russian",
    "zh": "Chinese", "ja": "Japanese", "ko": "Korean", "ar": "Arabic",
    "hi": "Hindi", "tr": "Turkish", "pl": "Polish", "sv": "Swedish",
    "da": "Danish", "fi": "Finnish", "no": "Norwegian", "el": "Greek",
    "he": "Hebrew", "th": "Thai", "vi": "Vietnamese", "id": "Indonesian",
    "uk": "Ukrainian", "cs": "Czech", "ro": "Romanian", "hu": "Hungarian",
    "fa": "Persian", "ur": "Urdu", "bn": "Bengali", "ta": "Tamil",
    "ms": "Malay", "ca": "Catalan", "sr": "Serbian", "hr": "Croatian",
    "bg": "Bulgarian", "sk": "Slovak", "sl": "Slovenian", "lt": "Lithuanian",
    "lv": "Latvian", "et": "Estonian",
}

# A public article below this threshold gets one additional, non-restricted
# reader fallback. Restricted previews never go through that fallback.
GOOD_TEXT_THRESHOLD = 1200
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

_BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

_SEC_HEADERS = {
    "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "cross-site",
    "Upgrade-Insecure-Requests": "1",
}

REQUEST_HEADERS = {
    "User-Agent": _BROWSER_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    **_SEC_HEADERS,
}

# When using curl_cffi TLS impersonation, the library sets its own browser
# fingerprint headers. Adding sec-ch-ua / Sec-Fetch-* manually can trigger
# WSJ's bot detection (401), so we use minimal headers for impersonated fetches.
IMPERSONATED_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


STRONG_RESTRICTION_MARKERS = (
    "subscribe to unlock", "subscribe to read", "create an account to read",
    "this article is for subscribers", "sign in to read",
    "register to continue", "to continue reading", "unlock this article",
    "subscription required",
)

SOFT_RESTRICTION_MARKERS = (
    "complete digital access", "for full access", "already a subscriber",
    "unlimited access", "become a member",
)

BLOCK_PAGE_MARKERS = (
    "verify you are human", "complete the captcha", "captcha challenge",
    "checking your browser", "just a moment...", "access denied",
    "request blocked", "cf-chl-", "attention required! | cloudflare",
)

RESTRICTED_NOTICE = (
    "The publisher returned a subscriber-only preview. NewsDesk preserved the "
    "public title and metadata, but it cannot retrieve content your account is "
    "not authorized to access."
)

RECOVERED_NOTICE = (
    "The publisher restricts this article, but the full text was recovered from "
    "a public archive or reader proxy."
)

HARD_PAYWALL_NOTICE = (
    "This article is behind a hard paywall. The full text could not be "
    "recovered from public archives or reader proxies from this server. "
    "Open the original article or paste the text manually."
)


def _extract_main_text(html: str) -> str:
    if not html:
        return ""
    try:
        return trafilatura.extract(
            html,
            include_comments=False,
            include_tables=False,
            favor_recall=True,
        ) or ""
    except Exception:
        return ""


def _looks_blocked(html: str, extracted_text: str) -> bool:
    """Reject CAPTCHA and anti-bot pages instead of treating them as articles."""
    try:
        visible = BeautifulSoup(html[:250000], "lxml").get_text(" ", strip=True)
    except Exception:
        visible = html[:50000]
    sample = f"{visible[:15000]} {extracted_text[:5000]}".lower()
    return any(marker in sample for marker in BLOCK_PAGE_MARKERS)


def _looks_restricted(html: str, extracted_text: str) -> bool:
    """Classify a subscriber preview without letting footer copy inflate it."""
    if re.search(r'"isAccessibleForFree"\s*:\s*false', html[:500000], flags=re.IGNORECASE):
        return True
    try:
        visible = BeautifulSoup(html[:350000], "lxml").get_text(" ", strip=True)
    except Exception:
        visible = html[:80000]
    sample = f"{extracted_text[:12000]} {visible[:20000]}".lower()
    strong_hits = sum(marker in sample for marker in STRONG_RESTRICTION_MARKERS)
    soft_hits = sum(marker in sample for marker in SOFT_RESTRICTION_MARKERS)
    if strong_hits == 0 and soft_hits == 0:
        return False
    article_words = len(extracted_text.split())
    return (strong_hits >= 1 and article_words < 1200) or (
        strong_hits + soft_hits >= 2 and article_words < 800
    )


async def _validate_public_url(url: str) -> str:
    """Allow only public HTTP(S) destinations and block SSRF targets."""
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid article URL") from exc

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="Enter a valid http:// or https:// article URL")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Article URLs cannot contain credentials")
    if port not in {None, 80, 443}:
        raise HTTPException(status_code=400, detail="Only standard web ports are supported")

    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise HTTPException(status_code=400, detail="Local network URLs are not supported")

    try:
        addresses = await asyncio.to_thread(
            socket.getaddrinfo,
            hostname,
            port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise HTTPException(status_code=400, detail="The article host could not be resolved") from exc

    for address in {item[4][0] for item in addresses}:
        try:
            if not ipaddress.ip_address(address).is_global:
                raise HTTPException(status_code=400, detail="Local or private network URLs are not supported")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="The article host resolved to an invalid address") from exc
    return url


def _curl_get(url: str, headers: dict) -> tuple[str, int, dict, str]:
    """Perform a TLS-impersonated GET (looks like real Chrome) to evade bot blocks."""
    from curl_cffi import requests as curl_requests

    resp = curl_requests.get(
        url,
        impersonate="chrome131",
        headers=headers,
        timeout=45.0,
        allow_redirects=False,
    )
    return resp.text, resp.status_code, dict(resp.headers), str(resp.url)


async def _fetch_html(
    client: httpx.AsyncClient,
    url: str,
    headers: Optional[dict] = None,
    allow_block: bool = False,
    impersonate: bool = True,
    reader_proxy: bool = False,
) -> tuple[str, int, str]:
    """Fetch HTML with redirect validation, TLS impersonation, and bounded size."""
    current = await _validate_public_url(url)
    if reader_proxy:
        chosen_headers = {
            "User-Agent": "Mozilla/5.0 (compatible; FeedReader/1.0)",
            "Accept": "text/plain, text/markdown, text/html, */*;q=0.5",
        }
    else:
        chosen_headers = headers or (IMPERSONATED_HEADERS if impersonate else REQUEST_HEADERS)
    for _ in range(8):
        if impersonate and not reader_proxy:
            try:
                text, status, resp_headers, final = await asyncio.to_thread(
                    _curl_get, current, chosen_headers
                )
            except Exception as exc:
                logger.warning("curl_cffi impersonation failed for %s: %r", current, exc)
                text, status, resp_headers, final = await _httpx_get(
                    client, current, REQUEST_HEADERS
                )
        else:
            text, status, resp_headers, final = await _httpx_get(
                client, current, chosen_headers
            )

        if status in {301, 302, 303, 307, 308}:
            location = resp_headers.get("location")
            if not location:
                raise HTTPException(status_code=502, detail="Publisher returned an invalid redirect")
            current = await _validate_public_url(urljoin(current, location))
            continue

        if status in {401, 403, 451}:
            if allow_block:
                return "", status, current
            raise HTTPException(
                status_code=403,
                detail="The publisher blocked automated access. Open the original article or paste text you are authorized to read.",
            )
        if status >= 400:
            raise HTTPException(status_code=502, detail=f"Publisher returned HTTP {status}")

        content_type = resp_headers.get("content-type", "").lower()
        if (
            content_type
            and "html" not in content_type
            and "xml" not in content_type
            and "text/plain" not in content_type
            and "text/markdown" not in content_type
        ):
            raise HTTPException(status_code=415, detail="The URL did not return an HTML article")
        if len(text) > MAX_RESPONSE_BYTES:
            raise HTTPException(status_code=413, detail="The article page is too large to process")
        return text, status, final

    raise HTTPException(status_code=502, detail="Publisher redirected too many times")


async def _httpx_get(
    client: httpx.AsyncClient, url: str, headers: dict
) -> tuple[str, int, dict, str]:
    """Plain httpx fallback used when curl_cffi is unavailable."""
    resp = await client.get(url, headers=headers, follow_redirects=False)
    return resp.text, resp.status_code, dict(resp.headers), str(resp.url)


# ---------------------------------------------------------------------------
# Public-proxy refetch — bypasses datacenter IP blocks (FT blocks AWS ranges).
# A free public HTTP proxy provides a non-blocked exit IP while we keep the
# social-referer trick that makes FT serve the full article.
# ---------------------------------------------------------------------------

_PROXY_STATE: dict = {"list": [], "ts": 0.0, "good": []}
_PROXY_SOURCES = (
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-LIST/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-LIST/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=yes&anonymity=all",
)
_PROXY_LIST_TTL = 900.0  # refresh candidate list every 15 minutes


def _curl_get_via_proxy(url: str, headers: dict, proxy: str) -> tuple[str, int]:
    from curl_cffi import requests as curl_requests

    addr = proxy if "://" in proxy else f"http://{proxy}"
    resp = curl_requests.get(
        url,
        impersonate="chrome131",
        headers=headers,
        timeout=8.0,
        allow_redirects=True,
        proxies={"http": addr, "https": addr},
    )
    return resp.text, resp.status_code


def _refresh_proxy_list() -> None:
    import time as _time
    import random as _random

    now = _time.time()
    if _PROXY_STATE["list"] and now - _PROXY_STATE["ts"] < _PROXY_LIST_TTL:
        return
    proxies: list[str] = []
    for src in _PROXY_SOURCES:
        is_socks = src.endswith("socks5.txt")
        try:
            resp = httpx.get(src, timeout=15.0)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", line):
                        proxies.append(f"socks5://{line}" if is_socks else line)
        except Exception:
            continue
        if len(proxies) >= 400:
            break
    if proxies:
        _random.shuffle(proxies)
        _PROXY_STATE["list"] = list(dict.fromkeys(proxies))[:400]
        _PROXY_STATE["ts"] = now
        logger.info("proxy list refreshed: %s candidates", len(_PROXY_STATE["list"]))


def _proxy_candidates(limit: int = 40) -> list[str]:
    """Known-good proxies first (rotated to avoid burning one IP), then a
    random slice of the fresh list."""
    import random as _random

    good = [p for p in _PROXY_STATE["good"] if p]
    _random.shuffle(good)
    rest = [p for p in _PROXY_STATE["list"] if p not in good]
    _random.shuffle(rest)
    return (good + rest)[:limit]


async def _fetch_via_public_proxy(url: str) -> Optional[str]:
    """Fetch article HTML through free public proxies with the social referer.

    Tries proxies in parallel waves; returns the first response whose
    extracted text looks like a real (non-paywalled) article.
    """
    _refresh_proxy_list()
    candidates = _proxy_candidates()
    if not candidates:
        logger.info("public_proxy: no candidates available")
        return None

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.facebook.com/",
    }
    loop = asyncio.get_running_loop()

    async def attempt(proxy: str) -> tuple[str, int, str]:
        try:
            text, status = await loop.run_in_executor(
                None, _curl_get_via_proxy, url, headers, proxy
            )
            return proxy, status, text
        except Exception:
            return proxy, 0, ""

    for i in range(0, len(candidates), 8):
        wave = candidates[i : i + 8]
        results = await asyncio.gather(*(attempt(p) for p in wave))
        for proxy, status, html in results:
            if status != 200 or len(html) < 20000:
                # A cached "good" proxy that stopped working gets demoted so
                # it doesn't keep failing at the front of the queue.
                if proxy in _PROXY_STATE["good"]:
                    _PROXY_STATE["good"].remove(proxy)
                continue
            page_text = await asyncio.to_thread(_extract_page_text, html)
            words = len(page_text.split())
            if words < 300 or _looks_blocked(html, page_text) or _looks_restricted(html, page_text):
                if proxy in _PROXY_STATE["good"]:
                    _PROXY_STATE["good"].remove(proxy)
                continue
            if proxy not in _PROXY_STATE["good"]:
                _PROXY_STATE["good"].insert(0, proxy)
                del _PROXY_STATE["good"][4:]
            logger.info("public_proxy: %s via %s words=%s", url[:60], proxy, words)
            return html
    logger.info("public_proxy: no working proxy produced an article")
    return None


def _extract_embedded_text(html: str) -> str:
    """Pull article paragraphs out of embedded JSON payloads (WSJ and similar).

    Many modern publishers (notably WSJ) render the article client-side from a
    JSON blob but also embed the full text for SEO crawlers. trafilatura misses
    it because the paragraphs live inside <script> tags. This reconstructs them.
    """
    blocks: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r'"text"\s*:\s*"((?:[^"\\]|\\.)*)"', html):
        try:
            t = m.group(1).encode().decode("unicode_escape", errors="ignore")
        except Exception:
            t = m.group(1)
        t = re.sub(r"\s+", " ", t).strip()
        if len(t) < 80:
            continue
        if t in seen:
            continue
        seen.add(t)
        blocks.append(t)
    if len(blocks) < 3:
        return ""
    return "\n\n".join(blocks)


def _extract_page_text(html: str) -> str:
    """Best-effort main-text extraction combining trafilatura and JSON mining."""
    traf = _extract_main_text(html)
    embedded = _extract_embedded_text(html)
    if len(embedded) > len(traf) + 200:
        return embedded
    return traf or embedded


def _find_amp_url(html: str, base_url: str) -> Optional[str]:
    """Find an <link rel='amphtml'> URL — AMP pages are often un-paywalled."""
    try:
        soup = BeautifulSoup(html[:200000], "lxml")
        link = soup.find("link", rel=lambda v: v and "amphtml" in v)
        if link and link.get("href"):
            href = link["href"].strip()
            if href.startswith("//"):
                href = "https:" + href
            elif href.startswith("/"):
                href = urljoin(base_url, href)
            if href.startswith("http") and href != base_url:
                return href
    except Exception:
        pass
    return None


async def _find_snapshot_urls(
    client: httpx.AsyncClient, url: str, limit: int = 8
) -> list[str]:
    """Collect candidate public-archive captures (Wayback CDX + availability + Memento)."""
    snapshots: list[str] = []
    seen: set[str] = set()

    # CDX matches URLs exactly, so tracking params (?syn=..., ?utm_...) break
    # snapshot lookup. Try the exact URL first, then the canonical form.
    parsed = urlparse(url)
    canonical = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    cdx_urls = [url] if canonical == url else [url, canonical]

    # 1. Wayback CDX search — most reliable for WSJ/FT and returns newest first.
    for cdx_url in cdx_urls:
        if snapshots:
            break
        for attempt in range(2):  # one retry — CDX intermittently times out
            try:
                resp = await client.get(
                    "https://web.archive.org/cdx/search/cdx",
                    params={
                        "url": cdx_url,
                        "output": "json",
                        "fl": "timestamp,statuscode",
                        "filter": "statuscode:200",
                        "limit": str(limit * 2),
                    },
                    timeout=40.0,
                )
                if resp.status_code == 200:
                    rows = resp.json()
                    newest = []
                    for row in rows[1:]:
                        if len(row) >= 2 and str(row[1]).startswith("2"):
                            newest.append(row[0])
                    for ts in reversed(newest):
                        snap = f"https://web.archive.org/web/{ts}id_/{cdx_url}"
                        if snap not in seen:
                            snapshots.append(snap)
                            seen.add(snap)
                            if len(snapshots) >= limit:
                                return snapshots
                    break
            except Exception:
                continue

    # 2. Wayback availability API (closest snapshot).
    for candidate_url in cdx_urls:
        try:
            wb = await _find_wayback_url(client, candidate_url)
            if wb and wb not in seen:
                snapshots.append(wb)
                seen.add(wb)
                break
        except Exception:
            pass

    # 3. Memento aggregator (covers archive.today and regional archives).
    from datetime import datetime, timezone

    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    try:
        response = await client.get(
            f"https://timetravel.mementoweb.org/api/json/{day}/{url}",
            timeout=30.0,
        )
        if response.status_code == 200:
            payload = response.json()
            for group in ("list", "first"):
                for memento in (payload.get("mementos") or {}).get(group, []) or []:
                    uri = memento.get("uri") if isinstance(memento, dict) else None
                    if uri and uri not in seen:
                        snapshots.append(uri)
                        seen.add(uri)
                        if len(snapshots) >= limit * 2:
                            return snapshots
    except Exception:
        pass

    return snapshots


async def _find_wayback_url(client: httpx.AsyncClient, url: str) -> Optional[str]:
    """Return the closest Wayback Machine capture of a URL, if any."""
    try:
        response = await client.get(
            "https://archive.org/wayback/available",
            params={"url": url},
            timeout=20.0,
        )
        response.raise_for_status()
        snapshot = ((response.json().get("archived_snapshots") or {}).get("closest") or {}).get("url")
        return snapshot or None
    except Exception:
        return None


async def _better_text(html: str, current_len: int) -> Optional[str]:
    """Extract page text; return it only if it beats the current best by a margin."""
    text = await asyncio.to_thread(_extract_page_text, html)
    if not text:
        return None
    if _looks_blocked(html, text):
        return None
    if len(text) < current_len + 400:
        return None
    return text


def _markdown_to_html(md: str) -> str:
    """Very small markdown -> HTML converter for reader-proxy output."""
    html_parts = []
    for block in re.split(r"\n{2,}", md.strip()):
        block = block.strip()
        if not block:
            continue
        heading = re.match(r"^(#{1,4})\s+(.*)", block)
        if heading:
            level = len(heading.group(1))
            html_parts.append(f"<h{level}>{html_lib.escape(heading.group(2).strip())}</h{level}>")
        else:
            escaped = html_lib.escape(block)
            escaped = re.sub(
                r"\[([^\]]*)\]\(([^)]*)\)",
                lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>',
                escaped,
            )
            html_parts.append(f"<p>{escaped}</p>")
    return "\n".join(html_parts)


# Short boilerplate lines that jina reader picks up from page chrome.
_NAV_PATTERNS = (
    "accessibility", "skip to", "sign in", "subscribe", "search",
    "open side navigation", "close search", "se connecter", "s'abonner",
    "voir la bourse", "en continu", "le journal", "mes articles",
    "newsletters", "podcasts", "infographies", "le cercle", "recherche",
    "open search", "menu", "log in", "register", "home", "contact",
)


def _process_jina_response(body: str) -> Optional[tuple[str, str]]:
    """Parse jina reader markdown into (title, full_html).

    Returns None when jina itself reports an error (404, CAPTCHA, etc.)
    or when the response is a paywall page with no article body.
    """
    if not body or not body.strip():
        return None

    head = body[:3000]
    if re.search(r"Warning:.*(?:error|CAPTCHA|blocked|forbidden|not found)", head, re.IGNORECASE):
        return None

    # Detect hard paywall pages (FT, WSJ, etc.) where jina only gets the
    # subscription pitch — no article body is present.
    _PAYWALL_MARKERS = (
        "subscribe to unlock", "try unlimited access", "then $75 per month",
        "only $1 for 4 weeks", "complete digital access",
        "explore more offers", "standard digital", "premium digital",
        "subscribe for full access", "to continue reading",
    )
    body_lower = body[:15000].lower()
    paywall_hits = sum(1 for m in _PAYWALL_MARKERS if m in body_lower)
    if paywall_hits >= 3:
        return None

    title = None
    published = None
    lines = body.split("\n")
    content_start = 0
    for i, line in enumerate(lines):
        m = re.match(r"^Title:\s*(.+)", line)
        if m:
            title = m.group(1).strip()
        m2 = re.match(r"^Published Time:\s*(.+)", line)
        if m2:
            published = m2.group(1).strip()
        if re.match(r"^Markdown Content:", line):
            content_start = i + 1
            break

    if content_start > 0:
        content_md = "\n".join(lines[content_start:]).strip()
    else:
        content_md = body.strip()

    paragraphs = [p.strip() for p in re.split(r"\n{2,}", content_md) if p.strip()]

    def _vis_len(p):
        return len(re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", p).strip())

    # Drop leading boilerplate paragraphs (nav chrome, sign-in links, etc.).
    while paragraphs:
        first = paragraphs[0]
        vis = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", first).strip().lower()
        if _vis_len(first) < 100 and any(pat in vis for pat in _NAV_PATTERNS):
            paragraphs.pop(0)
            continue
        if first.startswith("*") and _vis_len(first) < 120:
            paragraphs.pop(0)
            continue
        break

    # Drop trailing boilerplate (footer, "read more", cookie notices, etc.)
    while paragraphs:
        last = paragraphs[-1]
        vis = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", last).strip().lower()
        if _vis_len(last) < 100 and any(pat in vis for pat in _NAV_PATTERNS):
            paragraphs.pop()
            continue
        if last.startswith("*") and _vis_len(last) < 120:
            paragraphs.pop()
            continue
        break

    if not paragraphs:
        return None

    content_html = _markdown_to_html("\n\n".join(paragraphs))
    escaped_title = html_lib.escape(title) if title else ""
    meta_pub = f'<meta property="article:published_time" content="{html_lib.escape(published)}">' if published else ""
    full_html = (
        f"<html><head><title>{escaped_title}</title>"
        f'<meta property="og:title" content="{escaped_title}">'
        f"{meta_pub}"
        f"</head><body><article>{content_html}</article></body></html>"
    )
    return (title or "", full_html)


async def fetch_article(url: str) -> tuple[str, int, str, str, bool, bool, str, Optional[str]]:
    """Fetch public article HTML and classify restricted/blocked responses."""
    timeout = httpx.Timeout(40.0, connect=12.0)
    async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
        html, status, final_url = await _fetch_html(
            client, url, allow_block=True, impersonate=True
        )
        direct_text = await asyncio.to_thread(_extract_page_text, html)
        direct_blocked = status in {401, 403, 451}
        logger.info("direct: url=%s status=%s blocked=%s words=%s", url, status, direct_blocked, len(direct_text.split()))

        if _looks_blocked(html, direct_text) and not direct_blocked:
            raise HTTPException(
                status_code=502,
                detail="The publisher returned an anti-bot or CAPTCHA page instead of the article.",
            )
        restricted = (_looks_restricted(html, direct_text) or direct_blocked) and (
            len(direct_text) < GOOD_TEXT_THRESHOLD
        )

        best_html = html
        best_text = direct_text
        best_url = final_url
        best_status = status
        best_strategy = "direct"
        reader_mode = False
        recovered = len(direct_text) >= GOOD_TEXT_THRESHOLD

        needs_more = lambda: not recovered and (
            len(best_text) < GOOD_TEXT_THRESHOLD or restricted
        )

        # 0. Social-media referrer refetch — many paywalled publishers
        #    (notably FT) serve the full article when the Referer header
        #    looks like a Facebook/Twitter share link.
        if needs_more():
            for ref_label, ref_url in (
                ("social", "https://www.facebook.com/"),
                ("google_news", "https://news.google.com/"),
            ):
                if not needs_more():
                    break
                try:
                    ref_headers = {**IMPERSONATED_HEADERS, "Referer": ref_url}
                    ref_html, ref_status, ref_url_resolved = await _fetch_html(
                        client, final_url, headers=ref_headers, allow_block=True
                    )
                    ref_text = await _better_text(ref_html, len(best_text))
                    logger.info("social_referrer %s: status=%s words=%s", ref_label, ref_status, len(ref_text.split()) if ref_text else 0)
                    if ref_text:
                        best_html, best_text, best_url, best_status, best_strategy = (
                            ref_html, ref_text, ref_url_resolved, ref_status, "social_referrer",
                        )
                        restricted = False
                        recovered = len(best_text) >= GOOD_TEXT_THRESHOLD
                        break
                except HTTPException:
                    continue

        # 0.5 Public-proxy refetch — datacenter IPs (Render/AWS) are blocked
        #     outright by some publishers (FT). A free public proxy provides
        #     a non-blocked exit IP while keeping the social-referer trick.
        if restricted and needs_more():
            try:
                proxied_html = await _fetch_via_public_proxy(final_url)
                if proxied_html:
                    proxied_text = await asyncio.to_thread(_extract_page_text, proxied_html)
                    logger.info("public_proxy step: words=%s", len(proxied_text.split()))
                    if proxied_text and len(proxied_text) > len(best_text) + 400:
                        best_html, best_text, best_status, best_strategy = (
                            proxied_html, proxied_text, 200, "public_proxy",
                        )
                        restricted = False
                        recovered = len(best_text) >= GOOD_TEXT_THRESHOLD
            except Exception as exc:
                logger.warning("public_proxy step failed: %r", exc)

        # 1. AMP version — often served without the paywall.
        if needs_more():
            amp_url = _find_amp_url(html, final_url)
            if amp_url:
                try:
                    amp_html, amp_status, resolved_amp = await _fetch_html(client, amp_url)
                    amp_text = await _better_text(amp_html, len(best_text))
                    if amp_text:
                        best_html, best_text, best_url, best_status, best_strategy = (
                            amp_html, amp_text, resolved_amp, amp_status, "amp",
                        )
                        recovered = len(best_text) >= GOOD_TEXT_THRESHOLD
                except HTTPException:
                    pass

        # 2. Public archive captures (Wayback CDX + availability + Memento).
        if needs_more():
            for snapshot in await _find_snapshot_urls(client, final_url):
                if not needs_more():
                    break
                try:
                    snap_html, snap_status, resolved_snap = await _fetch_html(
                        client, snapshot, impersonate=False
                    )
                    snap_text = await _better_text(snap_html, len(best_text))
                    if snap_text:
                        logger.info("archive: snapshot=%s words=%s", snapshot, len(snap_text.split()))
                        best_html, best_text, best_url, best_status, best_strategy = (
                            snap_html, snap_text, resolved_snap, snap_status, "archive",
                        )
                        recovered = len(best_text) >= GOOD_TEXT_THRESHOLD
                        if recovered:
                            break
                except HTTPException:
                    continue

        # 3. archive.today newest snapshot (works from many networks).
        if needs_more():
            for mirror in ("archive.ph", "archive.today", "archive.vn"):
                if not needs_more():
                    break
                try:
                    at_url = f"https://{mirror}/newest/{final_url}"
                    at_html, at_status, at_resolved = await _fetch_html(
                        client, at_url, impersonate=True
                    )
                    at_text = await _better_text(at_html, len(best_text))
                    if at_text:
                        logger.info("archive_today: mirror=%s status=%s words=%s", mirror, at_status, len(at_text.split()))
                        best_html, best_text, best_url, best_status, best_strategy = (
                            at_html, at_text, at_resolved, at_status, "archive_today",
                        )
                        recovered = len(best_text) >= GOOD_TEXT_THRESHOLD
                        if recovered:
                            break
                except HTTPException:
                    continue

        # 4. Reader proxy (renders the page server-side).
        # NOTE: r.jina.ai refuses browser-like fingerprints (curl_cffi
        # impersonation or rich UA headers) with 403, so fetch it plainly.
        if needs_more():
            reader_url = f"https://r.jina.ai/{final_url}"
            try:
                reader_body, _status, _ = await _fetch_html(client, reader_url, impersonate=False, reader_proxy=True)
                processed = _process_jina_response(reader_body)
                if processed:
                    _jina_title, reader_html = processed
                    reader_text = await _better_text(reader_html, len(best_text))
                    logger.info("jina_reader: status=%s words=%s title=%s", _status, len(reader_text.split()) if reader_text else 0, _jina_title[:50])
                    if reader_text:
                        best_html = reader_html
                        best_text = reader_text
                        best_strategy = "jina_reader"
                        reader_mode = True
                        recovered = len(best_text) >= GOOD_TEXT_THRESHOLD
                else:
                    logger.info("jina_reader: status=%s (error/empty response, skipped)", _status)
            except HTTPException:
                pass

        partial = False
        access_status = "public"
        notice = None
        logger.info("fetch done: strategy=%s words=%s status=%s", best_strategy, len(best_text.split()), best_status)
        if direct_blocked and best_strategy == "direct":
            # Graceful degradation: return the title with an honest notice
            # instead of a hard 403 error. The title comes from jina's header
            # (the publisher page itself is blocked and carries no metadata).
            page_title = ""
            try:
                reader_url = f"https://r.jina.ai/{final_url}"
                rbody, _rstatus, _ = await _fetch_html(
                    client, reader_url, impersonate=False, reader_proxy=True
                )
                m = re.search(r"^Title:\s*(.+)", rbody, re.MULTILINE)
                if m:
                    page_title = m.group(1).strip()
            except Exception:
                pass
            notice = HARD_PAYWALL_NOTICE
            best_html = (
                f"<html><head><title>{html_lib.escape(page_title)}</title></head>"
                f"<body><article><h1>{html_lib.escape(page_title)}</h1>"
                f"<p><em>{html_lib.escape(notice)}</em></p></article></body></html>"
            )
            best_status = 403
            partial = True
            access_status = "restricted_preview"
            logger.info("fetch done: all sources blocked, returning graceful notice")
            return (
                best_html,
                best_status,
                best_url,
                best_strategy,
                reader_mode,
                partial,
                access_status,
                notice,
            )

        # Detect when the "recovered" text is actually paywall/subscription
        # pitch rather than real article content (common with FT on Wayback).
        _PAYWALL_TEXT_MARKERS = (
            "subscribe to unlock", "try unlimited access", "complete digital access",
            "explore more offers", "standard digital", "premium digital",
            "save 40%", "save now on essential", "then $75 per month",
            "only $1 for 4 weeks",
        )
        best_lower = best_text.lower()
        paywall_text_hits = sum(1 for m in _PAYWALL_TEXT_MARKERS if m in best_lower)
        is_paywall_pitch = paywall_text_hits >= 2 and len(best_text.split()) < 400

        if is_paywall_pitch:
            access_status = "restricted_preview"
            partial = True
            notice = HARD_PAYWALL_NOTICE
        elif restricted and best_strategy == "direct":
            partial = True
            access_status = "restricted_preview"
            notice = RESTRICTED_NOTICE
        elif restricted:
            access_status = "recovered"
            notice = RECOVERED_NOTICE
        elif not best_text.strip():
            notice = "The page loaded, but no readable article body was found."
        return (
            best_html,
            best_status,
            best_url,
            best_strategy,
            reader_mode,
            partial,
            access_status,
            notice,
        )


def sanitize_html_for_display(raw_html: str) -> str:
    """Extract article HTML via readability, then sanitize for safe iframe display."""
    from lxml.html import document_fromstring, tostring
    from lxml.html.clean import Cleaner

    try:
        article_html = ReadabilityDocument(raw_html).summary()
    except Exception:
        article_html = raw_html

    try:
        tree = document_fromstring(article_html or "<article></article>")
    except Exception:
        tree = document_fromstring("<article></article>")
    cleaner = Cleaner(
        scripts=True,
        javascript=True,
        embedded=True,
        frames=True,
        forms=True,
        meta=False,
        page_structure=False,
        processing_instructions=True,
        remove_unknown_tags=False,
        safe_attrs_only=True,
        style=False,
        inline_style=False,
        links=False,
        add_nofollow=True,
    )
    cleaned = cleaner.clean_html(tree)
    return tostring(cleaned, encoding="unicode")


def _extract_meta_fallback(html: str) -> dict:
    """Extract article metadata from Open Graph, HTML, and nested JSON-LD."""
    result = {
        "title": None,
        "author": None,
        "date": None,
        "description": None,
        "sitename": None,
        "language": None,
    }
    try:
        soup = BeautifulSoup(html, "lxml")

        def meta(prop, attr="property"):
            tag = soup.find("meta", {attr: prop})
            return tag["content"].strip() if tag and tag.get("content") else None

        result["title"] = (
            meta("og:title")
            or meta("twitter:title", attr="name")
            or meta("title", attr="name")
            or (soup.title.get_text(strip=True) if soup.title else None)
        )
        result["sitename"] = meta("og:site_name")
        result["description"] = (
            meta("og:description")
            or meta("twitter:description", attr="name")
            or meta("description", attr="name")
        )
        result["author"] = meta("article:author") or meta("author", attr="name")
        result["date"] = (
            meta("article:published_time")
            or meta("article:modified_time")
            or meta("og:updated_time")
            or meta("date", attr="name")
            or meta("pubdate", attr="name")
        )
        if result["date"] and "T" in result["date"]:
            result["date"] = result["date"].split("T")[0]

        # Language from <html lang="..">
        html_tag = soup.find("html")
        if html_tag and html_tag.get("lang"):
            result["language"] = html_tag["lang"].split("-")[0].lower()

        def iter_nodes(value):
            if isinstance(value, dict):
                yield value
                for nested in value.values():
                    if isinstance(nested, (dict, list)):
                        yield from iter_nodes(nested)
            elif isinstance(value, list):
                for nested in value:
                    yield from iter_nodes(nested)

        for script in soup.find_all("script", type="application/ld+json"):
            try:
                data = json.loads(script.string or "")
            except Exception:
                continue
            for node in iter_nodes(data):
                node_type = node.get("@type", "")
                if isinstance(node_type, list):
                    node_type = " ".join(str(item) for item in node_type)
                if "article" not in str(node_type).lower() and not any(
                    key in node for key in ("headline", "datePublished", "articleBody")
                ):
                    continue

                result["title"] = result["title"] or node.get("headline") or node.get("name")
                result["description"] = result["description"] or node.get("description")

                if not result["author"]:
                    authors = node.get("author") or node.get("creator")
                    if not isinstance(authors, list):
                        authors = [authors] if authors else []
                    names = []
                    for author in authors:
                        if isinstance(author, dict) and author.get("name"):
                            names.append(str(author["name"]))
                        elif isinstance(author, str):
                            names.append(author)
                    if names:
                        result["author"] = ", ".join(dict.fromkeys(names))

                if not result["date"]:
                    published = node.get("datePublished") or node.get("dateCreated")
                    if published:
                        result["date"] = str(published).split("T")[0]

                if not result["sitename"]:
                    publisher = node.get("publisher")
                    if isinstance(publisher, dict):
                        result["sitename"] = publisher.get("name")
    except Exception:
        pass
    return result


def _clean_extracted_text(text: str) -> str:
    """Remove URLs, image references, markdown link/image syntax, and other artifacts."""
    text = re.sub(r"!\[(?:[^\[\]]|\[[^\]]*\])*\]\([^)]*\)", "", text)
    text = re.sub(r"\[((?:[^\[\]]|\[[^\]]*\])*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"https?://\S+", "", text)
    text = re.sub(r"www\.\S+", "", text)
    text = re.sub(r"\(/wiki/[^)]*\)", "", text)
    text = re.sub(r"\b\S+\.(jpg|jpeg|png|gif|webp|svg|bmp|ico)\b", "", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)

    # trafilatura emits one block (paragraph / heading / list item) per line.
    # Treat each surviving line as its own paragraph so the reader can render
    # proper <p> breaks (v2 separates blocks with single "\n", v1 used "\n\n").
    blocks = []
    for line in text.split("\n"):
        cleaned = re.sub(r"  +", " ", line).strip()
        if cleaned and not re.match(r"^[\s\-_=|*#>]+$", cleaned):
            blocks.append(cleaned)
    return "\n\n".join(blocks).strip()


def _detect_language(text: str) -> Optional[str]:
    """Best-effort language detection from a text sample."""
    sample = text[:2000].strip()
    if len(sample) < 20:
        return None
    try:
        import py3langid
        lang, _ = py3langid.classify(sample)
        return lang
    except Exception:
        return None


def _chunk_text(text: str, max_size: int = 4500) -> list[str]:
    """Split text into chunks at paragraph boundaries, falling back to sentences."""
    paragraphs = text.split("\n\n")
    chunks: list[str] = []
    current = ""

    for para in paragraphs:
        if len(current) + len(para) + 2 <= max_size:
            current = f"{current}\n\n{para}" if current else para
        else:
            if current:
                chunks.append(current)
            if len(para) > max_size:
                sentences = re.split(r"(?<=[.!?])\s+", para)
                current = ""
                for sent in sentences:
                    if len(current) + len(sent) + 1 <= max_size:
                        current = f"{current} {sent}" if current else sent
                    else:
                        if current:
                            chunks.append(current)
                        current = sent
            else:
                current = para

    if current:
        chunks.append(current)
    return chunks

# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

def sanitize_reader_html(raw_html: str) -> str:
    """Sanitize already-processed reader-proxy HTML for iframe display.

    Unlike sanitize_html_for_display, this skips readability (which can
    destroy the simple <article> structure from jina markdown) and just
    cleans the article element with lxml.
    """
    from lxml.html import document_fromstring, tostring
    from lxml.html.clean import Cleaner

    try:
        tree = document_fromstring(raw_html)
    except Exception:
        return raw_html

    article = tree.find(".//article")
    if article is not None:
        subtree = article
    else:
        subtree = tree

    cleaner = Cleaner(
        scripts=True, javascript=True, embedded=True, frames=True,
        forms=True, meta=False, page_structure=False,
        processing_instructions=True, remove_unknown_tags=False,
        safe_attrs_only=True, style=False, inline_style=False,
        links=False, add_nofollow=True,
    )
    cleaned = cleaner.clean_html(subtree)
    return tostring(cleaned, encoding="unicode")


@app.post("/api/fetch", response_model=FetchResponse)
async def api_fetch(req: FetchRequest):
    (
        html,
        status,
        final_url,
        strategy,
        reader_mode,
        partial,
        access_status,
        notice,
    ) = await fetch_article(req.url)
    if reader_mode:
        clean_html = await asyncio.to_thread(sanitize_reader_html, html)
    else:
        clean_html = await asyncio.to_thread(sanitize_html_for_display, html)
    # If readability produced almost nothing, build clean HTML from the
    # extracted text so the user still sees the recovered article body.
    if len(clean_html) < 500 and access_status in ("recovered", "restricted_preview", "public"):
        extracted = await asyncio.to_thread(_extract_page_text, html)
        if extracted and len(extracted.strip()) > 50:
            paras = "\n".join(
                f"<p>{html_lib.escape(p.strip())}</p>"
                for p in re.split(r"\n{2,}", extracted.strip())
                if p.strip()
            )
            clean_html = f"<article>{paras}</article>"
    # When the content is a paywall pitch (not real article body), replace
    # the iframe content with just the title so the user isn't misled.
    if access_status == "restricted_preview" and notice and "hard paywall" in notice:
        meta = _extract_meta_fallback(html)
        title = meta.get("title") or ""
        clean_html = (
            f'<article><h1>{html_lib.escape(title)}</h1>'
            f"<p><em>{html_lib.escape(notice)}</em></p></article>"
        )
    return FetchResponse(
        html=html,
        clean_html=clean_html,
        status_code=status,
        final_url=final_url,
        strategy_used=strategy,
        reader_mode=reader_mode,
        partial=partial,
        access_status=access_status,
        notice=notice,
    )


@app.post("/api/extract", response_model=ExtractResponse)
async def api_extract(req: ExtractRequest):
    result = await asyncio.to_thread(
        trafilatura.bare_extraction,
        req.html,
        url=req.url,
        include_formatting=False,
        include_links=False,
        include_tables=True,
        include_comments=False,
        favor_recall=True,
    )
    if result is None:
        # Tiny or synthetic pages (e.g. paywall notices) — fall back to the
        # visible text instead of failing the UI flow with a 422.
        meta = _extract_meta_fallback(req.html)
        try:
            visible = BeautifulSoup(req.html[:250000], "lxml").get_text(" ", strip=True)
        except Exception:
            visible = ""
        if not visible.strip():
            raise HTTPException(status_code=422, detail="Could not extract article content")
        language = await asyncio.to_thread(_detect_language, visible)
        if language:
            language = language.split("-")[0].lower()
        word_count = len(visible.split())
        return ExtractResponse(
            title=meta.get("title"),
            author=meta.get("author"),
            date=meta.get("date"),
            text=visible,
            description=meta.get("description"),
            sitename=meta.get("sitename"),
            language=language,
            language_name=LANG_NAMES.get(language) if language else None,
            word_count=word_count,
            reading_minutes=max(1, round(word_count / 220)) if word_count else 0,
            source_url=req.url,
        )

    # trafilatura v1.x returns a dict; v2.x returns a Document object — handle both
    if isinstance(result, dict):
        raw_text    = result.get("text", "") or ""
        title       = result.get("title")
        author      = result.get("author")
        date        = result.get("date")
        description = result.get("description")
        sitename    = result.get("sitename")
        language    = result.get("language")
    else:
        raw_text    = getattr(result, "text", "") or ""
        title       = getattr(result, "title", None)
        author      = getattr(result, "author", None)
        date        = getattr(result, "date", None)
        description = getattr(result, "description", None)
        sitename    = getattr(result, "sitename", None)
        language    = getattr(result, "language", None)

    meta = _extract_meta_fallback(req.html)
    title    = title    or meta.get("title")
    author   = author   or meta.get("author")
    date     = date     or meta.get("date")
    description = description or meta.get("description")
    sitename = sitename or meta.get("sitename")
    language = language or meta.get("language")

    cleaned_text = _clean_extracted_text(raw_text)

    # trafilatura misses article text embedded in JSON payloads (e.g. WSJ).
    # Always try mining <script> JSON for paragraph strings and use the
    # longer result.
    embedded = _extract_embedded_text(req.html)
    if len(embedded) > len(cleaned_text) + 200:
        cleaned_text = _clean_extracted_text(embedded)

    # Full publisher pages (e.g. FT fetched via proxy) can confuse bare
    # extraction into returning the subscription pitch. The combined
    # extractor used by /api/fetch handles these better — prefer it when it
    # finds substantially more text.
    combined = await asyncio.to_thread(_extract_page_text, req.html)
    if len(combined) > len(cleaned_text) + 200:
        cleaned_text = _clean_extracted_text(combined)

    if not language:
        language = await asyncio.to_thread(_detect_language, cleaned_text)
    if language:
        language = language.split("-")[0].lower()

    word_count = len(cleaned_text.split())
    reading_minutes = max(1, round(word_count / 220)) if word_count else 0

    return ExtractResponse(
        title=title,
        author=author,
        date=date,
        text=cleaned_text,
        description=description,
        sitename=sitename,
        language=language,
        language_name=LANG_NAMES.get(language) if language else None,
        word_count=word_count,
        reading_minutes=reading_minutes,
        source_url=req.url,
    )


@app.post("/api/translate", response_model=TranslateResponse)
async def api_translate(req: TranslateRequest):
    text = req.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="No text to translate")

    translator = GoogleTranslator(source=req.source_lang, target=req.target_lang)

    if len(text) <= 4500:
        translated = await asyncio.to_thread(translator.translate, text)
        return TranslateResponse(
            translated_text=translated,
            source_lang=req.source_lang,
            target_lang=req.target_lang,
        )

    chunks = _chunk_text(text)
    translated_chunks: list[str] = []
    for chunk in chunks:
        result = await asyncio.to_thread(translator.translate, chunk)
        translated_chunks.append(result or "")

    return TranslateResponse(
        translated_text="\n\n".join(translated_chunks),
        source_lang=req.source_lang,
        target_lang=req.target_lang,
    )

# ---------------------------------------------------------------------------
# Serve frontend
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def root():
    index = Path(__file__).parent / "static" / "index.html"
    return HTMLResponse(
        content=index.read_text(encoding="utf-8"),
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

# ---------------------------------------------------------------------------
# Global error handler
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {str(exc)}"},
    )

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=port == 8000)
