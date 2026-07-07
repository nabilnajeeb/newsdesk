import asyncio
import json
import os
import re
from pathlib import Path
from typing import Optional

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

# A "good" direct fetch yields at least this many characters of real article
# text. Below this we treat the page as a soft paywall / teaser and keep
# trying archive + reader fallbacks to find a fuller copy.
GOOD_TEXT_THRESHOLD = 1800

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

HEADER_STRATEGIES = [
    {
        "name": "googlebot",
        "headers": {
            "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Referer": "https://www.google.com/",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "From": "googlebot(at)googlebot.com",
        },
    },
    {
        "name": "google_chrome",
        "headers": {
            "User-Agent": _BROWSER_UA,
            "Referer": "https://www.google.com/",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            **_SEC_HEADERS,
        },
    },
    {
        "name": "facebook_referrer",
        "headers": {
            "User-Agent": _BROWSER_UA,
            "Referer": "https://www.facebook.com/",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            **_SEC_HEADERS,
        },
    },
    {
        "name": "twitter_referrer",
        "headers": {
            "User-Agent": _BROWSER_UA,
            "Referer": "https://t.co/",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            **_SEC_HEADERS,
        },
    },
    {
        "name": "bingbot",
        "headers": {
            "User-Agent": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
    },
]

STRATEGY_LABELS = {
    "googlebot": "Googlebot",
    "google_chrome": "Google referrer",
    "facebook_referrer": "Facebook referrer",
    "twitter_referrer": "Twitter referrer",
    "bingbot": "Bingbot",
    "archive_today": "archive.today",
    "jina_reader": "Reader proxy",
    "wayback_machine": "Wayback Machine",
}

# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def _quick_text_len(html: str) -> int:
    """Return the length of the main article text trafilatura can pull out."""
    if not html:
        return 0
    try:
        txt = trafilatura.extract(
            html, include_comments=False, include_tables=False, favor_recall=True
        )
        return len(txt) if txt else 0
    except Exception:
        return 0


PAYWALL_MARKERS = (
    "subscribe to unlock", "subscribe to read", "complete digital access",
    "for full access", "already a subscriber", "unlimited access",
    "create an account to read", "this article is for subscribers",
    "sign in to read", "register to continue", "to continue reading",
    "become a member", "unlock this article",
)


def _looks_paywalled(text: str) -> bool:
    """Heuristic: short body that contains subscribe/paywall language."""
    if not text:
        return True
    words = len(text.split())
    if words > 250:
        return False
    low = text.lower()
    return any(m in low for m in PAYWALL_MARKERS)


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
                from urllib.parse import urljoin
                href = urljoin(base_url, href)
            if href.startswith("http") and href != base_url:
                return href
    except Exception:
        pass
    return None


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
            html_parts.append(f"<h{level}>{heading.group(2).strip()}</h{level}>")
        else:
            html_parts.append(f"<p>{block}</p>")
    return "\n".join(html_parts)


async def fetch_with_bypass(url: str) -> tuple[str, int, str, str, bool, bool]:
    """
    Fetch article HTML using a cascade of strategies.

    Returns (html, status_code, final_url, strategy_name, reader_mode, partial).

    Direct header strategies come first. If a direct fetch succeeds but only
    yields a teaser (soft paywall), we remember it and keep trying AMP, archive
    and reader-proxy fallbacks, ultimately returning whichever source gave the
    most real article text.
    """
    last_error = "no attempt made"
    best: Optional[tuple[int, tuple]] = None  # (text_len, payload tuple)
    first_direct_html: Optional[str] = None

    def consider(payload: tuple, text_len: int):
        nonlocal best
        if best is None or text_len > best[0]:
            best = (text_len, payload)

    def finalize(payload: tuple) -> tuple:
        """Append the `partial` (paywall-teaser) flag to a 5-tuple payload."""
        text_preview = trafilatura.extract(payload[0], favor_recall=True) or ""
        return (*payload, _looks_paywalled(text_preview))

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(30.0),
        verify=False,
        headers={"Accept-Encoding": "gzip, deflate"},
    ) as client:
        # --- Phase 1: direct fetch with header rotation ---
        for strategy in HEADER_STRATEGIES:
            try:
                resp = await client.get(url, headers=strategy["headers"])
                if resp.status_code < 400 and len(resp.text) > 1000:
                    if first_direct_html is None:
                        first_direct_html = resp.text
                    tlen = await asyncio.to_thread(_quick_text_len, resp.text)
                    payload = (resp.text, resp.status_code, str(resp.url), strategy["name"], False)
                    if tlen >= GOOD_TEXT_THRESHOLD:
                        return (*payload, False)
                    consider(payload, tlen)
                else:
                    last_error = f"{strategy['name']}: HTTP {resp.status_code}"
            except httpx.HTTPError as e:
                last_error = f"{strategy['name']}: {e}"
                continue

        # --- Phase 1b: AMP version (often served without the paywall) ---
        amp_url = _find_amp_url(first_direct_html, url) if first_direct_html else None
        if amp_url:
            try:
                resp = await client.get(amp_url, headers=HEADER_STRATEGIES[1]["headers"])
                if resp.status_code == 200 and len(resp.text) > 1000:
                    tlen = await asyncio.to_thread(_quick_text_len, resp.text)
                    payload = (resp.text, 200, str(resp.url), "google_chrome", False)
                    if tlen >= GOOD_TEXT_THRESHOLD:
                        return (*payload, False)
                    consider(payload, tlen)
            except httpx.HTTPError as e:
                last_error = f"amp: {e}"

        # --- Phase 2: archive.today (great for FT / WSJ / Bloomberg) ---
        try:
            arch_url = f"https://archive.ph/newest/{url}"
            resp = await client.get(
                arch_url,
                headers={"User-Agent": _BROWSER_UA, "Accept-Language": "en-US,en;q=0.9"},
                timeout=25.0,
            )
            if resp.status_code in (200, 429) and len(resp.text) > 1500:
                tlen = await asyncio.to_thread(_quick_text_len, resp.text)
                consider((resp.text, 200, str(resp.url), "archive_today", False), tlen)
                if tlen >= GOOD_TEXT_THRESHOLD:
                    return finalize(best[1])
            else:
                last_error = f"archive.today: HTTP {resp.status_code}"
        except httpx.HTTPError as e:
            last_error = f"archive.today: {e}"

        # --- Phase 3: Jina reader proxy (renders JS, strips paywalls) ---
        try:
            jina_url = f"https://r.jina.ai/{url}"
            resp = await client.get(
                jina_url,
                headers={
                    "User-Agent": _BROWSER_UA,
                    "X-Return-Format": "html",
                    "Accept": "text/html,*/*",
                },
                timeout=45.0,
            )
            if resp.status_code == 200 and len(resp.text) > 500:
                body = resp.text
                looks_like_html = "<" in body[:200]
                html_body = body if looks_like_html else _markdown_to_html(body)
                tlen = await asyncio.to_thread(_quick_text_len, html_body)
                if tlen < 200:  # trafilatura found little; treat raw as the text
                    html_body = f"<html><body><article>{html_body}</article></body></html>"
                    tlen = len(re.sub(r"<[^>]+>", "", html_body))
                consider((html_body, 200, url, "jina_reader", True), tlen)
                if tlen >= GOOD_TEXT_THRESHOLD:
                    return finalize(best[1])
            else:
                last_error = f"reader proxy: HTTP {resp.status_code}"
        except httpx.HTTPError as e:
            last_error = f"reader proxy: {e}"

        # --- Phase 4: Wayback Machine ---
        try:
            wb_api = f"https://archive.org/wayback/available?url={url}"
            wb_resp = await client.get(wb_api, timeout=12.0)
            if wb_resp.status_code == 200:
                snap = (wb_resp.json()
                        .get("archived_snapshots", {})
                        .get("closest", {})
                        .get("url"))
                if snap:
                    snap_resp = await client.get(
                        snap, headers={"User-Agent": _BROWSER_UA}, timeout=25.0
                    )
                    if snap_resp.status_code == 200 and len(snap_resp.text) > 1000:
                        tlen = await asyncio.to_thread(_quick_text_len, snap_resp.text)
                        consider((snap_resp.text, 200, url, "wayback_machine", False), tlen)
        except Exception as e:
            last_error = f"wayback: {e}"

    if best is not None:
        return finalize(best[1])

    raise HTTPException(status_code=502, detail=f"All fetch strategies failed. Last error: {last_error}")


def sanitize_html_for_display(raw_html: str) -> str:
    """Extract article HTML via readability, then sanitize for safe iframe display."""
    doc = ReadabilityDocument(raw_html)
    article_html = doc.summary()

    from lxml.html import document_fromstring, tostring
    from lxml.html.clean import Cleaner

    tree = document_fromstring(article_html)
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
    """Extract title/author/date/sitename/language from OG, meta tags and JSON-LD."""
    result = {"title": None, "author": None, "date": None, "sitename": None, "language": None}
    try:
        soup = BeautifulSoup(html, "lxml")

        def meta(prop, attr="property"):
            tag = soup.find("meta", {attr: prop})
            return tag["content"].strip() if tag and tag.get("content") else None

        result["title"] = (
            meta("og:title")
            or meta("twitter:title")
            or meta("title", attr="name")
            or (soup.title.get_text(strip=True) if soup.title else None)
        )
        result["sitename"] = meta("og:site_name")
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

        if not result["author"] or not result["date"]:
            for script in soup.find_all("script", type="application/ld+json"):
                try:
                    data = json.loads(script.string or "")
                    if isinstance(data, list):
                        data = data[0]
                    if not isinstance(data, dict):
                        continue
                    if not result["author"]:
                        af = data.get("author") or data.get("creator")
                        if isinstance(af, dict):
                            result["author"] = af.get("name")
                        elif isinstance(af, list) and af:
                            result["author"] = af[0].get("name") if isinstance(af[0], dict) else str(af[0])
                        elif isinstance(af, str):
                            result["author"] = af
                    if not result["date"]:
                        rd = data.get("datePublished") or data.get("dateCreated")
                        if rd:
                            result["date"] = rd.split("T")[0] if "T" in rd else rd
                except Exception:
                    continue
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

@app.post("/api/fetch", response_model=FetchResponse)
async def api_fetch(req: FetchRequest):
    html, status, final_url, strategy, reader_mode, partial = await fetch_with_bypass(req.url)
    clean_html = await asyncio.to_thread(sanitize_html_for_display, html)
    return FetchResponse(
        html=html,
        clean_html=clean_html,
        status_code=status,
        final_url=final_url,
        strategy_used=strategy,
        reader_mode=reader_mode,
        partial=partial,
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
        raise HTTPException(status_code=422, detail="Could not extract article content")

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
    sitename = sitename or meta.get("sitename")
    language = language or meta.get("language")

    cleaned_text = _clean_extracted_text(raw_text)

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
    return HTMLResponse(content=index.read_text(encoding="utf-8"))


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
