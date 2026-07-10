import asyncio
import html as html_lib
import ipaddress
import json
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


async def _fetch_html(client: httpx.AsyncClient, url: str) -> tuple[str, int, str]:
    """Fetch HTML with redirect validation and a bounded response size."""
    current = await _validate_public_url(url)
    for _ in range(6):
        response = await client.get(current, headers=REQUEST_HEADERS, follow_redirects=False)
        if response.status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get("location")
            if not location:
                raise HTTPException(status_code=502, detail="Publisher returned an invalid redirect")
            current = await _validate_public_url(urljoin(current, location))
            continue

        if response.status_code in {401, 403, 451}:
            raise HTTPException(
                status_code=403,
                detail="The publisher blocked automated access. Open the original article or paste text you are authorized to read.",
            )
        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"Publisher returned HTTP {response.status_code}")

        content_type = response.headers.get("content-type", "").lower()
        if (
            content_type
            and "html" not in content_type
            and "xml" not in content_type
            and "text/plain" not in content_type
        ):
            raise HTTPException(status_code=415, detail="The URL did not return an HTML article")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise HTTPException(status_code=413, detail="The article page is too large to process")
        return response.text, response.status_code, str(response.url)

    raise HTTPException(status_code=502, detail="Publisher redirected too many times")


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
            html_parts.append(f"<p>{html_lib.escape(block)}</p>")
    return "\n".join(html_parts)


async def fetch_article(url: str) -> tuple[str, int, str, str, bool, bool, str, Optional[str]]:
    """Fetch public article HTML and classify restricted/blocked responses."""
    timeout = httpx.Timeout(30.0, connect=12.0)
    async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
        html, status, final_url = await _fetch_html(client, url)
        direct_text = await asyncio.to_thread(_extract_main_text, html)

        if _looks_blocked(html, direct_text):
            raise HTTPException(
                status_code=502,
                detail="The publisher returned an anti-bot or CAPTCHA page instead of the article.",
            )
        if _looks_restricted(html, direct_text):
            return (
                html,
                status,
                final_url,
                "direct",
                False,
                True,
                "restricted_preview",
                RESTRICTED_NOTICE,
            )

        best_html = html
        best_text = direct_text
        best_url = final_url
        best_status = status
        best_strategy = "direct"
        reader_mode = False

        if len(direct_text) < GOOD_TEXT_THRESHOLD:
            amp_url = _find_amp_url(html, final_url)
            if amp_url:
                try:
                    amp_html, amp_status, resolved_amp = await _fetch_html(client, amp_url)
                    amp_text = await asyncio.to_thread(_extract_main_text, amp_html)
                    if (
                        not _looks_blocked(amp_html, amp_text)
                        and not _looks_restricted(amp_html, amp_text)
                        and len(amp_text) > len(best_text)
                    ):
                        best_html = amp_html
                        best_text = amp_text
                        best_url = resolved_amp
                        best_status = amp_status
                        best_strategy = "amp"
                except HTTPException:
                    pass

        # This fallback only runs after the publisher page was classified as
        # public. Restricted previews are returned above without proxying.
        if len(best_text) < GOOD_TEXT_THRESHOLD:
            reader_url = f"https://r.jina.ai/{final_url}"
            try:
                reader_body, _, _ = await _fetch_html(client, reader_url)
                reader_html = (
                    reader_body
                    if "<" in reader_body[:200]
                    else _markdown_to_html(reader_body)
                )
                reader_text = await asyncio.to_thread(_extract_main_text, reader_html)
                if (
                    not _looks_blocked(reader_html, reader_text)
                    and not _looks_restricted(reader_html, reader_text)
                    and len(reader_text) > len(best_text)
                ):
                    best_html = reader_html
                    best_text = reader_text
                    best_strategy = "jina_reader"
                    reader_mode = True
            except HTTPException:
                pass

        notice = None
        if not best_text.strip():
            notice = "The page loaded, but no readable article body was found."
        return (
            best_html,
            best_status,
            best_url,
            best_strategy,
            reader_mode,
            False,
            "public",
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
    clean_html = await asyncio.to_thread(sanitize_html_for_display, html)
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
    description = description or meta.get("description")
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
