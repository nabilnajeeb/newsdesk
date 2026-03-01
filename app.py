import asyncio
import os
import re
from pathlib import Path
from typing import Optional

import httpx
import trafilatura
import uvicorn
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
# Paywall bypass header strategies
# ---------------------------------------------------------------------------

HEADER_STRATEGIES = [
    {
        "name": "googlebot",
        "headers": {
            "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Referer": "https://www.google.com/",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Cache-Control": "no-cache",
        },
    },
    {
        "name": "google_chrome",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Referer": "https://www.google.com/",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        },
    },
    {
        "name": "facebook_referrer",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Referer": "https://www.facebook.com/",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        },
    },
    {
        "name": "twitter_referrer",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Referer": "https://t.co/",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        },
    },
    {
        "name": "bingbot",
        "headers": {
            "User-Agent": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    },
]

# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

async def fetch_with_bypass(url: str) -> tuple[str, int, str, str]:
    """Try each header strategy, then cached/archived versions as fallbacks."""
    last_error = None
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(30.0),
        verify=False,
    ) as client:
        # --- Phase 1: direct fetch with header rotation ---
        for strategy in HEADER_STRATEGIES:
            try:
                response = await client.get(url, headers=strategy["headers"])
                if response.status_code < 400 and len(response.text) > 1000:
                    return (
                        response.text,
                        response.status_code,
                        str(response.url),
                        strategy["name"],
                    )
                last_error = f"Status {response.status_code}, body length {len(response.text)}"
            except httpx.HTTPError as e:
                last_error = str(e)
                continue

        # --- Phase 2: cached / archived fallbacks ---
        chrome_headers = HEADER_STRATEGIES[1]["headers"]

        # Google Cache
        try:
            cache_url = f"https://webcache.googleusercontent.com/search?q=cache:{url}"
            response = await client.get(cache_url, headers=chrome_headers)
            if response.status_code == 200 and len(response.text) > 1000:
                return (response.text, 200, url, "google_cache")
            last_error = f"Google Cache: Status {response.status_code}"
        except httpx.HTTPError as e:
            last_error = f"Google Cache error: {e}"

        # Wayback Machine (latest snapshot)
        try:
            wb_api = f"https://archive.org/wayback/available?url={url}"
            wb_resp = await client.get(wb_api, timeout=10)
            if wb_resp.status_code == 200:
                wb_data = wb_resp.json()
                snapshot_url = (wb_data.get("archived_snapshots", {})
                                      .get("closest", {})
                                      .get("url"))
                if snapshot_url:
                    snap_resp = await client.get(snapshot_url, headers=chrome_headers)
                    if snap_resp.status_code == 200 and len(snap_resp.text) > 1000:
                        return (snap_resp.text, 200, url, "wayback_machine")
                    last_error = f"Wayback snapshot: Status {snap_resp.status_code}"
                else:
                    last_error = "Wayback Machine: no snapshot found"
        except (httpx.HTTPError, Exception) as e:
            last_error = f"Wayback Machine error: {e}"

    raise HTTPException(status_code=502, detail=f"All fetch strategies failed. Last error: {last_error}")


def sanitize_html_for_display(raw_html: str) -> str:
    """Extract article HTML via readability, then sanitize for safe iframe display."""
    doc = ReadabilityDocument(raw_html)
    article_html = doc.summary()

    # Use lxml Cleaner to strip dangerous elements
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


def _clean_extracted_text(text: str) -> str:
    """Remove URLs, image references, markdown link/image syntax, and other artifacts."""
    # Remove markdown image syntax: ![alt](url)
    text = re.sub(r"!\[(?:[^\[\]]|\[[^\]]*\])*\]\([^)]*\)", "", text)
    # Remove markdown links but keep the label: [text](url) -> text
    # Handles nested brackets like [[1]](#cite_note-1)
    text = re.sub(r"\[((?:[^\[\]]|\[[^\]]*\])*)\]\([^)]*\)", r"\1", text)
    # Remove standalone URLs (http/https)
    text = re.sub(r"https?://\S+", "", text)
    # Remove bare www. URLs
    text = re.sub(r"www\.\S+", "", text)
    # Remove relative wiki/path style links that might remain
    text = re.sub(r"\(/wiki/[^)]*\)", "", text)
    # Remove leftover image file references (e.g. image.jpg, photo.png)
    text = re.sub(r"\b\S+\.(jpg|jpeg|png|gif|webp|svg|bmp|ico)\b", "", text, flags=re.IGNORECASE)
    # Remove HTML-style tags that may have leaked through
    text = re.sub(r"<[^>]+>", "", text)
    # Remove lines that are just whitespace or single special characters
    lines = text.split("\n")
    cleaned_lines = []
    for line in lines:
        stripped = line.strip()
        # Skip lines that are only punctuation/symbols/whitespace
        if stripped and not re.match(r"^[\s\-_=|*#>]+$", stripped):
            cleaned_lines.append(line)
    text = "\n".join(cleaned_lines)
    # Collapse multiple blank lines into double newlines
    text = re.sub(r"\n{3,}", "\n\n", text)
    # Remove leading/trailing whitespace on each line, collapse spaces
    lines = text.split("\n")
    lines = [re.sub(r"  +", " ", l).strip() for l in lines]
    text = "\n".join(lines)
    return text.strip()


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
    html, status, final_url, strategy = await fetch_with_bypass(req.url)
    clean_html = await asyncio.to_thread(sanitize_html_for_display, html)
    return FetchResponse(
        html=html,
        clean_html=clean_html,
        status_code=status,
        final_url=final_url,
        strategy_used=strategy,
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

    cleaned_text = _clean_extracted_text(raw_text)

    return ExtractResponse(
        title=title,
        author=author,
        date=date,
        text=cleaned_text,
        description=description,
        sitename=sitename,
        language=language,
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
        translated_chunks.append(result)

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
