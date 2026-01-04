# -*- coding: utf-8 -*-
"""
A practical Douyin (抖音) share-link checker that aims to be:
- Stable: input validation, SSRF-safe domain allowlist, bounded cache, rate limiting
- Reliable: better "invalid" detection (200 but '内容不存在/已删除/下架'), avoid "404" false positives
- Honest about uncertainty: explicitly surfaces "blocked" (anti-bot / captcha / access denied) vs "maybe"
- Friendly for non-technical users: works with index.html UI, supports batching from the front-end

Status terms:
- valid: strong evidence the content exists (IDs extracted)
- invalid: strong evidence the content does not exist / removed
- blocked: strong evidence access is restricted (anti-bot / captcha / 403/429)
- maybe: inconclusive (200 without IDs and without clear not-found or blocked signals)
- unknown: network/server errors
"""

import csv
import io
import os
import re
import time
import random
import logging
from collections import OrderedDict
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse, urljoin, urlunparse

import requests
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, HTMLResponse, PlainTextResponse, Response


# ------------------------
# App & Logging
# ------------------------

app = FastAPI(title="Douyin Link Checker", version="2.0.0")

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
logger = logging.getLogger("douyin_checker")


# ------------------------
# Config (safe defaults)
# ------------------------

# Security: only fetch from these domains to avoid SSRF abuse
ALLOWED_DOMAIN_SUFFIXES = ("douyin.com", "iesdouyin.com")

# Request control
MAX_LINKS_PER_REQUEST = int(os.getenv("MAX_LINKS_PER_REQUEST", "25"))  # keep requests short on Render
MAX_URL_LENGTH = int(os.getenv("MAX_URL_LENGTH", "2048"))

DEFAULT_POLICY = os.getenv("DEFAULT_POLICY", "conservative")  # conservative|strict

DEFAULT_SLEEP_S = float(os.getenv("DEFAULT_SLEEP_S", "0.6"))  # per-link sleep (server-side)
DEFAULT_JITTER_S = float(os.getenv("DEFAULT_JITTER_S", "0.25"))  # random 0..jitter to look less "bursty"

CONNECT_TIMEOUT_S = float(os.getenv("CONNECT_TIMEOUT_S", "5"))
READ_TIMEOUT_S = float(os.getenv("READ_TIMEOUT_S", "12"))

RETRY_TIMES = int(os.getenv("RETRY_TIMES", "1"))  # 1 => total 2 attempts
RETRY_BACKOFF_S = float(os.getenv("RETRY_BACKOFF_S", "1.2"))

# Cache (LRU + TTL)
CACHE_TTL_S = int(os.getenv("CACHE_TTL_S", "3600"))
CACHE_MAX_ITEMS = int(os.getenv("CACHE_MAX_ITEMS", "2000"))

# Simple rate limit (links/min per IP). Prevents abuse when you share the tool publicly.
RATE_LIMIT_LINKS_PER_MIN = int(os.getenv("RATE_LIMIT_LINKS_PER_MIN", "200"))


# ------------------------
# Regex patterns
# ------------------------

# URL type/id extraction
URL_KIND_PATTERNS = [
    ("share_video", re.compile(r"/share/video/(\d+)", re.I)),
    ("share_note", re.compile(r"/share/note/(\d+)", re.I)),
    ("video", re.compile(r"/video/(\d+)", re.I)),
    ("note", re.compile(r"/note/(\d+)", re.I)),
]

# IDs in HTML (be permissive: quote optional, numeric/string)
AWEME_ID_PATTERNS = [
    re.compile(r'"aweme_id"\s*:\s*"?(\d+)"?', re.I),
    re.compile(r'"awemeId"\s*:\s*"?(\d+)"?', re.I),
]
ITEM_ID_PATTERNS = [
    re.compile(r'"itemId"\s*:\s*"?(\d+)"?', re.I),
    re.compile(r'"item_id"\s*:\s*"?(\d+)"?', re.I),
]
NOTE_ID_PATTERNS = [
    re.compile(r'"note_id"\s*:\s*"?(\d+)"?', re.I),
    re.compile(r'"noteId"\s*:\s*"?(\d+)"?', re.I),
]

# Follow meta refresh / simple JS redirect once (some share pages do this)
META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\']+)["\']',
    re.I,
)
JS_REDIRECT_RE = re.compile(
    r'(?:window\.)?location\.href\s*=\s*["\']([^"\']+)["\']',
    re.I,
)

# Not-found detection
NF_STRONG_PHRASES = [
    "您访问的内容不存在",
    "你访问的内容不存在",
    "访问的内容不存在",
    "该内容不存在",
    "该视频不存在",
    "该作品不存在",
    "该内容已删除",
    "内容已删除",
    "视频已删除",
    "作品已删除",
    "已下架",
    "内容不可见",
    "无法查看",
    "暂时无法查看",
    "不可观看",
    "已失效",
]

NF_ENTITY = ["内容", "视频", "作品", "页面", "当前内容"]
NF_STATE = ["不存在", "已删除", "删除", "下架", "失效", "不可见", "无法查看", "不可观看", "无权查看"]

# English: avoid bare "404" false positives
NF_EN_STRONG = [
    "404 not found",
    "page not found",
]
NF_EN_WEAK = "not found"  # require context words nearby

# Blocked / anti-bot detection
BLOCK_HINTS = [
    "captcha",
    "verify",
    "verification",
    "challenge",
    "geetest",
    "安全校验",
    "安全验证",
    "人机验证",
    "验证码",
    "请求频繁",
    "访问受限",
    "访问异常",
    "系统繁忙",
    "风险",
    "too many requests",
    "rate limit",
    "access denied",
]

# If HTML is extremely short and we have no IDs and no not-found hints, it's likely blocked/shell
MIN_HTML_LEN_SUSPECT = int(os.getenv("MIN_HTML_LEN_SUSPECT", "1800"))


# ------------------------
# Global HTTP session
# ------------------------

_session = requests.Session()
_session.max_redirects = 10  # safety
_adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=20, max_retries=0)
_session.mount("https://", _adapter)
_session.mount("http://", _adapter)

MOBILE_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 "
    "Mobile/15E148 Safari/604.1"
)

DEFAULT_HEADERS = {
    "User-Agent": MOBILE_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Connection": "close",
}


# ------------------------
# LRU TTL Cache
# ------------------------

class LruTtlCache:
    def __init__(self, max_items: int, ttl_s: int):
        self.max_items = max_items
        self.ttl_s = ttl_s
        self._data: "OrderedDict[str, Tuple[float, Dict[str, Any]]]" = OrderedDict()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        now = time.time()
        if key not in self._data:
            return None
        ts, value = self._data[key]
        if now - ts > self.ttl_s:
            del self._data[key]
            return None
        self._data.move_to_end(key, last=True)
        return value

    def set(self, key: str, value: Dict[str, Any]) -> None:
        now = time.time()
        self._data[key] = (now, value)
        self._data.move_to_end(key, last=True)
        while len(self._data) > self.max_items:
            self._data.popitem(last=False)

_cache = LruTtlCache(max_items=CACHE_MAX_ITEMS, ttl_s=CACHE_TTL_S)


# ------------------------
# Simple per-IP rate limiter (links/min)
# ------------------------

_ip_window: Dict[str, List[float]] = {}


def _client_ip(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    if req.client and req.client.host:
        return req.client.host
    return "unknown"


def _rate_limit_check(ip: str, cost_links: int) -> None:
    now = time.time()
    window = _ip_window.get(ip, [])
    window = [t for t in window if now - t < 60.0]
    if len(window) + cost_links > RATE_LIMIT_LINKS_PER_MIN:
        raise HTTPException(status_code=429, detail="Too many requests. Please slow down or split into smaller batches.")
    window.extend([now] * cost_links)
    _ip_window[ip] = window


# ------------------------
# Helpers: URL validation (SSRF-safe)
# ------------------------

_IP_LIT_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _is_allowed_host(host: str) -> bool:
    host = (host or "").strip().lower().strip(".")
    if not host:
        return False
    if _IP_LIT_RE.match(host):
        return False
    return any(host == suf or host.endswith("." + suf) for suf in ALLOWED_DOMAIN_SUFFIXES)


def _normalize_url(u: str) -> Tuple[Optional[str], str]:
    if not u:
        return None, "Empty URL"
    u = u.strip()
    if len(u) > MAX_URL_LENGTH:
        return None, "URL too long"

    if not (u.startswith("http://") or u.startswith("https://")):
        u = "https://" + u

    parsed = urlparse(u)
    scheme = (parsed.scheme or "").lower()

    if scheme not in ("https", "http"):
        return None, "Unsupported scheme"

    # For user-friendliness: upgrade http -> https
    if scheme == "http":
        scheme = "https"

    # reject userinfo like https://user:pass@host/...
    if parsed.username or parsed.password:
        return None, "Unsupported URL format"

    host = parsed.hostname or ""
    if not _is_allowed_host(host):
        return None, "Unsupported domain (only douyin.com / iesdouyin.com allowed)"

    # disallow non-standard ports for safety
    port = parsed.port
    if port not in (None, 80, 443):
        return None, "Unsupported port"

    # normalize to https without explicit 80/443
    if port in (80, 443):
        port = None

    netloc = host if port is None else f"{host}:{port}"

    cleaned = parsed._replace(scheme=scheme, netloc=netloc, fragment="")
    return urlunparse(cleaned), ""


def _detect_kind_and_id(url: str) -> Tuple[str, str]:
    path = urlparse(url).path or ""
    for kind, pat in URL_KIND_PATTERNS:
        m = pat.search(path)
        if m:
            return kind, m.group(1)
    return "unknown", ""


# ------------------------
# Helpers: response text decoding
# ------------------------

def _safe_text(resp: requests.Response) -> str:
    try:
        if not resp.encoding:
            resp.encoding = resp.apparent_encoding
        return resp.text or ""
    except Exception:
        try:
            return (resp.content or b"").decode("utf-8", errors="ignore")
        except Exception:
            return ""


def _normalize_text(text: str) -> str:
    if not text:
        return ""
    low = text.lower()
    low = re.sub(r"\s+", " ", low)
    return low


# ------------------------
# Extraction: IDs
# ------------------------

def _extract_first(patterns: List[re.Pattern], text: str) -> str:
    for p in patterns:
        m = p.search(text)
        if m:
            return m.group(1)
    return ""


def extract_ids(text: str, final_url: str) -> Dict[str, str]:
    aweme_id = _extract_first(AWEME_ID_PATTERNS, text)
    item_id = _extract_first(ITEM_ID_PATTERNS, text)
    note_id = _extract_first(NOTE_ID_PATTERNS, text)

    kind2, url_id_final = _detect_kind_and_id(final_url)
    return {
        "aweme_id": aweme_id,
        "item_id": item_id,
        "note_id": note_id,
        "kind_final": kind2,
        "url_id_final": url_id_final,
    }


# ------------------------
# Detection: not-found & blocked
# ------------------------

def detect_not_found(text: str, has_ids: bool) -> Tuple[bool, str, int]:
    low = _normalize_text(text)
    if not low:
        return False, "", 0

    for p in NF_STRONG_PHRASES:
        if p.lower() in low:
            return True, f"Matched phrase: {p}", 95

    for p in NF_EN_STRONG:
        if p in low:
            return True, f"Matched misc: {p}", 90

    if NF_EN_WEAK in low and ("404" in low or "page" in low or "error" in low):
        return True, "Matched misc: not found (+context)", 75

    hit_entity = next((e for e in NF_ENTITY if e in low), "")
    hit_state = next((s for s in NF_STATE if s in low), "")
    if hit_entity and hit_state:
        return True, f"Matched entity+state: {hit_entity} + {hit_state}", 90

    if (not has_ids) and hit_state:
        if any(k in low for k in ["访问", "查看", "播放", "作品", "视频", "内容"]):
            return True, f"Matched state w/o IDs: {hit_state}", 70

    return False, "", 0


def detect_blocked(resp: Optional[requests.Response], text: str, has_ids: bool, is_not_found: bool) -> Tuple[bool, str, int]:
    if resp is None:
        return False, "", 0

    if resp.status_code in (401, 403):
        return True, f"HTTP {resp.status_code} (blocked)", 95
    if resp.status_code == 429:
        return True, "HTTP 429 (rate limited)", 95

    low = _normalize_text(text)
    for k in BLOCK_HINTS:
        if k in low:
            return True, f"Blocked/verify hint: {k}", 90

    if resp.status_code == 200 and (not has_ids) and (not is_not_found):
        if len(text or "") < MIN_HTML_LEN_SUSPECT:
            return True, f"HTML too short (<{MIN_HTML_LEN_SUSPECT})", 65

    return False, "", 0


# ------------------------
# Fetch (with retry) + optional one-step meta/js redirect follow
# ------------------------

def _sleep_with_jitter(base_s: float) -> None:
    base_s = max(0.0, base_s)
    jitter = random.random() * max(0.0, DEFAULT_JITTER_S)
    time.sleep(base_s + jitter)


def _fetch(url: str, timeout_s: Tuple[float, float]) -> Tuple[Optional[requests.Response], str]:
    last_err = ""
    for attempt in range(RETRY_TIMES + 1):
        try:
            resp = _session.get(
                url,
                headers=DEFAULT_HEADERS,
                timeout=timeout_s,
                allow_redirects=True,
            )
            return resp, ""
        except requests.RequestException as e:
            last_err = f"{type(e).__name__}: {e}"
            if attempt < RETRY_TIMES:
                time.sleep(RETRY_BACKOFF_S * (attempt + 1) + random.random() * 0.3)
                continue
            return None, last_err
    return None, last_err


def _maybe_follow_html_redirect(resp: requests.Response, text: str) -> Tuple[requests.Response, str]:
    if resp is None or resp.status_code != 200:
        return resp, text

    target = ""
    m = META_REFRESH_RE.search(text or "")
    if m:
        target = m.group(1).strip()

    if not target:
        m2 = JS_REDIRECT_RE.search(text or "")
        if m2:
            target = m2.group(1).strip()

    if not target:
        return resp, text

    if target.startswith("//"):
        target = "https:" + target
    elif target.startswith("/"):
        target = urljoin(resp.url, target)
    elif not (target.startswith("http://") or target.startswith("https://")):
        target = urljoin(resp.url, target)

    norm_target, err = _normalize_url(target)
    if err:
        return resp, text

    r2, err2 = _fetch(norm_target, timeout_s=(CONNECT_TIMEOUT_S, READ_TIMEOUT_S))
    if r2 is None:
        return resp, text

    t2 = _safe_text(r2)
    return r2, t2


# ------------------------
# Core: check one URL
# ------------------------

def check_one(url: str, sleep_s: float, timeout_s: Tuple[float, float], policy: str) -> Dict[str, Any]:
    t0 = time.time()

    norm_url, err = _normalize_url(url)
    if err:
        return {
            "original_url": url,
            "normalized_url": "",
            "kind": "unknown",
            "url_id": "",
            "http_status": None,
            "final_url": None,
            "aweme_id": "",
            "item_id": "",
            "note_id": "",
            "validity": "invalid",
            "raw_validity": "invalid",
            "confidence": 90,
            "content_len": 0,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "note": err,
        }

    cached = _cache.get(norm_url)
    if cached:
        out = dict(cached)
        out["cached"] = True
        return out

    _sleep_with_jitter(sleep_s)

    kind, url_id = _detect_kind_and_id(norm_url)

    resp, fetch_err = _fetch(norm_url, timeout_s=timeout_s)
    if resp is None:
        data = {
            "original_url": url,
            "normalized_url": norm_url,
            "kind": kind,
            "url_id": url_id,
            "http_status": None,
            "final_url": None,
            "aweme_id": "",
            "item_id": "",
            "note_id": "",
            "validity": "unknown",
            "raw_validity": "unknown",
            "confidence": 30,
            "content_len": 0,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "note": f"RequestError: {fetch_err}",
        }
        _cache.set(norm_url, data)
        return data

    text = _safe_text(resp)
    resp2, text2 = _maybe_follow_html_redirect(resp, text)
    resp = resp2
    text = text2

    ids = extract_ids(text, resp.url)
    aweme_id = ids["aweme_id"]
    item_id = ids["item_id"]
    note_id = ids["note_id"]

    has_ids = bool(aweme_id or item_id or note_id)

    raw_validity = "maybe"
    confidence = 50
    note = f"HTTP {resp.status_code}"

    if resp.status_code in (404, 410):
        raw_validity, confidence, note = "invalid", 95, "HTTP 404/410"
    elif resp.status_code >= 500:
        raw_validity, confidence, note = "unknown", 40, "Server error (5xx)"
    else:
        is_nf, why_nf, conf_nf = detect_not_found(text, has_ids)
        is_blk, why_blk, conf_blk = detect_blocked(resp, text, has_ids, is_nf)

        if is_nf:
            raw_validity, confidence, note = "invalid", conf_nf, why_nf or "Not found/removed"
        elif has_ids:
            raw_validity, confidence, note = "valid", 95, "Found aweme_id/itemId/note_id"
        elif is_blk:
            raw_validity, confidence, note = "blocked", conf_blk, why_blk or "Blocked/verification"
        else:
            raw_validity, confidence, note = "maybe", 50, "200 OK but no IDs and no clear signals"

    validity = raw_validity
    if policy == "strict":
        if raw_validity in ("blocked", "maybe"):
            validity = "invalid"
            note = f"[strict] {note}"

    data = {
        "original_url": url,
        "normalized_url": norm_url,
        "kind": kind,
        "url_id": url_id,
        "http_status": resp.status_code,
        "final_url": resp.url,
        "aweme_id": aweme_id,
        "item_id": item_id,
        "note_id": note_id,
        "validity": validity,
        "raw_validity": raw_validity,
        "confidence": confidence,
        "content_len": len(text or ""),
        "elapsed_ms": int((time.time() - t0) * 1000),
        "note": note,
    }

    _cache.set(norm_url, data)
    return data


# ------------------------
# Routes
# ------------------------

@app.get("/", response_class=HTMLResponse)
def home():
    path = os.path.join(os.path.dirname(__file__), "index.html")
    if not os.path.exists(path):
        return "<h3>index.html not found</h3>"
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


@app.head("/", include_in_schema=False)
def home_head():
    return Response(status_code=200)


@app.get("/health", response_class=PlainTextResponse, include_in_schema=False)
def health():
    return "ok"


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)


@app.post("/check")
def check_links(
    links: List[str],
    request: Request,
    sleep_s: float = DEFAULT_SLEEP_S,
    timeout_s: float = READ_TIMEOUT_S,
    policy: str = DEFAULT_POLICY,
):
    policy = (policy or "conservative").strip().lower()
    if policy not in ("conservative", "strict"):
        raise HTTPException(status_code=400, detail="policy must be conservative or strict")

    if not isinstance(links, list):
        raise HTTPException(status_code=400, detail="Body must be a JSON array of URLs")
    if len(links) == 0:
        return {"count": 0, "results": []}

    if len(links) > MAX_LINKS_PER_REQUEST:
        raise HTTPException(
            status_code=400,
            detail=f"Too many links in one request (max {MAX_LINKS_PER_REQUEST}). Please split into batches.",
        )

    ip = _client_ip(request)
    _rate_limit_check(ip, cost_links=len(links))

    seen = set()
    cleaned: List[str] = []
    for u in links:
        if not isinstance(u, str):
            continue
        u2 = u.strip()
        if not u2:
            continue
        if u2 in seen:
            continue
        seen.add(u2)
        cleaned.append(u2)

    results = []
    timeout_tuple = (CONNECT_TIMEOUT_S, float(timeout_s))

    for idx, u in enumerate(cleaned, 1):
        res = check_one(u, sleep_s=float(sleep_s), timeout_s=timeout_tuple, policy=policy)
        results.append(res)
        logger.info("check #%s ip=%s validity=%s raw=%s url=%s", idx, ip, res.get("validity"), res.get("raw_validity"), u)

    return {"count": len(results), "results": results}


@app.post("/check_csv")
def check_links_csv(
    links: List[str],
    request: Request,
    sleep_s: float = DEFAULT_SLEEP_S,
    timeout_s: float = READ_TIMEOUT_S,
    policy: str = DEFAULT_POLICY,
):
    payload = check_links(links=links, request=request, sleep_s=sleep_s, timeout_s=timeout_s, policy=policy)
    results = payload["results"]

    output = io.StringIO()
    fieldnames = [
        "original_url",
        "validity",
        "raw_validity",
        "confidence",
        "http_status",
        "kind",
        "url_id",
        "aweme_id",
        "item_id",
        "note_id",
        "final_url",
        "content_len",
        "elapsed_ms",
        "note",
    ]
    w = csv.DictWriter(output, fieldnames=fieldnames)
    w.writeheader()
    for r in results:
        row = {k: r.get(k, "") for k in fieldnames}
        w.writerow(row)

    csv_bytes = output.getvalue().encode("utf-8-sig")
    return StreamingResponse(
        io.BytesIO(csv_bytes),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=douyin_check_result.csv"},
    )
