# -*- coding: utf-8 -*-
import csv
import io
import re
import time
from typing import List, Dict, Any
from urllib.parse import urlparse

import requests
from fastapi import FastAPI
from fastapi.responses import StreamingResponse

app = FastAPI(title="Douyin Link Checker")

MOBILE_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 "
    "Mobile/15E148 Safari/604.1"
)

VIDEO_ID_RE = re.compile(r"/share/video/(\d+)")
AWEME_ID_RE = re.compile(r'"aweme_id"\s*:\s*"(\d+)"')
ITEM_ID_RE = re.compile(r'"itemId"\s*:\s*"(\d+)"')

NOT_FOUND_HINTS = [
    "视频不见了", "内容已删除", "无法查看", "not found", "404",
    "该内容无法查看", "内容不可见", "已失效", "不存在"
]

CACHE_TTL = 3600
cache: Dict[str, Dict[str, Any]] = {}


def extract_video_id(url: str) -> str:
    m = VIDEO_ID_RE.search(url)
    return m.group(1) if m else ""


def fetch_one(url: str, timeout: int = 12, sleep_s: float = 0.3) -> Dict[str, Any]:
    now = time.time()
    c = cache.get(url)
    if c and now - c["ts"] < CACHE_TTL:
        return c["data"]

    time.sleep(max(sleep_s, 0.0))

    headers = {
        "User-Agent": MOBILE_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Connection": "close",
    }

    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        text = r.text or ""
    except requests.RequestException as e:
        data = {
            "original_url": url,
            "video_id_in_url": extract_video_id(url),
            "http_status": None,
            "final_url": None,
            "aweme_id": None,
            "item_id": None,
            "validity": "unknown",
            "note": f"RequestError: {e}",
        }
        cache[url] = {"ts": now, "data": data}
        return data

    aweme_id = None
    item_id = None
    m1 = AWEME_ID_RE.search(text)
    if m1:
        aweme_id = m1.group(1)
    m2 = ITEM_ID_RE.search(text)
    if m2:
        item_id = m2.group(1)

    validity = "unknown"
    note = f"HTTP {r.status_code}"

    if r.status_code in (404, 410):
        validity, note = "invalid", "HTTP 404/410"
    elif r.status_code in (401, 403):
        validity, note = "unknown", "Blocked (401/403)"
    elif r.status_code >= 500:
        validity, note = "unknown", "Server error (5xx)"
    elif r.status_code == 200:
        if aweme_id or item_id:
            validity, note = "valid", "Found aweme_id/itemId"
        else:
            low = text.lower()
            if any(h.lower() in low for h in NOT_FOUND_HINTS):
                validity, note = "invalid", "Not-found hint"
            else:
                host = (urlparse(r.url).netloc or "").lower()
                if "douyin.com" in host:
                    validity, note = "maybe", "200 OK but no IDs (anti-bot possible)"
                else:
                    validity, note = "maybe", "200 OK but no IDs"

    data = {
        "original_url": url,
        "video_id_in_url": extract_video_id(url),
        "http_status": r.status_code,
        "final_url": r.url,
        "aweme_id": aweme_id,
        "item_id": item_id,
        "validity": validity,
        "note": note,
    }
    cache[url] = {"ts": now, "data": data}
    return data


from fastapi.responses import HTMLResponse
import os

@app.get("/", response_class=HTMLResponse)
def home():
    # 读取同目录下的 index.html 并返回
    path = os.path.join(os.path.dirname(__file__), "index.html")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


@app.post("/check")
def check_links(links: List[str], sleep_s: float = 0.3, timeout: int = 12):
    results = []
    for u in links:
        u = (u or "").strip()
        if not u:
            continue
        if not (u.startswith("http://") or u.startswith("https://")):
            results.append({"original_url": u, "validity": "invalid", "note": "Not a URL"})
            continue
        results.append(fetch_one(u, timeout=timeout, sleep_s=sleep_s))
    return {"count": len(results), "results": results}


@app.post("/check_csv")
def check_links_csv(links: List[str], sleep_s: float = 0.3, timeout: int = 12):
    payload = check_links(links, sleep_s=sleep_s, timeout=timeout)
    results = payload["results"]

    output = io.StringIO()
    fieldnames = [
        "original_url","video_id_in_url","http_status",
        "final_url","aweme_id","item_id","validity","note"
    ]
    w = csv.DictWriter(output, fieldnames=fieldnames)
    w.writeheader()
    for r in results:
        row = {k: r.get(k) for k in fieldnames}
        w.writerow(row)

    csv_bytes = output.getvalue().encode("utf-8-sig")
    return StreamingResponse(
        io.BytesIO(csv_bytes),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=douyin_check_result.csv"},
    )
