# -*- coding: utf-8 -*-
import csv
import io
import os
import re
import time
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse

import requests
from fastapi import FastAPI
from fastapi.responses import StreamingResponse, HTMLResponse

app = FastAPI(title="Douyin Link Checker")

MOBILE_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 "
    "Mobile/15E148 Safari/604.1"
)

VIDEO_ID_RE = re.compile(r"/share/video/(\d+)")
AWEME_ID_RE = re.compile(r'"aweme_id"\s*:\s*"(\d+)"')
ITEM_ID_RE = re.compile(r'"itemId"\s*:\s*"(\d+)"')

# ---------------------------
# 失效判定：关键词 + 组合规则
# 目标：解决“HTTP 200 但页面提示内容不存在/已删除/下架”等情况
# ---------------------------

# “对象词”（页面在说什么不存在/删除）
NF_ENTITY = [
    "内容",
    "视频",
    "作品",
    "页面",
]

# “状态词”（不存在/删除/下架/不可见/无法看）
NF_STATE = [
    "不存在",
    "已删除",
    "删除",
    "下架",
    "已下架",
    "失效",
    "不可见",
    "不可查看",
    "无法查看",
    "暂时无法查看",
    "不可观看",
    "无法播放",
    "已被删除",
    "已被下架",
]

# 一些“典型整句”作为强信号（更稳，但不依赖它）
NF_STRONG_PHRASES = [
    "您访问的内容不存在",
    "你访问的内容不存在",
    "访问的内容不存在",
    "该内容不存在",
    "该视频不存在",
    "该作品不存在",
    "该内容已删除",
    "该内容无法查看",
    "内容不可见",
]

# 英文/通用（强信号）
NF_MISC = [
    "not found",
    "404",
]

CACHE_TTL = 3600  # 1小时缓存
cache: Dict[str, Dict[str, Any]] = {}


def extract_video_id(url: str) -> str:
    m = VIDEO_ID_RE.search(url)
    return m.group(1) if m else ""


def _normalize_text(text: str) -> str:
    """
    做一个轻度归一化，提升命中率：
    - lower
    - 去掉多余空白（不做太重的清洗，避免误判）
    """
    if not text:
        return ""
    low = text.lower()
    # 把连续空白压缩成一个空格
    low = re.sub(r"\s+", " ", low)
    return low


def page_says_not_found(text: str, has_id: bool) -> Tuple[bool, str]:
    """
    返回 (是否判定失效, 命中原因说明)
    规则（从强到弱）：
    1) 命中典型整句 or 英文/404 -> 失效
    2) 同时出现 entity + state -> 失效
    3) 出现 state 且没有 aweme_id/itemId -> 大概率失效
    """
    low = _normalize_text(text)
    if not low:
        return False, ""

    # 1) 强信号：整句/英文
    for p in NF_STRONG_PHRASES:
        if p.lower() in low:
            return True, f"Matched phrase: {p}"
    for k in NF_MISC:
        if k in low:
            return True, f"Matched misc: {k}"

    # 2) 组合信号：对象词 + 状态词
    hit_entities = [k for k in NF_ENTITY if k in low]
    hit_states = [k for k in NF_STATE if k in low]
    if hit_entities and hit_states:
        return True, f"Matched entity+state: {hit_entities[0]} + {hit_states[0]}"

    # 3) 次强：状态词出现且没有ID（很多“无效页”是 200 + 无ID + 状态词）
    if hit_states and not has_id:
        return True, f"Matched state without IDs: {hit_states[0]}"

    return False, ""


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

    has_id = bool(aweme_id or item_id)

    validity = "unknown"
    note = f"HTTP {r.status_code}"

    if r.status_code in (404, 410):
        validity, note = "invalid", "HTTP 404/410"
    elif r.status_code in (401, 403):
        validity, note = "unknown", "Blocked (401/403) - captcha/login possible"
    elif r.status_code >= 500:
        validity, note = "unknown", "Server error (5xx)"
    elif r.status_code == 200:
        # 关键：先判“页面提示不存在/删除/下架”
        is_nf, why = page_says_not_found(text, has_id)
        if is_nf:
            validity, note = "invalid", why or "Page indicates not found/removed"
        elif has_id:
            validity, note = "valid", "Found aweme_id/itemId"
        else:
            host = (urlparse(r.url).netloc or "").lower()
            if "douyin.com" in host:
                validity, note = "maybe", "200 OK but no IDs extracted (anti-bot possible)"
            else:
                validity, note = "maybe", "200 OK but no IDs extracted"

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
        "original_url", "video_id_in_url", "http_status",
        "final_url", "aweme_id", "item_id", "validity", "note"
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
