"""RSS/Atom-Feeds. fetch_state: etag, last_modified (bedingter Abruf)."""
import calendar
from datetime import datetime, timezone

import feedparser

from ..models import FetchResult, RawItem
from ..textutil import strip_html


def parse_feed(content: bytes, source: dict) -> list[RawItem]:
    feed = feedparser.parse(content)
    if feed.bozo and not feed.entries:
        raise ValueError(f"kein gueltiger Feed: {feed.get('bozo_exception')}")
    limit = int((source.get("config") or {}).get("max_items", 200))
    items: list[RawItem] = []
    for e in feed.entries[:limit]:
        title = strip_html(e.get("title"))
        link = e.get("link") or source["url"]
        if e.get("content"):
            html = e["content"][0].get("value", "")
        else:
            html = e.get("summary", "")
        body = strip_html(html)
        ts = e.get("published_parsed") or e.get("updated_parsed")
        published = datetime.fromtimestamp(calendar.timegm(ts), timezone.utc) if ts else None
        external_id = e.get("id") or e.get("link") or f"{title}|{published}"
        if not title and body:
            # Social-Beitraege (z. B. Mastodon) haben keinen Titel: erste Zeile, gekuerzt
            first = body.split("\n", 1)[0]
            title = first if len(first) <= 120 else first[:117].rstrip() + "..."
        items.append(RawItem(external_id=external_id, url=link, title=title,
                             body=body, published_at=published))
    return items


def fetch(source: dict, state: dict | None, http, conn) -> FetchResult:
    state = state or {}
    headers = {}
    if state.get("etag"):
        headers["If-None-Match"] = state["etag"]
    if state.get("last_modified"):
        headers["If-Modified-Since"] = state["last_modified"]
    resp = http.get(source["url"], headers=headers, allow_304=True)
    if resp.status_code == 304:
        return FetchResult(state=state, seen=0)
    new_state = {k: v for k, v in (("etag", resp.headers.get("ETag")),
                                   ("last_modified", resp.headers.get("Last-Modified"))) if v}
    return FetchResult(items=parse_feed(resp.content, source), state=new_state)
