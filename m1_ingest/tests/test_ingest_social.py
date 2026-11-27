from app import ingest
from app.connectors import rss


def test_post_without_title_gets_one_from_body():
    feed = (b'<?xml version="1.0"?><rss version="2.0"><channel><title>#cve</title>'
            b'<item><guid>1</guid><link>https://x/1</link><description>&lt;p&gt;'
            + b"word " * 60 + b'&lt;/p&gt;</description></item></channel></rss>')
    [item] = rss.parse_feed(feed, {"url": "u"})
    assert item.title.startswith("word word") and item.title.endswith("...") and len(item.title) <= 120


def test_fact_sources_never_run_in_parallel():
    source = {"id": 99, "name": "epss", "connector": "epss"}
    assert ingest._facts_lock.acquire(blocking=False)
    try:
        result = ingest.run_source(source)          # darf die Datenbank nicht anfassen
    finally:
        ingest._facts_lock.release()
    assert result["status"] == "skipped" and result["reason"] == "andere Faktenquelle laeuft"
    assert 99 not in ingest._active
