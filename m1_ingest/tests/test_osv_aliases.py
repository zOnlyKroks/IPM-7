from app.connectors import osv
from app.httpclient import FetchError


class _Resp:
    def __init__(self, data):
        self.data = data

    def json(self):
        return self.data


RECORDS = {
    "CVE-1": {"aliases": ["GHSA-a", "GHSA-gone", "GHSA-old", "CVE-2"],
              "affected": [{"ranges": [{"type": "GIT"}]}]},
    "GHSA-a": {"affected": [{"package": {"ecosystem": "Maven", "name": "x"}, "versions": ["1.0"]}]},
    "GHSA-old": {"withdrawn": "2024-01-01",
                 "affected": [{"package": {"ecosystem": "npm", "name": "y"}, "versions": ["1"]}]},
}


class _Http:
    def get(self, url):
        key = url.rsplit("/", 1)[1]
        if key not in RECORDS:
            raise FetchError("404", 404)
        return _Resp(RECORDS[key])


def test_follows_package_aliases_and_skips_withdrawn():
    assert osv.load_rows(_Http(), "http://osv", "CVE-1") == [
        {"ecosystem": "Maven", "package_name": "x", "version_exact": "1.0"}]


def test_unknown_cve():
    assert osv.load_rows(_Http(), "http://osv", "CVE-404") is None
