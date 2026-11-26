"""Unit-Tests ohne Datenbank: Normalisierung, Versionsvergleich, Risiko-Score, CSV-Pruefung.
Start (im Ordner m3_risk):  python -m pytest tests
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from app import normalize, risk, versions
from app.inventory import CsvValidationError, parse_csv

POLICY = risk.load_policy(Path(__file__).resolve().parents[1] / "app" / "risk_policy.yaml")
NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------- Normalisierung

@pytest.mark.parametrize("raw, expected", [
    ("Fortinet, Inc.", "fortinet"),
    ("Palo Alto Networks", "paloaltonetworks"),     # wie in NVD-CPEs
    ("Apache Software Foundation", "apache"),
    ("Microsoft Corporation", "microsoft"),
    ("  Ivanti ", "ivanti"),
    ("SAP SE", "sap"),
    ("", None),
    (None, None),
])
def test_normalize_vendor(raw, expected):
    assert normalize.normalize_vendor(raw) == expected


@pytest.mark.parametrize("raw, expected", [
    ("Exchange Server", "exchange_server"),
    ("FortiOS", "fortios"),
    ("Node.js", "node.js"),
    ("Connect Secure", "connect_secure"),
])
def test_normalize_product(raw, expected):
    assert normalize.normalize_product(raw) == expected


def test_parse_cpe23():
    cpe = normalize.parse_cpe23("cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*")
    assert (cpe["part"], cpe["vendor"], cpe["product"], cpe["version"]) == ("o", "fortinet", "fortios", "7.2.4")
    escaped = normalize.parse_cpe23(r"cpe:2.3:a:vendor:prod\:x:1.0:*:*:*:*:*:*:*")
    assert escaped["product"] == "prod:x" and escaped["version"] == "1.0"
    assert normalize.parse_cpe23("cpe:/o:fortinet:fortios") is None
    assert normalize.parse_cpe23("cpe:2.3:o:fortinet") is None


# ---------------------------------------------------------------- Versionen

@pytest.mark.parametrize("a, b, expected", [
    ("7.2.4", "7.2.7", -1),
    ("7.2.10", "7.2.9", 1),
    ("7.2", "7.2.0", 0),
    ("7.2.1", "7.2", 1),
    ("v1.2", "1.2", 0),
    ("1.0rc1", "1.0", -1),               # PEP 440: Vorabversion
    ("22.7R2.4", "22.7R2.3", 1),         # Ivanti-Format
    ("22.7R2", "22.7R2.0", 0),
    ("1.0.2", "1.0.2a", None),           # OpenSSL-artig: unklar -> None
    ("1.0", "abc", None),
    ("*", "1.0", None),
])
def test_compare(a, b, expected):
    assert versions.compare(a, b) == expected


@pytest.mark.parametrize("version, kwargs, expected", [
    ("7.2.4", dict(start_including="7.2.0", end_excluding="7.2.7"), "affected"),
    ("7.2.7", dict(start_including="7.2.0", end_excluding="7.2.7"), "not_affected"),
    ("7.2.7", dict(start_including="7.2.0", end_including="7.2.7"), "affected"),
    ("7.0.1", dict(start_including="7.2.0", end_excluding="7.2.7"), "not_affected"),
    ("7.2.4", dict(exact="7.2.4"), "affected"),
    ("7.2.5", dict(exact="7.2.4"), "not_affected"),
    ("7.2.4", dict(), "affected"),                                   # alle Versionen
    (None, dict(end_excluding="7.2.7"), "unknown"),                  # Version im Inventar fehlt
    ("1.0.2", dict(end_excluding="1.0.2k"), "unknown"),              # nicht vergleichbar
    ("0.9", dict(start_including="1.0", end_excluding="1.0.2k"), "not_affected"),  # sichere Grenze reicht
    # feste Version UND Grenzen in einer Zeile: uebereinstimmend -> Ergebnis, Widerspruch -> unknown
    ("7.2.4", dict(exact="7.2.4", start_including="7.2.0", end_excluding="7.2.7"), "affected"),
    ("7.3.0", dict(exact="7.2.4", start_including="7.2.0", end_excluding="7.2.7"), "not_affected"),
    ("7.2.5", dict(exact="7.2.4", start_including="7.2.0", end_excluding="7.2.7"), "unknown"),
    ("7.2.4", dict(exact="7.2.4", end_excluding="7.2.0"), "unknown"),
])
def test_check_range(version, kwargs, expected):
    assert versions.check_range(version, **kwargs) == expected


# ---------------------------------------------------------------- Risiko-Score

def _inp(**kw):
    base = dict(cvss_score=9.8, kev_listed=True, kev_due_date=None, epss_score=0.9, asset_criticality=5,
                internet_exposed=True, trust_score=1.0, match_confidence=0.95, version_status="affected")
    base.update(kw)
    return risk.RiskInput(**base)


def test_score_maximum_case_is_critical():
    r = risk.score(_inp(), POLICY, NOW)
    # 35*0.98 + 25 + 15 + 10 + 10 + 5*0.95 = 34.3 + 25 + 15 + 10 + 10 + 4.75 = 99.05
    assert r.score == pytest.approx(99.05)
    assert r.risk_level == "critical"
    assert r.action_code == "patch_immediately"
    assert r.deadline_at == datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
    assert r.factor_breakdown["missing"] == []


def test_breakdown_points_add_up():
    r = risk.score(_inp(cvss_score=5.0, kev_listed=False, epss_score=0.1, asset_criticality=3,
                        internet_exposed=False, trust_score=0.5), POLICY, NOW)
    points = sum(f["points"] for f in r.factor_breakdown["factors"].values())
    assert r.score == pytest.approx(points)


def test_missing_values_are_flagged():
    r = risk.score(_inp(cvss_score=None, kev_listed=False, epss_score=None, trust_score=None), POLICY, NOW)
    assert set(r.factor_breakdown["missing"]) == {"severity", "exploitation", "trust"}


def test_floor_kev_exposed_affected_is_at_least_high():
    r = risk.score(_inp(cvss_score=None, epss_score=None, trust_score=None, asset_criticality=1), POLICY, NOW)
    assert r.score < 60
    assert r.risk_level == "high"
    assert r.factor_breakdown["floor_applied"]["rule"] == "kev_exposed_affected"


def test_no_floor_when_version_unknown():
    r = risk.score(_inp(cvss_score=None, epss_score=None, trust_score=None, asset_criticality=1,
                        version_status="unknown"), POLICY, NOW)
    assert r.factor_breakdown["floor_applied"] is None
    assert r.risk_level != "high"


def test_deadline_never_after_kev_due_date():
    r = risk.score(_inp(cvss_score=5.0, kev_listed=True, kev_due_date=date(2026, 11, 20),
                        asset_criticality=2, internet_exposed=False), POLICY, NOW)
    assert r.risk_level in ("medium", "high")
    assert r.deadline_at == datetime(2026, 11, 20, 23, 59, 59, tzinfo=timezone.utc)


def test_policy_weights_must_sum_to_100(tmp_path):
    bad = (Path(__file__).resolve().parents[1] / "app" / "risk_policy.yaml").read_text(encoding="utf-8")
    bad = bad.replace("severity: 35", "severity: 40")
    p = tmp_path / "p.yaml"
    p.write_text(bad, encoding="utf-8")
    with pytest.raises(ValueError):
        risk.load_policy(p)


# ---------------------------------------------------------------- CSV

HEADER = "asset_key,name,asset_type,criticality,internet_exposed,environment,owner_team,vendor,product,version,component_type,vendor_country,cpe23\n"


def test_csv_ok_with_multiple_rows_per_asset():
    data = (HEADER
            + "fw-01,Firewall,firewall,5,true,,Netz,Fortinet,FortiOS,7.2.4,firmware,US,\n"
            + "srv-01,KI-Server,server,3,false,,IT,Alibaba,qwen2.5,7b,ai_model,CN,\n"
            + "srv-01,KI-Server,server,3,false,,IT,Ollama,Ollama,0.4.0,application,US,\n").encode()
    inv = parse_csv(data)
    assert set(inv.assets) == {"fw-01", "srv-01"}
    assert len(inv.components["srv-01"]) == 2
    fw = inv.components["fw-01"][0]
    assert (fw["vendor_norm"], fw["product_norm"], fw["version"]) == ("fortinet", "fortios", "7.2.4")


def test_csv_semicolon_and_bom():
    data = ("\ufeff" + HEADER.replace(",", ";")
            + "fw-01;Firewall;firewall;5;ja;;;Fortinet;FortiOS;7.2.4;;;\n").encode("utf-8")
    inv = parse_csv(data)
    assert inv.assets["fw-01"]["internet_exposed"] is True


def test_csv_cpe_overrides_vendor_and_product():
    data = (HEADER + "fw-01,Firewall,firewall,5,true,,,Fortinet Inc,Forti OS,,firmware,,"
            + "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*\n").encode()
    c = parse_csv(data).components["fw-01"][0]
    assert c["name"] == "Forti OS"
    assert (c["vendor_norm"], c["product_norm"], c["version"]) == ("fortinet", "fortios", "7.2.4")


def test_csv_empty_product_uses_cpe_name():
    data = (HEADER + "fw-01,Firewall,firewall,5,true,,,,,,firmware,,"
            + "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*\n").encode()
    c = parse_csv(data).components["fw-01"][0]
    assert (c["name"], c["vendor"]) == ("fortios", "fortinet")
    assert (c["vendor_norm"], c["product_norm"], c["version"]) == ("fortinet", "fortios", "7.2.4")


def test_csv_empty_product_without_cpe_is_rejected():
    data = (HEADER + "fw-01,Firewall,firewall,5,true,,,,,,firmware,,\n").encode()
    with pytest.raises(CsvValidationError) as exc:
        parse_csv(data)
    assert any(e["field"] == "product" for e in exc.value.errors)


def test_csv_collects_all_errors():
    data = (HEADER
            + "fw-01,Firewall,router,7,vielleicht,,,Fortinet,FortiOS,7.2.4,,,\n"
            + "fw-01,Firewall-2,firewall,5,true,,,Fortinet,FortiOS,7.2.5,,,\n"
            + ",x,server,1,false,,,,,,,,\n").encode()
    with pytest.raises(CsvValidationError) as exc:
        parse_csv(data)
    fields = {(e["row"], e["field"]) for e in exc.value.errors}
    assert {(2, "asset_type"), (2, "criticality"), (2, "internet_exposed"), (4, "asset_key")} <= fields
    assert any(e["row"] == 3 and e["field"] == "product" for e in exc.value.errors)   # doppeltes Produkt


def test_risk_inputs_do_not_change_match_fingerprint():
    from app.pipeline import item_fingerprints, needs_rematch
    item = {"id": 1, "cve_ids": ["CVE-2099-0001"], "category": "VULNERABILITY",
            "trust_score": 0.8, "trust_label": "CONFIRMED", "p_status": "done", "p_match_fp": None}
    facts = {"CVE-2099-0001": {"cvss_score": 9.8, "kev_listed": False}}
    affected = {"CVE-2099-0001": [["nvd", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"]]}
    entities = {1: [["PRODUCT", "fortios", None]]}
    inventory = {"assets": 1, "components": 1}
    match_a, risk_a = item_fingerprints(item, facts, affected, entities, inventory, [["fw-01", 5, True]], POLICY)
    match_b, risk_b = item_fingerprints(item, facts, affected, entities, inventory, [["fw-01", 1, True]], POLICY)
    assert match_a == match_b and risk_a != risk_b
    item["p_match_fp"] = match_a
    assert needs_rematch(item, match_b) is False

    entities_version = {1: [["PRODUCT", "fortios", "7.2.4"]]}
    match_c, risk_c = item_fingerprints(item, facts, affected, entities_version, inventory, [["fw-01", 5, True]], POLICY)
    assert match_c != match_a and risk_c == risk_a
    assert needs_rematch(item, match_c) is True


def test_csv_header_errors():
    with pytest.raises(CsvValidationError) as exc:
        parse_csv(b"asset_key,name,typo\nfw-01,x,y\n")
    msg = " ".join(e["message"] for e in exc.value.errors)
    assert "Pflichtspalten fehlen" in msg and "Unbekannte Spalten" in msg


# ---------------------------------------------------------------- SBOM / purl

from app import sbom  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sbom_small.cdx.json"


@pytest.mark.parametrize("purl, expected", [
    ("pkg:npm/axios@1.6.0", ("npm", "axios")),
    ("pkg:npm/%40acme/tools@2.0.0", ("npm", "@acme/tools")),
    ("pkg:pypi/Django_Rest.Framework@3.0", ("PyPI", "django-rest-framework")),
    ("pkg:golang/golang.org/x/net@v0.17.0", ("Go", "golang.org/x/net")),
    ("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", ("Maven", "org.apache.logging.log4j:log4j-core")),
    ("pkg:deb/debian/libssl3@3.0.11-1?distro=debian-12", None),      # Betriebssystempaket: nicht abgleichen
])
def test_osv_key(purl, expected):
    assert sbom.osv_key(sbom.parse_purl(purl)) == expected


def test_parse_purl_version_and_qualifiers():
    p = sbom.parse_purl("pkg:deb/debian/libssl3@3.0.11-1?arch=amd64&distro=debian-12#sub")
    assert (p.type, p.namespace, p.name, p.version) == ("deb", "debian", "libssl3", "3.0.11-1")
    assert sbom.parse_purl("not-a-purl") is None


def test_parse_cyclonedx_fixture():
    parsed = sbom.parse_cyclonedx(FIXTURE.read_bytes())
    names = [p["name"] for p in parsed.packages]
    assert names.count("axios") == 1                        # Duplikat entfernt
    assert "/usr/lib/libssl.so.3" not in names and parsed.skipped_files == 1
    assert parsed.matchable == 4 and parsed.os_packages == 1
    assert sbom.default_image_ref(parsed) == "example/webapp:1.0"
    django = next(p for p in parsed.packages if p["name"] == "Django")
    assert (django["osv_ecosystem"], django["osv_package"]) == ("PyPI", "django")


@pytest.mark.parametrize("data", [b"{not json", b'{"bomFormat": "SPDX"}', b'{"bomFormat": "CycloneDX", "components": []}'])
def test_parse_cyclonedx_rejects_invalid(data):
    with pytest.raises(sbom.SbomError):
        sbom.parse_cyclonedx(data)
