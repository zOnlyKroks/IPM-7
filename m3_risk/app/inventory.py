"""Inventar-Import (CSV). Siehe README, Abschnitt 6.

Eine Zeile = eine Software auf einem Asset. Der Import ist ein vollstaendiger Schnappschuss:
was in der Datei fehlt, wird deaktiviert (nie geloescht). Alles oder nichts: bei einem Fehler
wird nichts gespeichert und die Antwort listet alle fehlerhaften Zeilen.
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from typing import Any

from .normalize import is_wildcard, normalize_product, normalize_vendor, parse_cpe23

ASSET_TYPES = {"server", "firewall", "vpn_gateway", "client", "mail_server", "database",
               "web_application", "container_host", "network_device", "other"}
ENVIRONMENTS = {"production", "staging", "test"}
COMPONENT_TYPES = {"operating_system", "application", "library", "container_image",
                   "firmware", "ai_model", "cloud_service", "other"}

REQUIRED = ("asset_key", "name", "asset_type", "criticality", "internet_exposed", "product")
OPTIONAL = ("environment", "owner_team", "vendor", "version", "component_type", "vendor_country", "cpe23")
ASSET_FIELDS = ("name", "asset_type", "criticality", "internet_exposed", "environment", "owner_team")

_TRUE = {"true", "1", "yes", "ja", "y", "x"}
_FALSE = {"false", "0", "no", "nein", "n", ""}


class CsvValidationError(Exception):
    def __init__(self, message: str, errors: list[dict[str, Any]]):
        super().__init__(message)
        self.message = message
        self.errors = errors


@dataclass
class ParsedInventory:
    assets: dict[str, dict[str, Any]] = field(default_factory=dict)       # asset_key -> Asset-Felder
    components: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # asset_key -> Software


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig")          # Excel speichert UTF-8 gern mit BOM
    except UnicodeDecodeError as exc:
        raise CsvValidationError("Datei ist nicht UTF-8-kodiert.", [{"row": None, "field": None,
                                                                    "message": str(exc)}]) from exc


def _dialect(text: str) -> type[csv.Dialect] | csv.Dialect:
    try:
        return csv.Sniffer().sniff(text.split("\n", 1)[0], delimiters=",;")   # deutsches Excel: Semikolon
    except csv.Error:
        return csv.excel


def parse_csv(data: bytes) -> ParsedInventory:
    text = _decode(data)
    reader = csv.DictReader(io.StringIO(text), dialect=_dialect(text))
    header = [h.strip() for h in (reader.fieldnames or [])]
    reader.fieldnames = header
    errors: list[dict[str, Any]] = []

    missing = [c for c in REQUIRED if c not in header]
    unknown = [c for c in header if c and c not in REQUIRED + OPTIONAL]
    if missing or unknown:
        if missing:
            errors.append({"row": 1, "field": None, "message": f"Pflichtspalten fehlen: {', '.join(missing)}"})
        if unknown:
            errors.append({"row": 1, "field": None, "message": f"Unbekannte Spalten: {', '.join(unknown)}"})
        raise CsvValidationError("Kopfzeile ungueltig.", errors)

    result = ParsedInventory()
    seen_products: dict[tuple[str, str | None, str], int] = {}

    for rownum, raw in enumerate(reader, start=2):        # Zeile 1 = Kopfzeile
        row = {k: (v or "").strip() for k, v in raw.items() if k}
        if not any(row.values()):
            continue                                       # leere Zeile ignorieren

        def err(fieldname: str | None, message: str) -> None:
            errors.append({"row": rownum, "field": fieldname, "message": message})

        key = row.get("asset_key", "")
        if not key:
            err("asset_key", "Pflichtfeld leer")
            continue

        asset: dict[str, Any] = {"name": row.get("name", "")}
        if not asset["name"]:
            err("name", "Pflichtfeld leer")
        asset_type = row.get("asset_type", "").lower()
        if asset_type not in ASSET_TYPES:
            err("asset_type", f"Ungueltig: '{row.get('asset_type')}'. Erlaubt: {', '.join(sorted(ASSET_TYPES))}")
        asset["asset_type"] = asset_type
        try:
            crit = int(row.get("criticality", ""))
            if not 1 <= crit <= 5:
                raise ValueError
            asset["criticality"] = crit
        except ValueError:
            err("criticality", "Ganzzahl von 1 bis 5 erwartet")
            asset["criticality"] = None
        exposed = row.get("internet_exposed", "").lower()
        if exposed in _TRUE and exposed != "":
            asset["internet_exposed"] = True
        elif exposed in _FALSE and exposed != "":
            asset["internet_exposed"] = False
        else:
            err("internet_exposed", "true oder false erwartet")
            asset["internet_exposed"] = None
        env = (row.get("environment") or "production").lower()
        if env not in ENVIRONMENTS:
            err("environment", f"Ungueltig: '{row.get('environment')}'. Erlaubt: {', '.join(sorted(ENVIRONMENTS))}")
        asset["environment"] = env
        asset["owner_team"] = row.get("owner_team") or None

        if key in result.assets:
            for f in ASSET_FIELDS:
                if result.assets[key][f] != asset[f]:
                    err(f, f"Abweichende Asset-Angabe fuer '{key}' (vorher: {result.assets[key][f]!r})")
        else:
            result.assets[key] = asset
            result.components[key] = []

        # --- Software
        comp_type = (row.get("component_type") or "application").lower()
        if comp_type not in COMPONENT_TYPES:
            err("component_type", f"Ungueltig: '{row.get('component_type')}'. Erlaubt: {', '.join(sorted(COMPONENT_TYPES))}")
        country = (row.get("vendor_country") or "").upper() or None
        if country is not None and (len(country) != 2 or not country.isalpha()):
            err("vendor_country", "ISO-Laendercode mit zwei Buchstaben erwartet, z. B. DE")

        vendor, product, version = row.get("vendor") or None, row.get("product") or None, row.get("version") or None
        vendor_norm, product_norm = normalize_vendor(vendor), normalize_product(product)
        cpe23 = row.get("cpe23") or None
        if cpe23:
            cpe = parse_cpe23(cpe23)
            if cpe is None:
                err("cpe23", "Kein gueltiger CPE-2.3-String (cpe:2.3:part:vendor:product:version:...)")
            else:
                vendor_norm, product_norm = cpe["vendor"], cpe["product"]   # CPE ist massgeblich
                if product is None:
                    product = cpe["product"]                                # Anzeigename, Spalte darf dann leer sein
                if vendor is None:
                    vendor = cpe["vendor"]
                if version is None and not is_wildcard(cpe["version"]):
                    version = cpe["version"]
                elif version is not None and not is_wildcard(cpe["version"]) and cpe["version"] != version:
                    err("version", f"Widerspricht der Version in cpe23 ('{cpe['version']}')")
        if not product_norm:
            err("product", "Pflichtfeld leer")
            continue

        dup_key = (key, vendor_norm, product_norm)
        if dup_key in seen_products:
            err("product", f"Produkt ist fuer '{key}' schon in Zeile {seen_products[dup_key]} angegeben")
            continue
        seen_products[dup_key] = rownum

        result.components[key].append({
            "row": rownum, "name": product, "vendor": vendor, "version": version, "vendor_norm": vendor_norm,
            "product_norm": product_norm, "component_type": comp_type, "vendor_country": country,
            "cpe23": cpe23,
        })

    if not result.assets and not errors:
        errors.append({"row": None, "field": None, "message": "Datei enthaelt keine Datenzeilen"})
    if errors:
        raise CsvValidationError(f"{len(errors)} Fehler in der CSV-Datei, nichts gespeichert.", errors)
    return result


def naming_warnings(conn, inv: ParsedInventory) -> list[dict[str, Any]]:
    """Hinweise (keine Fehler): Hersteller/Produkt ohne cpe23, die in den NVD-Daten nie vorkommen.
    Dann passt die Schreibweise vermutlich nicht zu NVD, und der Abgleich wuerde nichts finden."""
    candidates = [(key, c) for key, comps in inv.components.items() for c in comps if not c["cpe23"]]
    if not candidates:
        return []
    if conn.execute("SELECT NOT EXISTS (SELECT 1 FROM public.cve_affected WHERE data_source = 'nvd') AS empty"
                    ).fetchone()["empty"]:
        return [{"row": None, "asset_key": None, "message":
                 "Noch keine NVD-Daten vorhanden, Pruefung der Produktnamen uebersprungen"}]
    known = {(r["vendor"], r["product"]) for r in conn.execute("""
        SELECT DISTINCT vendor, product FROM public.cve_affected
         WHERE data_source = 'nvd' AND product = ANY(%s)""",
        ([c["product_norm"] for _, c in candidates],)).fetchall()}
    known_products = {p for _, p in known}
    warnings = []
    for key, c in candidates:
        found = ((c["vendor_norm"], c["product_norm"]) in known if c["vendor_norm"]
                 else c["product_norm"] in known_products)
        if not found:
            warnings.append({
                "row": c["row"], "asset_key": key,
                "message": f"'{c['vendor'] or ''} {c['name']}' kommt in den NVD-Daten nicht vor "
                           f"(als '{c['vendor_norm'] or '-'}:{c['product_norm']}'). Schreibweise pruefen oder cpe23 angeben."})
    return warnings


def apply_inventory(conn, inv: ParsedInventory) -> dict[str, int]:
    """Schreibt den Schnappschuss. Muss innerhalb einer Transaktion aufgerufen werden."""
    stats = {k: 0 for k in ("assets_created", "assets_updated", "assets_deactivated",
                            "components_created", "components_updated", "components_deactivated")}
    asset_ids: dict[str, int] = {}

    for key, a in inv.assets.items():
        before = conn.execute(
            "SELECT id, name, asset_type, criticality, internet_exposed, environment, owner_team, is_active "
            "FROM m3.assets WHERE asset_key = %s FOR UPDATE", (key,)).fetchone()
        if before is None:
            row = conn.execute(
                "INSERT INTO m3.assets (asset_key, name, asset_type, criticality, internet_exposed, environment, owner_team) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (key, a["name"], a["asset_type"], a["criticality"], a["internet_exposed"], a["environment"], a["owner_team"]),
            ).fetchone()
            stats["assets_created"] += 1
            asset_ids[key] = row["id"]
            continue
        asset_ids[key] = before["id"]
        changed = any(before[f] != a[f] for f in ASSET_FIELDS) or not before["is_active"]
        if changed:
            conn.execute(
                "UPDATE m3.assets SET name=%s, asset_type=%s, criticality=%s, internet_exposed=%s, "
                "environment=%s, owner_team=%s, is_active=true WHERE id=%s",
                (a["name"], a["asset_type"], a["criticality"], a["internet_exposed"], a["environment"],
                 a["owner_team"], before["id"]))
            stats["assets_updated"] += 1

    stats["assets_deactivated"] = conn.execute(
        "UPDATE m3.assets SET is_active = false WHERE is_active AND NOT (asset_key = ANY(%s))",
        (list(inv.assets),)).rowcount
    # Manuelle Software deaktivierter Assets ebenfalls deaktivieren (SBOM-Komponenten bleiben unberuehrt,
    # zaehlen aber ueber die Views nicht mehr, solange das Asset inaktiv ist).
    stats["components_deactivated"] += conn.execute(
        "UPDATE m3.sbom_components c SET is_active = false FROM m3.assets a "
        "WHERE a.id = c.asset_id AND NOT a.is_active AND c.origin = 'manual' AND c.is_active").rowcount

    comp_fields = ("name", "vendor", "version", "component_type", "vendor_country", "cpe23")
    for key, comps in inv.components.items():
        asset_id = asset_ids[key]
        kept_ids: list[int] = []
        for c in comps:
            before = conn.execute(
                "SELECT id, name, vendor, version, component_type, vendor_country, cpe23, is_active "
                "FROM m3.sbom_components WHERE origin = 'manual' AND asset_id = %s "
                "AND coalesce(vendor_norm, '') = coalesce(%s, '') AND product_norm = %s FOR UPDATE",
                (asset_id, c["vendor_norm"], c["product_norm"])).fetchone()
            if before is None:
                row = conn.execute(
                    "INSERT INTO m3.sbom_components (asset_id, origin, component_type, name, vendor, version, "
                    "vendor_norm, product_norm, vendor_country, cpe23) "
                    "VALUES (%s,'manual',%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                    (asset_id, c["component_type"], c["name"], c["vendor"], c["version"], c["vendor_norm"],
                     c["product_norm"], c["vendor_country"], c["cpe23"])).fetchone()
                stats["components_created"] += 1
                kept_ids.append(row["id"])
                continue
            kept_ids.append(before["id"])
            if any(before[f] != c[f] for f in comp_fields) or not before["is_active"]:
                # gleiche Zeile, damit bestehende Treffer verknuepft bleiben (z. B. neue Version nach Update)
                conn.execute(
                    "UPDATE m3.sbom_components SET name=%s, vendor=%s, version=%s, component_type=%s, "
                    "vendor_country=%s, cpe23=%s, is_active=true WHERE id=%s",
                    (c["name"], c["vendor"], c["version"], c["component_type"], c["vendor_country"],
                     c["cpe23"], before["id"]))
                stats["components_updated"] += 1
        stats["components_deactivated"] += conn.execute(
            "UPDATE m3.sbom_components SET is_active = false "
            "WHERE origin = 'manual' AND asset_id = %s AND is_active AND NOT (id = ANY(%s))",
            (asset_id, kept_ids)).rowcount
    return stats
