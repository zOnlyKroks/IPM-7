"""SBOM-Import (CycloneDX JSON, z. B. von Syft) und purl -> OSV-Zuordnung.

Grundsaetze (README Abschnitt 6):
  * Nur Pakete, keine Einzeldateien (Syft listet sehr viele "file"-Eintraege).
  * Eltern-Komponente jedes Pakets ist das Image selbst (Pfad: Image -> Paket).
  * Schnappschuss je Asset und Image: fehlende Pakete werden deaktiviert, nie geloescht.
  * Abgleich nur fuer Paketoekosysteme mit eindeutigen Namen und Versionen (npm, PyPI, Go, ...).
    Betriebssystempakete (deb, apk, rpm) werden gespeichert, aber nicht abgeglichen.
  * Von Syft geratene CPEs werden nur gespeichert, nicht fuer den Abgleich genutzt.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

# purl-Typ -> OSV-Oekosystem. Fehlt ein Typ, wird das Paket gespeichert, aber nicht abgeglichen.
PURL_TO_OSV = {
    "npm": "npm", "pypi": "PyPI", "golang": "Go", "maven": "Maven", "cargo": "crates.io",
    "gem": "RubyGems", "nuget": "NuGet", "composer": "Packagist", "hex": "Hex", "pub": "Pub",
}
OS_PURL_TYPES = {"deb", "apk", "rpm", "alpm"}

CDX_TYPES = {
    "library": "library", "framework": "library", "application": "application",
    "operating-system": "operating_system", "container": "container_image", "firmware": "firmware",
}
SKIP_TYPES = {"file"}


class SbomError(ValueError):
    pass


@dataclass(frozen=True)
class Purl:
    type: str
    namespace: str | None
    name: str
    version: str | None


def parse_purl(value: str | None) -> Purl | None:
    """pkg:type/namespace/name@version?qualifiers#subpath -> Purl; None, wenn ungueltig."""
    if not value or not value.startswith("pkg:"):
        return None
    rest = value[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in rest:
        return None
    ptype, path = rest.split("/", 1)
    version = None
    if "@" in path:
        path, version = path.rsplit("@", 1)
        version = unquote(version) or None
    parts = [unquote(p) for p in path.strip("/").split("/") if p]
    if not parts:
        return None
    namespace = "/".join(parts[:-1]) or None
    return Purl(ptype.lower(), namespace, parts[-1], version)


def normalize_pypi(name: str) -> str:
    """PEP 503: Gross-/Kleinschreibung und -, _, . sind gleichwertig."""
    return re.sub(r"[-_.]+", "-", name).lower()


def osv_key(purl: Purl) -> tuple[str, str] | None:
    """(OSV-Oekosystem, Paketname wie in OSV) oder None, wenn nicht abgleichbar."""
    eco = PURL_TO_OSV.get(purl.type)
    if eco is None:
        return None
    if purl.type == "pypi":
        return eco, normalize_pypi(purl.name)
    if purl.type == "maven":
        return (eco, f"{purl.namespace}:{purl.name}") if purl.namespace else None
    if purl.namespace and purl.type in {"npm", "golang", "composer"}:
        return eco, f"{purl.namespace}/{purl.name}"
    return eco, purl.name


@dataclass
class ParsedSbom:
    image_name: str | None
    image_version: str | None
    packages: list[dict[str, Any]] = field(default_factory=list)
    skipped_files: int = 0
    os_packages: int = 0
    matchable: int = 0


def parse_cyclonedx(data: bytes) -> ParsedSbom:
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SbomError(f"Kein gueltiges JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise SbomError("Keine CycloneDX-SBOM (bomFormat fehlt oder ist nicht 'CycloneDX')")
    meta = (doc.get("metadata") or {}).get("component") or {}
    result = ParsedSbom(image_name=meta.get("name"), image_version=meta.get("version"))

    seen: set[str] = set()
    for comp in doc.get("components") or []:
        if not isinstance(comp, dict):
            continue
        ctype = comp.get("type")
        if ctype in SKIP_TYPES:
            result.skipped_files += 1
            continue
        name = (comp.get("name") or "").strip()
        if not name:
            continue
        version = (comp.get("version") or "").strip() or None
        purl_text = comp.get("purl") or None
        purl = parse_purl(purl_text)
        key = purl_text or f"{name}@{version or ''}"
        if key in seen:
            continue                                   # Syft listet manche Pakete mehrfach (verschiedene Fundorte)
        seen.add(key)
        osv = osv_key(purl) if purl else None
        if purl and purl.type in OS_PURL_TYPES:
            result.os_packages += 1
        if osv:
            result.matchable += 1
        cpe = comp.get("cpe")
        result.packages.append({
            "name": name,
            "version": version or (purl.version if purl else None),
            "component_type": CDX_TYPES.get(ctype, "other"),
            "purl": purl_text if purl_text and purl_text.startswith("pkg:") else None,
            "cpe23": cpe if isinstance(cpe, str) and cpe.startswith("cpe:2.3:") else None,
            "osv_ecosystem": osv[0] if osv else None,
            "osv_package": osv[1] if osv else None,
        })
    if not result.packages:
        raise SbomError("SBOM enthaelt keine Pakete")
    return result


def default_image_ref(parsed: ParsedSbom) -> str | None:
    if not parsed.image_name:
        return None
    v = parsed.image_version
    if v and not v.startswith("sha256:"):
        return f"{parsed.image_name}:{v}"
    return parsed.image_name


def apply_sbom(conn, asset_id: int, image_ref: str, parsed: ParsedSbom, sha256: str) -> dict[str, Any]:
    """Schreibt den Schnappschuss eines Images. Muss in einer Transaktion laufen."""
    stats: dict[str, Any] = {"image_ref": image_ref, "unchanged": False, "packages": len(parsed.packages),
                             "packages_matchable": parsed.matchable, "os_packages_not_matched": parsed.os_packages,
                             "files_skipped": parsed.skipped_files,
                             "components_created": 0, "components_updated": 0, "components_deactivated": 0}
    image_purl = f"pkg:docker/{image_ref.split('@', 1)[0]}"
    image = conn.execute(
        "SELECT id, sbom_sha256, is_active FROM m3.sbom_components "
        "WHERE origin = 'sbom' AND asset_id = %s AND image_ref = %s AND purl = %s FOR UPDATE",
        (asset_id, image_ref, image_purl)).fetchone()
    if image and image["is_active"] and image["sbom_sha256"] == sha256:
        stats["unchanged"] = True                        # gleiche Datei schon importiert
        return stats
    if image is None:
        image_id = conn.execute(
            "INSERT INTO m3.sbom_components (asset_id, origin, component_type, name, version, purl, image_ref, sbom_sha256) "
            "VALUES (%s,'sbom','container_image',%s,%s,%s,%s,%s) RETURNING id",
            (asset_id, image_ref, parsed.image_version, image_purl, image_ref, sha256)).fetchone()["id"]
        stats["components_created"] += 1
    else:
        image_id = image["id"]
        conn.execute("UPDATE m3.sbom_components SET version=%s, sbom_sha256=%s, is_active=true WHERE id=%s",
                     (parsed.image_version, sha256, image_id))
        stats["components_updated"] += 1

    existing = {r["k"]: r for r in conn.execute(
        "SELECT id, coalesce(purl, name || '@' || coalesce(version, '')) AS k, is_active, version, component_type "
        "FROM m3.sbom_components WHERE origin = 'sbom' AND asset_id = %s AND image_ref = %s AND id <> %s",
        (asset_id, image_ref, image_id)).fetchall()}
    kept: list[int] = [image_id]
    for p in parsed.packages:
        key = p["purl"] or f"{p['name']}@{p['version'] or ''}"
        row = existing.get(key)
        if row is None:
            new_id = conn.execute(
                "INSERT INTO m3.sbom_components (asset_id, parent_component_id, origin, component_type, name, version, "
                "purl, cpe23, osv_ecosystem, osv_package, image_ref, sbom_sha256) "
                "VALUES (%s,%s,'sbom',%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (asset_id, image_id, p["component_type"], p["name"], p["version"], p["purl"], p["cpe23"],
                 p["osv_ecosystem"], p["osv_package"], image_ref, sha256)).fetchone()["id"]
            stats["components_created"] += 1
            kept.append(new_id)
            continue
        kept.append(row["id"])
        conn.execute(
            "UPDATE m3.sbom_components SET parent_component_id=%s, component_type=%s, version=%s, cpe23=%s, "
            "osv_ecosystem=%s, osv_package=%s, sbom_sha256=%s, is_active=true WHERE id=%s",
            (image_id, p["component_type"], p["version"], p["cpe23"], p["osv_ecosystem"], p["osv_package"],
             sha256, row["id"]))
        if not row["is_active"] or row["version"] != p["version"] or row["component_type"] != p["component_type"]:
            stats["components_updated"] += 1
    stats["components_deactivated"] = conn.execute(
        "UPDATE m3.sbom_components SET is_active = false "
        "WHERE origin = 'sbom' AND asset_id = %s AND image_ref = %s AND is_active AND NOT (id = ANY(%s))",
        (asset_id, image_ref, kept)).rowcount
    return stats
