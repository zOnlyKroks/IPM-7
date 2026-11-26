"""Handlungsempfehlungen je Zielgruppe (README Abschnitt 8).

Aufbau jeder Empfehlung:
  * Feste Teile, regelbasiert aus den Daten: Ueberschrift, Massnahmen, Frist, Betroffen,
    "Manuelle Pruefung noetig". Diese Teile schreibt nie das LLM.
  * Einschaetzung (1-3 Saetze): vom lokalen LLM formuliert, nur aus einem festen Faktenpaket.
    Besteht der Text die Pruefregeln nicht oder ist Ollama nicht erreichbar, wird ein Mustertext genutzt.

Ablauf: Bei jeder neuen Bewertung werden sofort Mustertexte gespeichert (es gibt also immer eine
Empfehlung). Am Ende von /run ersetzt das LLM die Einschaetzung fuer die wichtigsten Bewertungen.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any

import httpx
from psycopg.types.json import Jsonb

from . import config

log = logging.getLogger("m3.recommend")

AUDIENCES = ("it_security", "management", "executive")
PROMPT_VERSION = "rec-v1"
TEMPLATE_MODEL = "template"
LLM_UNAVAILABLE = "llm_unavailable"          # einziger Fehler, nach dem es beim naechsten /run erneut versucht wird
MAX_LEN = {"it_security": 600, "management": 450, "executive": 300}

LEVEL_DE = {"critical": "kritisch", "high": "hoch", "medium": "mittel", "low": "niedrig", "info": "Information"}
HEADLINE = {
    "critical": "Sofort handeln",
    "high": "Dringend patchen",
    "medium": "Patch einplanen",
    "low": "Im nächsten Wartungsfenster patchen",
    "info": "Beobachten",
}
HEADLINE_KEV = "Sofort patchen – Schwachstelle wird aktiv ausgenutzt"

# Faelle, die ein Mensch pruefen muss. Code -> fester Text.
MANUAL_CHECKS = {
    "version_unknown": "Installierte Version ist nicht sicher vergleichbar – Version am System prüfen.",
    "name_only": "Treffer nur über den Produktnamen – Zuordnung manuell bestätigen.",
    "indirect": "Nur über eine Abhängigkeit betroffen – prüfen, ob die betroffene Funktion genutzt wird.",
    "report_unconfirmed": "Meldung ist laut Glaubwürdigkeitsprüfung nicht bestätigt – Quelle prüfen.",
    "report_contradictory": "Quellen widersprechen sich – Meldung manuell prüfen.",
    "no_severity": "Keine CVSS-Bewertung vorhanden – Schweregrad manuell einschätzen.",
}


# ---------------------------------------------------------------- feste Teile

def manual_checks(*, version_status: str, match_method: str, is_direct: bool, trust_label: str | None,
                  cvss_score: float | None, kev_listed: bool | None) -> list[dict[str, str]]:
    codes = []
    if version_status == "unknown":
        codes.append("version_unknown")
    if match_method in ("name_only", "vendor_exposure"):
        codes.append("name_only")
    if not is_direct:
        codes.append("indirect")
    if trust_label == "UNCONFIRMED":
        codes.append("report_unconfirmed")
    elif trust_label == "CONTRADICTORY":
        codes.append("report_contradictory")
    if cvss_score is None and not kev_listed:
        codes.append("no_severity")
    return [{"code": c, "text": MANUAL_CHECKS[c]} for c in codes]


def fixed_version(match_details: dict[str, Any]) -> str | None:
    """Erste Version ohne die Luecke, falls die Regel sie nennt (NVD/OSV: version_end_excluding)."""
    for rule in match_details.get("rules") or []:
        if rule.get("version_end_excluding"):
            return str(rule["version_end_excluding"])
    return None


def _date(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.strftime("%d.%m.%Y")


def build_facts(m: dict[str, Any], assessment: dict[str, Any], checks: list[dict[str, str]]) -> dict[str, Any]:
    """Festes Faktenpaket. Enthaelt keinen Freitext aus Meldungen (Schutz vor Prompt-Injection)."""
    details = m.get("match_details") or {}
    path = list(m.get("path_names") or [])
    f = {
        "cve_id": m["cve_id"],
        "risk_level": assessment["risk_level"],
        "risk_level_de": LEVEL_DE[assessment["risk_level"]],
        "risk_score": round(float(assessment["score"])),
        "deadline": _date(assessment["deadline_at"]),
        "kev_listed": bool(assessment["kev_listed"]),
        "kev_due_date": _date(assessment["kev_due_date"]),
        "cvss_score": None if assessment["cvss_score"] is None else float(assessment["cvss_score"]),
        "epss_score": None if assessment["epss_score"] is None else round(float(assessment["epss_score"]), 3),
        "asset_key": m["asset_key"],
        "asset_name": m["asset_name"],
        "asset_criticality": m["criticality"],
        "internet_exposed": bool(m["internet_exposed"]),
        "component": m["component_name"],
        "component_version": details.get("component_version"),
        "fixed_version": fixed_version(details),
        "version_status": m["version_status"],
        "is_direct": bool(m["is_direct"]),
        "contained_in": path[0] if not m["is_direct"] and len(path) > 1 else None,
        "from_report": m.get("raw_item_id") is not None,
        "trust_label": assessment.get("trust_label"),
        "manual_checks": [c["text"] for c in checks],
    }
    f["headline"] = headline(f)
    f["actions"] = actions(f)
    return f


def headline(f: dict[str, Any]) -> str:
    if f["kev_listed"] and f["risk_level"] in ("critical", "high"):
        return HEADLINE_KEV
    return HEADLINE[f["risk_level"]]


def actions(f: dict[str, Any]) -> list[str]:
    out = []
    comp = f["component"]
    if f["version_status"] == "unknown":
        out.append(f"Installierte Version von {comp} prüfen")
    if f["risk_level"] == "info":
        out.append(f"Hinweise zu {f['cve_id']} beobachten")
        return out
    if f["fixed_version"]:
        if f["contained_in"]:
            out.append(f"{comp} in {f['contained_in']} auf Version {f['fixed_version']} oder neuer aktualisieren "
                       f"und das Image neu bauen")
        else:
            out.append(f"{comp} auf Version {f['fixed_version']} oder neuer aktualisieren")
    else:
        out.append(f"Herstellerhinweise zu {f['cve_id']} prüfen und bis zum Update einen Workaround umsetzen")
    if f["internet_exposed"] and f["risk_level"] in ("critical", "high"):
        out.append("Erreichbarkeit aus dem Internet bis zum Update einschränken")
    if f["kev_listed"]:
        out.append("System auf Anzeichen einer Ausnutzung prüfen")
    return out


def render(audience: str, f: dict[str, Any], analysis: str) -> str:
    deadline = f["deadline"] or "keine feste Frist"
    manual = ("Manuelle Prüfung nötig: " + " ".join(f["manual_checks"])) if f["manual_checks"] else None
    affected = f"{f['asset_name']} ({f['asset_key']})"
    if audience == "it_security":
        comp = f"{f['component']} {f['component_version'] or ''}".strip()
        if f["contained_in"]:
            comp += f" in {f['contained_in']}"
        facts = [f"CVSS {f['cvss_score']}" if f["cvss_score"] is not None else "CVSS unbekannt"]
        if f["epss_score"] is not None:
            facts.append(f"EPSS {f['epss_score']}")
        facts.append("in CISA KEV" if f["kev_listed"] else "nicht in CISA KEV")
        lines = [f["headline"],
                 "Maßnahmen: " + "; ".join(f["actions"]),
                 f"Frist: {deadline}",
                 f"Betroffen: {affected} – {comp}",
                 f"Schwachstelle: {f['cve_id']} ({', '.join(facts)})"]
    elif audience == "management":
        lines = [f["headline"],
                 f"Risiko: {f['risk_level_de']} ({f['risk_score']}/100) · Frist: {deadline}",
                 f"Betroffen: {affected}",
                 f"Maßnahme: {f['actions'][0]}"]
    else:
        lines = [f"Risiko {f['risk_level_de']} für {f['asset_name']}: {f['headline']}. Frist: {deadline}."]
        if f["manual_checks"]:
            manual = f"Manuelle Prüfung nötig ({len(f['manual_checks'])} Punkt{'e' if len(f['manual_checks']) > 1 else ''})."
    if manual:
        lines.append(manual)
    lines.append(f"Einschätzung: {analysis}")
    return "\n".join(lines)


def template_analysis(audience: str, f: dict[str, Any]) -> str:
    """Mustertexte, wenn das LLM nicht genutzt wird oder die Pruefung nicht besteht."""
    exposed = "aus dem Internet erreichbar" if f["internet_exposed"] else "nur intern erreichbar"
    kev = " Die Lücke wird laut CISA bereits aktiv ausgenutzt." if f["kev_listed"] else ""
    if audience == "it_security":
        version = ("liegt im betroffenen Versionsbereich" if f["version_status"] == "affected"
                   else "ist nicht sicher einem Versionsbereich zuzuordnen")
        return (f"{f['component']} auf {f['asset_name']} {version}; das System ist {exposed}.{kev}")
    if audience == "management":
        return (f"Ein System mit Kritikalität {f['asset_criticality']} von 5 ist betroffen und {exposed}.{kev} "
                f"Die Maßnahme sollte bis zur Frist umgesetzt werden.")
    return f"Das Risiko ist {f['risk_level_de']}.{kev}".strip()


# ---------------------------------------------------------------- LLM

PROMPT = """Du bist Sicherheitsberater in einem deutschen Unternehmen. Schreibe zu einer bewerteten Schwachstelle
je Zielgruppe eine kurze Einschätzung auf Deutsch (1 bis 3 Sätze): warum die Maßnahme wichtig ist.
Risikostufe, Maßnahmen und Frist sind bereits festgelegt und werden separat angezeigt. Ändere sie nicht.
Regeln:
- Nutze nur Angaben aus dem Faktenpaket. Erfinde keine Versionen, Zahlen, Daten, CVE-Nummern, Hersteller oder Links.
- Behaupte keine aktive Ausnutzung, wenn kev_listed false ist.
- Stehen Punkte in manual_checks, weise darauf hin, dass ein Mensch sie prüfen muss.
- it_security: technisch und knapp. management: Auswirkung und Frist, ohne Fachbegriffe.
  executive: ein Satz, ob Handlungsbedarf besteht.
Antworte nur mit JSON: {{"it_security": "...", "management": "...", "executive": "..."}}
FAKTENPAKET: {facts}
"""


class LlmUnavailable(Exception):
    pass


def ask_llm(facts: dict[str, Any]) -> Any:
    """Ruft das lokale Ollama auf. Rueckgabe: geparstes JSON (Typ wird erst in validate geprueft)."""
    payload = {"model": config.LLM_MODEL, "prompt": PROMPT.format(facts=json.dumps(facts, ensure_ascii=False)),
               "format": "json", "stream": False, "options": {"temperature": 0}}
    try:
        with httpx.Client(timeout=httpx.Timeout(config.LLM_TIMEOUT, connect=5.0)) as client:
            response = client.post(f"{config.OLLAMA_URL}/api/generate", json=payload)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise LlmUnavailable(f"{type(exc).__name__}") from exc
    try:
        return json.loads(response.json().get("response", ""))
    except (ValueError, AttributeError):
        return None


# ---------------------------------------------------------------- Pruefregeln

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
NUMBER_RE = re.compile(r"\d+(?:[.,]\d+)*")
URL_RE = re.compile(r"https?://|www\.", re.IGNORECASE)
EXPLOIT_RE = re.compile(r"aktiv ausgenutzt|wird ausgenutzt|werden ausgenutzt|ausgenutzt wird", re.IGNORECASE)


def _numbers(text: str) -> set[str]:
    return {n.replace(",", ".").rstrip(".") for n in NUMBER_RE.findall(text)}


def allowed_numbers(facts: dict[str, Any]) -> set[str]:
    allowed = _numbers(json.dumps(facts, ensure_ascii=False))
    allowed |= {"5"}                                   # Kritikalitaet "von 5"
    for n in list(allowed):                            # 0.3 auch als 0.30 oder 30 % schreiben duerfen
        try:
            value = float(n)
        except ValueError:
            continue
        if 0 < value < 1:
            allowed.add(f"{value * 100:g}")
        if value == int(value):
            allowed.add(str(int(value)))
    return allowed


def validate(answer: Any, facts: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    """Gibt die gepruefen Texte zurueck und die Fehler (leer = bestanden)."""
    if not isinstance(answer, dict):
        return {}, ["no_json_object"]
    texts, errors = {}, []
    allowed = allowed_numbers(facts)
    known_cve = facts["cve_id"].upper() if facts.get("cve_id") else None
    for audience in AUDIENCES:
        text = answer.get(audience)
        if not isinstance(text, str) or not text.strip():
            errors.append(f"{audience}: leer")
            continue
        text = " ".join(text.split())
        if len(text) > MAX_LEN[audience]:
            errors.append(f"{audience}: zu lang ({len(text)})")
        if URL_RE.search(text):
            errors.append(f"{audience}: Link")
        foreign = {c.upper() for c in CVE_RE.findall(text)} - {known_cve}
        if foreign:
            errors.append(f"{audience}: fremde CVE {', '.join(sorted(foreign))}")
        unknown = sorted(n for n in _numbers(text) if n not in allowed)
        if unknown:
            errors.append(f"{audience}: Zahl nicht im Faktenpaket ({', '.join(unknown[:5])})")
        if not facts["kev_listed"] and EXPLOIT_RE.search(text):
            errors.append(f"{audience}: behauptet aktive Ausnutzung")
        if facts["risk_level"] != "critical" and re.search(r"\bkritisch", text, re.IGNORECASE):
            errors.append(f"{audience}: Risikostufe widerspricht")
        texts[audience] = text
    return texts, errors


# ---------------------------------------------------------------- Speichern

def _upsert(conn, assessment_id: int, audience: str, facts: dict, text: str, model: str, status: str,
            errors: list[str] | None) -> None:
    conn.execute("""
        INSERT INTO m3.recommendations (risk_assessment_id, audience, fact_package, text, llm_model,
                                        prompt_version, validation_status, validation_errors)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (risk_assessment_id, audience) DO UPDATE SET
            fact_package=EXCLUDED.fact_package, text=EXCLUDED.text, llm_model=EXCLUDED.llm_model,
            prompt_version=EXCLUDED.prompt_version, validation_status=EXCLUDED.validation_status,
            validation_errors=EXCLUDED.validation_errors, created_at=now()""",
        (assessment_id, audience, Jsonb(facts), text, model, PROMPT_VERSION, status,
         Jsonb(errors) if errors is not None else None))


def write_templates(conn, assessment_id: int, facts: dict[str, Any], errors: list[str] | None = None) -> None:
    for audience in AUDIENCES:
        _upsert(conn, assessment_id, audience, facts, render(audience, facts, template_analysis(audience, facts)),
                TEMPLATE_MODEL, "fallback_template", errors)


def refine_with_llm(conn, limit: int | None = None) -> dict[str, int]:
    """Ersetzt Mustertexte durch LLM-Texte fuer aktuelle Bewertungen ab der eingestellten Stufe.
    Laeuft ausserhalb der Transaktionen einzelner Meldungen (LLM-Aufrufe dauern Sekunden)."""
    stats = {"llm_passed": 0, "llm_fallback": 0, "llm_unavailable": 0}
    if not config.LLM_ENABLED:
        return stats
    rows = conn.execute("""
        SELECT rec.risk_assessment_id, rec.fact_package
          FROM m3.recommendations rec
          JOIN m3.risk_assessments ra ON ra.id = rec.risk_assessment_id
          JOIN m3.findings_current f ON f.risk_assessment_id = ra.id    -- nur sichtbare Treffer
         WHERE rec.audience = 'it_security' AND rec.llm_model = %s AND ra.risk_level = ANY(%s)
           AND (rec.validation_errors IS NULL OR rec.validation_errors = %s)
         ORDER BY ra.score DESC, ra.id
         LIMIT %s""",
        (TEMPLATE_MODEL, list(config.LLM_LEVELS), Jsonb([LLM_UNAVAILABLE]),
         limit or config.LLM_LIMIT)).fetchall()
    for row in rows:
        facts = row["fact_package"]
        try:
            answer = ask_llm(facts)
        except LlmUnavailable as exc:
            log.warning("M3: Ollama nicht erreichbar (%s), Mustertexte bleiben", exc)
            with conn.transaction():
                write_templates(conn, row["risk_assessment_id"], facts, [LLM_UNAVAILABLE])
            stats["llm_unavailable"] += 1
            break                                      # nicht fuer jede Bewertung erneut auf das Timeout warten
        texts, errors = validate(answer, facts)
        with conn.transaction():
            if errors:
                write_templates(conn, row["risk_assessment_id"], facts, errors)
                stats["llm_fallback"] += 1
                continue
            for audience in AUDIENCES:
                _upsert(conn, row["risk_assessment_id"], audience, facts, render(audience, facts, texts[audience]),
                        config.LLM_MODEL, "passed", [])
            stats["llm_passed"] += 1
    return stats
