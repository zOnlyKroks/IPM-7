-- Argos AI / M3 Unternehmensabgleich, Lieferkette und Risiko: initiales Schema v3
-- Stand 2026-11-16. Kompatibel mit m1_initial.sql und m2_initial.sql v1.2 (main @ 3e68075).
--
-- Laeuft beim allerersten Start von PostgreSQL nach m1_* und m2_* (alphabetisch).
-- Nach einer Aenderung: docker compose down -v
--
-- Regeln:
--   * M3 schreibt nur in das Schema m3. public.* (M1) und m2.* werden nur gelesen.
--   * Verweise nach aussen nur auf public.raw_items(id) (laut M1), nie auf cve_affected.id.
--   * Interne Inventardaten (Assets, Komponenten) verlassen das System nie.
--   * Schnittstelle zu M4 sind ausschliesslich die Views am Ende dieser Datei.
--   * Alle Zeitstempel in UTC (timestamptz).

BEGIN;

CREATE SCHEMA IF NOT EXISTS m3;

-- Frueh abbrechen, wenn M1 oder M2 fehlen.
DO $$
BEGIN
    IF to_regclass('public.raw_items') IS NULL THEN
        RAISE EXCEPTION 'M1 table public.raw_items does not exist. Run m1_initial.sql first.';
    END IF;
    IF to_regclass('m2.summaries') IS NULL THEN
        RAISE EXCEPTION 'M2 table m2.summaries does not exist. Run m2_initial.sql first.';
    END IF;
END $$;

CREATE FUNCTION m3.touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

-- =====================================================================
-- 1. assets: Inventar der Beispielfirma
--    Schreibt: M3 ueber POST /import/assets (CSV, von M4 weitergeleitet).
--    Ein CSV-Import ist ein vollstaendiger Schnappschuss: fehlende Assets
--    werden deaktiviert, nie geloescht (alte Treffer bleiben nachvollziehbar).
-- =====================================================================
CREATE TABLE m3.assets (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset_key        text        NOT NULL UNIQUE CHECK (btrim(asset_key) <> ''),
    name             text        NOT NULL CHECK (btrim(name) <> ''),
    asset_type       text        NOT NULL CHECK (asset_type IN
                        ('server', 'firewall', 'vpn_gateway', 'client', 'mail_server', 'database',
                         'web_application', 'container_host', 'network_device', 'other')),
    description      text,
    criticality      smallint    NOT NULL CHECK (criticality BETWEEN 1 AND 5),  -- 5 = geschaeftskritisch
    internet_exposed boolean     NOT NULL DEFAULT false,
    environment      text        NOT NULL DEFAULT 'production'
                        CHECK (environment IN ('production', 'staging', 'test')),
    owner_team       text,
    is_active        boolean     NOT NULL DEFAULT true,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER assets_touch_updated_at BEFORE UPDATE ON m3.assets
    FOR EACH ROW EXECUTE FUNCTION m3.touch_updated_at();

-- =====================================================================
-- 2. sbom_components: Software je Asset (manuell aus CSV oder aus Syft-SBOM)
--    Abhaengigkeitsgraph ueber parent_component_id, Pfade per WITH RECURSIVE.
--    Manuelle Komponenten werden ueber (Asset, Hersteller, Produkt) gefunden
--    und bei Versionsaenderung an Ort und Stelle aktualisiert: die id bleibt
--    stabil, bestehende Treffer bleiben verknuepft.
-- =====================================================================
CREATE TABLE m3.sbom_components (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset_id            bigint      NOT NULL REFERENCES m3.assets (id),
    parent_component_id bigint      REFERENCES m3.sbom_components (id),
    origin              text        NOT NULL CHECK (origin IN ('manual', 'sbom')),
    component_type      text        NOT NULL CHECK (component_type IN
                           ('operating_system', 'application', 'library', 'container_image',
                            'firmware', 'ai_model', 'cloud_service', 'other')),
    name                text        NOT NULL CHECK (btrim(name) <> ''),
    vendor              text,
    version             text,
    vendor_norm         text        CHECK (vendor_norm = lower(vendor_norm)),   -- gleiche Form wie cve_affected.vendor
    product_norm        text        CHECK (product_norm = lower(product_norm)), -- gleiche Form wie cve_affected.product
    vendor_country      text        CHECK (vendor_country ~ '^[A-Z]{2}$'),      -- ISO 3166-1 alpha-2, fuer vendor_exposure
    cpe23               text        CHECK (cpe23 LIKE 'cpe:2.3:%'),
    purl                text        CHECK (purl LIKE 'pkg:%'),
    osv_ecosystem       text,                                                   -- aus der purl abgeleitet, z. B. "npm", "PyPI", "Go"
    osv_package         text,                                                   -- Paketname wie in OSV (PyPI normalisiert); NULL = nicht abgleichbar (z. B. deb/apk)
    image_ref           text,                                                   -- nur sbom, z. B. "n8nio/n8n:1.70.1"
    sbom_sha256         text        CHECK (sbom_sha256 ~ '^[0-9a-f]{64}$'),     -- nur sbom
    is_active           boolean     NOT NULL DEFAULT true,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CHECK (parent_component_id IS NULL OR parent_component_id <> id),
    -- manuelle Eintraege: Produkt Pflicht, keine Eltern, keine SBOM-Felder
    CHECK (origin <> 'manual'
           OR (product_norm IS NOT NULL AND parent_component_id IS NULL
               AND image_ref IS NULL AND sbom_sha256 IS NULL)),
    -- SBOM-Eintraege: Image und Hash der SBOM-Datei Pflicht
    CHECK (origin <> 'sbom' OR (image_ref IS NOT NULL AND sbom_sha256 IS NOT NULL))
);

COMMENT ON COLUMN m3.sbom_components.vendor_norm IS
    'Kleingeschrieben, ohne Rechtsform. Gleiche Normalisierungsfunktion wie fuer cve_affected-Abgleich.';

-- Eine Version je Produkt und Asset (Prototyp-Vereinfachung); auch inaktive Zeilen,
-- damit ein wieder auftauchendes Produkt dieselbe Zeile reaktiviert.
CREATE UNIQUE INDEX sbom_components_manual_uidx ON m3.sbom_components
    (asset_id, coalesce(vendor_norm, ''), product_norm) WHERE origin = 'manual';
-- SBOM: ein Paket je Image und Asset; neue Paketversion = neue purl = neue Zeile
CREATE UNIQUE INDEX sbom_components_sbom_uidx ON m3.sbom_components
    (asset_id, image_ref, coalesce(purl, name || '@' || coalesce(version, ''))) WHERE origin = 'sbom';
CREATE INDEX sbom_components_asset_idx          ON m3.sbom_components (asset_id);
CREATE INDEX sbom_components_parent_idx         ON m3.sbom_components (parent_component_id);
CREATE INDEX sbom_components_vendor_product_idx ON m3.sbom_components (vendor_norm, product_norm);
CREATE INDEX sbom_components_purl_idx           ON m3.sbom_components (purl);
CREATE INDEX sbom_components_osv_idx            ON m3.sbom_components (osv_ecosystem, osv_package) WHERE is_active;

CREATE TRIGGER sbom_components_touch_updated_at BEFORE UPDATE ON m3.sbom_components
    FOR EACH ROW EXECUTE FUNCTION m3.touch_updated_at();

-- =====================================================================
-- 3. matches: welche Meldung betrifft welche Komponente
--    match_key = cve_id bei CVE-basierten Treffern, sonst 'raw:<raw_item_id>'.
--    Lebenszyklus: open -> resolved (mit Grund), nie geloescht.
--    "nicht betroffen" wird nicht gespeichert, beendet aber einen offenen Treffer.
-- =====================================================================
CREATE TABLE m3.matches (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    raw_item_id     bigint       REFERENCES public.raw_items (id),   -- NULL = Fund direkt aus dem Inventar, ohne Meldung
    component_id    bigint       NOT NULL REFERENCES m3.sbom_components (id),
    cve_id          text         CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    match_key       text         NOT NULL,
    match_method    text         NOT NULL CHECK (match_method IN
                       ('cpe_version', 'purl_version', 'cpe_product_only', 'name_only', 'vendor_exposure')),
    confidence      numeric(3,2) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    version_status  text         NOT NULL CHECK (version_status IN ('affected', 'unknown', 'not_applicable')),
    is_direct       boolean      NOT NULL,          -- false = nur ueber eine Abhaengigkeit betroffen
    dependency_path bigint[]     NOT NULL,          -- Komponenten-IDs von oben bis zur betroffenen Komponente
    match_details   jsonb        NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(match_details) = 'object'),
    status          text         NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    resolved_at     timestamptz,
    resolved_reason text         CHECK (resolved_reason IN
                       ('version_not_affected', 'component_removed', 'asset_deactivated',
                        'advisory_changed', 'suppressed')),
    created_at      timestamptz  NOT NULL DEFAULT now(),
    updated_at      timestamptz  NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (raw_item_id, component_id, match_key),
    CHECK (raw_item_id IS NOT NULL OR cve_id IS NOT NULL),
    CHECK (match_key = coalesce(cve_id, 'raw:' || raw_item_id)),
    -- CVE-Pfade brauchen eine CVE, vendor_exposure prueft keine Version
    CHECK (match_method NOT IN ('cpe_version', 'purl_version', 'cpe_product_only') OR cve_id IS NOT NULL),
    CHECK ((match_method = 'vendor_exposure') = (version_status = 'not_applicable')),
    CHECK ((status = 'resolved') = (resolved_at IS NOT NULL AND resolved_reason IS NOT NULL)),
    CHECK (cardinality(dependency_path) >= 1 AND dependency_path[cardinality(dependency_path)] = component_id)
);

COMMENT ON COLUMN m3.matches.match_details IS
    'Gegriffene Regel als Werte (cpe, Versionsgrenzen, purl, Namen), nie cve_affected.id.';

CREATE INDEX matches_raw_item_idx  ON m3.matches (raw_item_id);
CREATE INDEX matches_component_idx ON m3.matches (component_id);
CREATE INDEX matches_open_idx      ON m3.matches (id) WHERE status = 'open';

CREATE TRIGGER matches_touch_updated_at BEFORE UPDATE ON m3.matches
    FOR EACH ROW EXECUTE FUNCTION m3.touch_updated_at();

-- =====================================================================
-- 4. suppressions: von Analysten als Fehlalarm markiert (ueber M4 -> POST /suppressions)
--    Beim erneuten Abgleich wird (component_id, match_key) uebersprungen.
-- =====================================================================
CREATE TABLE m3.suppressions (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    component_id bigint      NOT NULL REFERENCES m3.sbom_components (id),
    match_key    text        NOT NULL,
    reason       text        NOT NULL CHECK (btrim(reason) <> ''),
    created_by   text        NOT NULL,
    is_active    boolean     NOT NULL DEFAULT true,     -- false = Markierung aufgehoben
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX suppressions_active_uidx ON m3.suppressions (component_id, match_key) WHERE is_active;

CREATE TRIGGER suppressions_touch_updated_at BEFORE UPDATE ON m3.suppressions
    FOR EACH ROW EXECUTE FUNCTION m3.touch_updated_at();

-- =====================================================================
-- 5. risk_assessments: nachrechenbarer Risiko-Score
--    Historie bleibt erhalten, genau eine Zeile je Treffer ist aktuell.
--    Neue Bewertung = neue Zeile = neue id (M4 benachrichtigt je id genau einmal).
--    Massnahme und Frist regelbasiert aus m3_risk/app/risk_policy.yaml.
-- =====================================================================
CREATE TABLE m3.risk_assessments (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    match_id          bigint       NOT NULL REFERENCES m3.matches (id),
    is_current        boolean      NOT NULL DEFAULT true,
    scoring_branch    text         NOT NULL CHECK (scoring_branch IN ('cve', 'vendor_exposure')),
    score             numeric(5,2) NOT NULL CHECK (score BETWEEN 0 AND 100),
    risk_level        text         NOT NULL CHECK (risk_level IN ('critical', 'high', 'medium', 'low', 'info')),
    action_code       text         NOT NULL,         -- z. B. 'patch_immediately', 'review_vendor_dependency'
    deadline_at       timestamptz,                   -- min(Policy-Frist, KEV-Frist)
    policy_version    text         NOT NULL,
    -- Schnappschuss der Eingangswerte zum Bewertungszeitpunkt
    cvss_score        numeric(3,1),
    cvss_version      text,
    kev_listed        boolean,
    kev_due_date      date,
    epss_score        numeric,
    asset_criticality smallint     NOT NULL,
    internet_exposed  boolean      NOT NULL,
    match_confidence  numeric(3,2) NOT NULL,
    trust_score       numeric(5,4) CHECK (trust_score BETWEEN 0 AND 1),
    trust_label       text         CHECK (trust_label IN ('CONFIRMED', 'UNCONFIRMED', 'CONTRADICTORY')),
    category          text         NOT NULL,         -- M2 summaries.category zum Bewertungszeitpunkt
    factor_breakdown  jsonb        NOT NULL CHECK (jsonb_typeof(factor_breakdown) = 'object'),
    -- Faelle, die ein Mensch pruefen muss: [{"code": "version_unknown", "text": "..."}], leer = keine
    manual_checks     jsonb        NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(manual_checks) = 'array'),
    risk_fingerprint  text         NOT NULL,
    assessed_at       timestamptz  NOT NULL DEFAULT now(),
    -- vendor_exposure ist hoechstens medium (kein CVSS/KEV/EPSS, Namensabgleich)
    CHECK (scoring_branch <> 'vendor_exposure' OR risk_level IN ('medium', 'low', 'info'))
);
CREATE UNIQUE INDEX risk_assessments_current_uidx ON m3.risk_assessments (match_id) WHERE is_current;
CREATE INDEX risk_assessments_match_idx ON m3.risk_assessments (match_id);

-- =====================================================================
-- 6. recommendations: Text je Zielgruppe, vom lokalen LLM formuliert
--    Das LLM erhaelt nur fact_package; Pruefregel gegen erfundene Werte.
-- =====================================================================
CREATE TABLE m3.recommendations (
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    risk_assessment_id bigint      NOT NULL REFERENCES m3.risk_assessments (id) ON DELETE CASCADE,
    audience           text        NOT NULL CHECK (audience IN ('it_security', 'management', 'executive')),
    fact_package       jsonb       NOT NULL CHECK (jsonb_typeof(fact_package) = 'object'),
    text               text        NOT NULL CHECK (btrim(text) <> ''),
    llm_model          text        NOT NULL,         -- z. B. "qwen2.5:7b"; "template" beim Fallback
    prompt_version     text        NOT NULL,
    validation_status  text        NOT NULL CHECK (validation_status IN ('passed', 'fallback_template')),
    validation_errors  jsonb       CHECK (validation_errors IS NULL OR jsonb_typeof(validation_errors) = 'array'),
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (risk_assessment_id, audience)
);

-- =====================================================================
-- 7. evidence: jede Aussage einer Bewertung mit Beleg
--    Haengt an der Bewertung (gleiche Fakten fuer alle Zielgruppen).
-- =====================================================================
CREATE TABLE m3.evidence (
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    risk_assessment_id bigint NOT NULL REFERENCES m3.risk_assessments (id) ON DELETE CASCADE,
    claim_key          text   NOT NULL,              -- z. B. 'kev_listed', 'affected_version', 'asset_count'
    claim_text         text   NOT NULL,
    source_kind        text   NOT NULL CHECK (source_kind IN
                          ('raw_item', 'cve_fact', 'cve_affected', 'inventory', 'sbom', 'm2_analysis')),
    raw_item_id        bigint REFERENCES public.raw_items (id),
    source_url         text,
    ref_detail         jsonb  CHECK (ref_detail IS NULL OR jsonb_typeof(ref_detail) = 'object'),
    CHECK (source_kind <> 'raw_item' OR raw_item_id IS NOT NULL)
);
CREATE INDEX evidence_assessment_idx ON m3.evidence (risk_assessment_id);

-- =====================================================================
-- 8. processing: Verarbeitungsstand je Meldung
--    Offen = in m2.summaries vorhanden UND (keine Zeile hier ODER Fingerabdruck geaendert).
--    Fingerabdruecke ueber die tatsaechlich genutzten Werte, nicht ueber Zeitstempel.
-- =====================================================================
CREATE TABLE m3.processing (
    raw_item_id       bigint      PRIMARY KEY REFERENCES public.raw_items (id),
    status            text        NOT NULL CHECK (status IN ('done', 'no_match', 'skipped', 'failed')),
    category          text,
    match_fingerprint text,       -- cve_ids, cve_affected (NVD und OSV), M2-Entitaeten inkl. version_text, Inventarstand ohne Kritikalitaet
    risk_fingerprint  text,       -- CVSS/KEV/EPSS, Trust, Kategorie, Kritikalitaet und Exposition aktiver Assets, policy_version
    attempts          smallint    NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error        text,
    processed_at      timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CHECK (status = 'failed' OR (match_fingerprint IS NOT NULL AND risk_fingerprint IS NOT NULL))
);
CREATE INDEX processing_failed_idx ON m3.processing (raw_item_id) WHERE status = 'failed';

CREATE TRIGGER processing_touch_updated_at BEFORE UPDATE ON m3.processing
    FOR EACH ROW EXECUTE FUNCTION m3.touch_updated_at();

-- =====================================================================
-- 9. Views: einzige Schnittstelle zu M4 (nur lesen)
-- =====================================================================

-- Alle Treffer inkl. erledigter, mit aktueller (bzw. letzter) Bewertung
CREATE VIEW m3.findings_history AS
SELECT
    m.id                              AS match_id,
    ra.id                             AS risk_assessment_id,
    m.status,
    m.resolved_at,
    m.resolved_reason,
    r.id                              AS raw_item_id,
    coalesce(r.title_de, r.title, 'Bekannte Schwachstelle ' || m.cve_id || ' im Inventar') AS title,
    coalesce(r.url, 'https://nvd.nist.gov/vuln/detail/' || m.cve_id) AS url,
    coalesce(r.published_at, r.fetched_at,
             (SELECT f.published_at FROM public.cve_facts f WHERE f.cve_id = m.cve_id), m.created_at) AS published_at,
    m.cve_id,
    ra.category,
    ra.trust_score,
    ra.trust_label,
    a.id                              AS asset_id,
    a.asset_key,
    a.name                            AS asset_name,
    a.criticality,
    a.internet_exposed,
    a.is_active                       AS asset_is_active,
    c.id                              AS component_id,
    c.name                            AS component_name,
    c.vendor                          AS component_vendor,
    c.version                         AS component_version,
    c.is_active                       AS component_is_active,
    (SELECT array_agg(pc.name ORDER BY p.ord)
       FROM unnest(m.dependency_path) WITH ORDINALITY AS p(component_id, ord)
       JOIN m3.sbom_components pc ON pc.id = p.component_id) AS dependency_path_names,
    m.match_method,
    m.confidence,
    m.version_status,
    m.is_direct,
    ra.score                          AS risk_score,
    ra.risk_level,
    ra.action_code,
    ra.deadline_at,
    ra.manual_checks,
    ra.factor_breakdown,
    ra.assessed_at,
    (SELECT jsonb_object_agg(rec.audience, rec.text)
       FROM m3.recommendations rec WHERE rec.risk_assessment_id = ra.id) AS recommendations,
    (SELECT jsonb_agg(jsonb_build_object('claim_key', e.claim_key, 'claim_text', e.claim_text,
                                         'source_kind', e.source_kind, 'raw_item_id', e.raw_item_id,
                                         'source_url', e.source_url) ORDER BY e.id)
       FROM m3.evidence e WHERE e.risk_assessment_id = ra.id) AS evidence
FROM m3.matches m
JOIN m3.sbom_components c ON c.id = m.component_id
JOIN m3.assets a          ON a.id = c.asset_id
LEFT JOIN public.raw_items r ON r.id = m.raw_item_id
LEFT JOIN m3.risk_assessments ra ON ra.match_id = m.id AND ra.is_current;

COMMENT ON VIEW m3.findings_history IS
    'Alle Treffer inkl. erledigter (status, resolved_reason). Fuer Verlauf und Entwarnungen in M4.';

-- Nur offene, bewertete Treffer auf aktiven Assets und Komponenten
CREATE VIEW m3.findings_current AS
SELECT *
FROM m3.findings_history
WHERE status = 'open'
  AND asset_is_active
  AND component_is_active
  AND risk_assessment_id IS NOT NULL
  -- Inventarfund ausblenden, wenn dieselbe CVE auf derselben Komponente schon ueber eine Meldung offen ist
  AND (raw_item_id IS NOT NULL OR NOT EXISTS (
        SELECT 1 FROM m3.matches x
         WHERE x.component_id = findings_history.component_id AND x.cve_id = findings_history.cve_id
           AND x.raw_item_id IS NOT NULL AND x.status = 'open'));

COMMENT ON VIEW m3.findings_current IS
    'Aktuelle Befunde fuer Uebersicht, Detailansicht und Benachrichtigung. M4 benachrichtigt je risk_assessment_id einmal.';

-- Inventaruebersicht fuer die Verwaltungsseite in M4
CREATE VIEW m3.assets_overview AS
SELECT
    a.id                AS asset_id,
    a.asset_key,
    a.name,
    a.asset_type,
    a.criticality,
    a.internet_exposed,
    a.environment,
    a.owner_team,
    a.is_active,
    a.updated_at,
    (SELECT count(*) FROM m3.sbom_components c
      WHERE c.asset_id = a.id AND c.is_active AND a.is_active) AS active_component_count,
    (SELECT count(*) FROM m3.findings_current f
      WHERE f.asset_id = a.id)                 AS open_finding_count,
    (SELECT f.risk_level FROM m3.findings_current f
      WHERE f.asset_id = a.id
      ORDER BY array_position(ARRAY['critical','high','medium','low','info'], f.risk_level)
      LIMIT 1)                                 AS highest_risk_level,
    (SELECT jsonb_agg(jsonb_build_object('component_id', c.id, 'name', c.name, 'vendor', c.vendor,
                                         'version', c.version, 'component_type', c.component_type,
                                         'origin', c.origin, 'is_active', c.is_active) ORDER BY c.id)
       FROM m3.sbom_components c
      WHERE c.asset_id = a.id AND c.parent_component_id IS NULL) AS top_level_components
FROM m3.assets a;

COMMENT ON VIEW m3.assets_overview IS
    'Inventar fuer die Verwaltungsseite in M4. Aenderungen am Inventar nur ueber POST /import/assets und /import/sbom.';

COMMIT;
