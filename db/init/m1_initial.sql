-- M1 Datenerfassung und Plattform: initiales Schema
-- Konzept und Regeln fuer alle Module: db/schema_m1.md
--
-- Laeuft beim allerersten Start von PostgreSQL (docker-entrypoint-initdb.d, alphabetisch,
-- also vor m2_*, m3_*, m4_*). Nach einer Aenderung: docker compose down -v
--
-- Andere Module duerfen nur auf sources(id) und raw_items(id) verweisen (beide bigint),
-- nicht auf cve_facts und nicht auf cve_affected.id.

BEGIN;

-- ---------------------------------------------------------------- Hilfsfunktion

CREATE FUNCTION m1_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------- sources
-- Gehoert M4 (nur die API schreibt), M1 bis M3 lesen. Liegt hier, weil raw_items darauf verweist.
-- Quellen werden nie geloescht, nur deaktiviert oder gesperrt. Der Abrufstatus steht in fetch_runs.

CREATE TABLE sources (
    id                     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                   text         NOT NULL UNIQUE,
    url                    text         NOT NULL,
    connector              text         NOT NULL
        CHECK (connector IN ('rss', 'cisa_kev', 'nvd', 'epss', 'osv')),
    source_type            text         NOT NULL
        CHECK (source_type IN ('authority', 'vendor', 'press', 'social')),
    language               text
        CHECK (language ~ '^[a-z]{2}(-[a-z]{2})?$'),
    trust_weight           numeric(3,2) NOT NULL DEFAULT 0.5
        CHECK (trust_weight BETWEEN 0 AND 1),
    is_primary_source      boolean      NOT NULL DEFAULT false,
    is_priority            boolean      NOT NULL DEFAULT false,
    status                 text         NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled', 'blocked')),
    fetch_interval_minutes integer      NOT NULL DEFAULT 30
        CHECK (fetch_interval_minutes > 0),
    config                 jsonb        NOT NULL DEFAULT '{}'
        CHECK (jsonb_typeof(config) = 'object'),
    created_at             timestamptz  NOT NULL DEFAULT now(),
    updated_at             timestamptz  NOT NULL DEFAULT now()
);

COMMENT ON TABLE sources IS 'Konfigurierte Quellen. Schreibt nur M4, M1 bis M3 lesen.';
COMMENT ON COLUMN sources.config IS 'Connector-spezifische Einstellungen, niemals Zugangsdaten (die stehen in .env).';
COMMENT ON COLUMN sources.is_priority IS 'Wird im Eilmeldungs-Lauf (scope = priority) abgerufen.';

CREATE TRIGGER sources_touch_updated_at
    BEFORE UPDATE ON sources
    FOR EACH ROW EXECUTE FUNCTION m1_touch_updated_at();

-- ---------------------------------------------------------------- fetch_runs
-- Ein Abruf einer Quelle. fetch_state des letzten erfolgreichen Laufs ist der Startpunkt des naechsten.

CREATE TABLE fetch_runs (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id       bigint      NOT NULL REFERENCES sources (id) ON DELETE RESTRICT,
    scope           text        NOT NULL
        CHECK (scope IN ('regular', 'priority', 'manual')),
    status          text        NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'success', 'failed')),
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    attempts        smallint    NOT NULL DEFAULT 1 CHECK (attempts >= 1),
    http_status     integer,
    items_seen      integer     NOT NULL DEFAULT 0 CHECK (items_seen >= 0),
    items_new       integer     NOT NULL DEFAULT 0 CHECK (items_new >= 0),
    items_duplicate integer     NOT NULL DEFAULT 0 CHECK (items_duplicate >= 0),
    items_failed    integer     NOT NULL DEFAULT 0 CHECK (items_failed >= 0),
    error_message   text,
    fetch_state     jsonb
        CHECK (jsonb_typeof(fetch_state) = 'object'),
    -- ein laufender Abruf hat kein Ende, ein beendeter immer
    CHECK ((status = 'running') = (finished_at IS NULL)),
    CHECK (finished_at IS NULL OR finished_at >= started_at)
);

COMMENT ON TABLE fetch_runs IS 'Abrufprotokoll je Quelle. Letzter Status einer Quelle = juengste Zeile nach started_at.';
COMMENT ON COLUMN fetch_runs.fetch_state IS 'ETag, Last-Modified oder Zeitstempel fuer den naechsten inkrementellen Abruf.';

CREATE INDEX fetch_runs_source_started_idx ON fetch_runs (source_id, started_at DESC);
CREATE INDEX fetch_runs_last_success_idx
    ON fetch_runs (source_id, started_at DESC) WHERE status = 'success';

-- ---------------------------------------------------------------- raw_items
-- Normalisierte Meldungen. Nach der Freigabe (translation_status <> 'pending') unveraendert.

CREATE TABLE raw_items (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id            bigint      NOT NULL REFERENCES sources (id) ON DELETE RESTRICT,
    fetch_run_id         bigint      REFERENCES fetch_runs (id) ON DELETE SET NULL,
    external_id          text        NOT NULL CHECK (external_id <> ''),
    url                  text        NOT NULL,
    title                text        NOT NULL,
    body                 text        NOT NULL DEFAULT '',
    lang                 text
        CHECK (lang ~ '^[a-z]{2}(-[a-z]{2})?$'),
    title_de             text,
    body_de              text,
    translation_status   text        NOT NULL DEFAULT 'pending'
        CHECK (translation_status IN ('pending', 'done', 'not_needed', 'failed')),
    translation_attempts smallint    NOT NULL DEFAULT 0 CHECK (translation_attempts >= 0),
    cve_ids              text[]      NOT NULL DEFAULT '{}',
    published_at         timestamptz,
    fetched_at           timestamptz NOT NULL DEFAULT now(),
    content_hash         text        NOT NULL
        CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    raw_payload          jsonb,
    UNIQUE (source_id, external_id),
    UNIQUE (source_id, content_hash),
    -- uebersetzte und deutsche Meldungen haben immer einen deutschen Text
    CHECK (translation_status NOT IN ('done', 'not_needed')
           OR (title_de IS NOT NULL AND body_de IS NOT NULL)),
    -- nur gueltige CVE-IDs, keine NULL-Elemente, damit der Join auf cve_facts sicher greift
    CHECK (array_position(cve_ids, NULL) IS NULL
           AND array_to_string(cve_ids, ',') ~ '^(CVE-[0-9]{4}-[0-9]{4,}(,CVE-[0-9]{4}-[0-9]{4,})*)?$')
);

COMMENT ON TABLE raw_items IS 'Normalisierte Meldungen. Offen fuer M2: translation_status <> ''pending'' und noch keine M2-Zeile. Text lesen mit COALESCE(title_de, title), COALESCE(body_de, body).';
COMMENT ON COLUMN raw_items.content_hash IS 'SHA-256 (hex, kleingeschrieben) von normalisiertem Titel und Text. Eindeutig nur je Quelle; identische Inhalte aus anderen Quellen bleiben erhalten (Bestaetigung durch unabhaengige Quellen, z. B. GROUP BY content_hash).';
COMMENT ON COLUMN raw_items.published_at IS 'NULL, wenn die Quelle kein Datum liefert. Dann gilt fetched_at.';

CREATE INDEX raw_items_cve_ids_idx      ON raw_items USING gin (cve_ids);
CREATE INDEX raw_items_pending_idx      ON raw_items (id) WHERE translation_status = 'pending';
CREATE INDEX raw_items_fetch_run_id_idx ON raw_items (fetch_run_id);
CREATE INDEX raw_items_content_hash_idx ON raw_items (content_hash);

-- ---------------------------------------------------------------- cve_facts
-- Eine Zeile pro CVE. NULL heisst "unbekannt", nicht 0.
-- updated_at aendert sich nur, wenn sich ein Faktenwert wirklich aendert (nicht bei *_checked_at),
-- damit M3 daran erkennen kann, dass eine Bewertung neu berechnet werden muss.

CREATE TABLE cve_facts (
    cve_id              text        PRIMARY KEY
        CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    description         text,
    nvd_status          text,
    published_at        timestamptz,
    nvd_modified_at     timestamptz,
    nvd_checked_at      timestamptz,
    cvss_score          numeric(3,1)
        CHECK (cvss_score BETWEEN 0 AND 10),
    cvss_vector         text,
    cvss_version        text
        CHECK (cvss_version IN ('2.0', '3.0', '3.1', '4.0')),
    cvss_severity       text
        CHECK (cvss_severity IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    cwe_ids             text[]      NOT NULL DEFAULT '{}',
    kev_listed          boolean     NOT NULL DEFAULT false,
    kev_date_added      date,
    kev_due_date        date,
    kev_required_action text,
    kev_ransomware_use  text,
    epss_score          numeric
        CHECK (epss_score BETWEEN 0 AND 1),
    epss_percentile     numeric
        CHECK (epss_percentile BETWEEN 0 AND 1),
    epss_date           date,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    -- ein CVSS-Wert ohne Version laesst sich nicht einordnen
    CHECK ((cvss_score IS NULL) = (cvss_version IS NULL))
);

COMMENT ON TABLE cve_facts IS 'Harte Fakten je CVE aus NVD, CISA KEV und EPSS. Keine Fremdschluessel aus anderen Modulen, nur per Join.';
COMMENT ON COLUMN cve_facts.updated_at IS 'Zeitpunkt der letzten echten Faktenaenderung. M1 aktualisiert ihn auch, wenn sich cve_affected einer CVE inhaltlich aendert.';

CREATE FUNCTION m1_cve_facts_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.description, NEW.nvd_status, NEW.published_at, NEW.nvd_modified_at,
        NEW.cvss_score, NEW.cvss_vector, NEW.cvss_version, NEW.cvss_severity, NEW.cwe_ids,
        NEW.kev_listed, NEW.kev_date_added, NEW.kev_due_date, NEW.kev_required_action,
        NEW.kev_ransomware_use, NEW.epss_score, NEW.epss_percentile, NEW.epss_date)
       IS DISTINCT FROM
       (OLD.description, OLD.nvd_status, OLD.published_at, OLD.nvd_modified_at,
        OLD.cvss_score, OLD.cvss_vector, OLD.cvss_version, OLD.cvss_severity, OLD.cwe_ids,
        OLD.kev_listed, OLD.kev_date_added, OLD.kev_due_date, OLD.kev_required_action,
        OLD.kev_ransomware_use, OLD.epss_score, OLD.epss_percentile, OLD.epss_date)
    THEN
        NEW.updated_at := now();
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cve_facts_touch_updated_at
    BEFORE UPDATE ON cve_facts
    FOR EACH ROW EXECUTE FUNCTION m1_cve_facts_touch_updated_at();

CREATE INDEX cve_facts_kev_listed_idx ON cve_facts (cve_id) WHERE kev_listed;
CREATE INDEX cve_facts_updated_at_idx ON cve_facts (updated_at);

-- ---------------------------------------------------------------- cve_affected
-- Betroffene Produkte und Versionsbereiche je CVE. Pro (cve_id, data_source) ersetzt M1 alle
-- Zeilen in einer Transaktion, die id ist deshalb nicht stabil und darf nicht referenziert werden.
-- Versionen sind Text: SQL findet Kandidaten, den Versionsvergleich macht M3 in Python.

CREATE TABLE cve_affected (
    id                      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id                  text NOT NULL REFERENCES cve_facts (cve_id) ON DELETE CASCADE,
    data_source             text NOT NULL
        CHECK (data_source IN ('nvd', 'osv')),
    cpe                     text,
    vendor                  text CHECK (vendor = lower(vendor)),
    product                 text CHECK (product = lower(product)),
    ecosystem               text,
    package_name            text,
    version_exact           text,
    version_start_including text,
    version_start_excluding text,
    version_end_including   text,
    version_end_excluding   text,
    -- NVD liefert CPEs, OSV liefert Pakete
    CHECK ((data_source = 'nvd' AND cpe IS NOT NULL)
        OR (data_source = 'osv' AND ecosystem IS NOT NULL AND package_name IS NOT NULL)),
    -- eine Untergrenze ist entweder einschliessend oder ausschliessend, nie beides
    CHECK (version_start_including IS NULL OR version_start_excluding IS NULL),
    CHECK (version_end_including IS NULL OR version_end_excluding IS NULL)
);

COMMENT ON TABLE cve_affected IS 'Betroffene Produkte (NVD: CPE) und Pakete (OSV) je CVE mit Versionsbereichen.';

CREATE INDEX cve_affected_cve_id_idx          ON cve_affected (cve_id);
CREATE INDEX cve_affected_vendor_product_idx  ON cve_affected (vendor, product);
CREATE INDEX cve_affected_ecosystem_pkg_idx   ON cve_affected (ecosystem, package_name);

COMMIT;
