-- Argos AI / M4 Zentrale API und Benachrichtigung: initiales Schema
-- Eigene Tabellen von M4 (Schema m4): users, recipient_groups, recipients, notification_rules,
-- notification_log, item_status, audit_log.
-- Die Tabelle public.sources gehoert zwar M4 (nur die API schreibt), liegt aber in m1_initial.sql,
-- weil raw_items darauf verweist.
--
-- Laeuft beim allerersten Start von PostgreSQL (docker-entrypoint-initdb.d, alphabetisch),
-- also nach m1_*, m2_*, m3_*. Nach einer Aenderung: docker compose down -v
--
-- Regeln:
--   * M4 schreibt nur in das Schema m4 und in public.sources. Alles andere wird nur gelesen.
--   * Fremdschluessel nach aussen nur auf public.raw_items(id) (laut M1).
--   * Verweise auf M3 (match_id, risk_assessment_id) sind bewusst ohne Fremdschluessel.
--     M4 liest M3 ausschliesslich ueber die Views m3.findings_current, m3.findings_history, m3.assets_overview.
--   * Abweichung von den Namen im Arbeitspaket: notifications heisst notification_log,
--     alert_status heisst item_status.
--   * Alle Zeitstempel in UTC (timestamptz).

BEGIN;

CREATE SCHEMA IF NOT EXISTS m4;

-- Frueh abbrechen, wenn M1 fehlt.
DO $$
BEGIN
    IF to_regclass('public.raw_items') IS NULL OR to_regclass('public.sources') IS NULL THEN
        RAISE EXCEPTION 'M1 tables public.raw_items/public.sources do not exist. Run m1_initial.sql first.';
    END IF;
END $$;

-- ---------------------------------------------------------------- Hilfsfunktionen

CREATE FUNCTION m4.touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

CREATE FUNCTION m4.forbid_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% ist nur zum Anhaengen gedacht (% nicht erlaubt)', TG_TABLE_NAME, TG_OP;
END;
$$;

-- Reihenfolge der Risikostufen (gleiche Werte wie m3.risk_assessments.risk_level).
-- Damit laesst sich "hoeher als zuletzt gemeldet" direkt in SQL vergleichen.
CREATE FUNCTION m4.risk_rank(level text) RETURNS smallint
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT CASE level
        WHEN 'info'     THEN 1
        WHEN 'low'      THEN 2
        WHEN 'medium'   THEN 3
        WHEN 'high'     THEN 4
        WHEN 'critical' THEN 5
    END::smallint;
$$;

-- ---------------------------------------------------------------- users
-- Anmeldung und Rollen. Der erste Admin wird beim Start von M4 aus der .env angelegt
-- (ADMIN_USERNAME, ADMIN_PASSWORD), nie per SQL mit festem Passwort.
-- Rollen:
--   admin   alles, inklusive Quellen, Regeln, Empfaenger, Inventar-Import und Benutzer
--   analyst Meldungen bearbeiten (item_status), Fehlalarme markieren, manuellen Lauf starten
--   viewer  nur lesen

CREATE TABLE m4.users (
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username           text        NOT NULL
        CHECK (username ~ '^[A-Za-z0-9._-]{3,64}$'),
    password_hash      text        NOT NULL CHECK (password_hash <> ''),
    role               text        NOT NULL DEFAULT 'viewer'
        CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_active          boolean     NOT NULL DEFAULT true,
    token_version      integer     NOT NULL DEFAULT 0 CHECK (token_version >= 0),
    failed_login_count smallint    NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
    locked_until       timestamptz,
    last_login_at      timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE m4.users IS 'Benutzer der Weboberflaeche. Werden nie geloescht, nur deaktiviert (Audit-Log verweist darauf).';
COMMENT ON COLUMN m4.users.password_hash IS 'Nur gehasht (argon2 oder bcrypt), niemals Klartext.';
COMMENT ON COLUMN m4.users.token_version IS 'Steht im JWT. Erhoehen bei Passwortwechsel, Rollenwechsel oder Deaktivierung: alte Tokens werden ungueltig.';
COMMENT ON COLUMN m4.users.locked_until IS 'Nach zu vielen Fehlversuchen kurz gesperrt (Brute-Force-Schutz).';

CREATE UNIQUE INDEX users_username_lower_idx ON m4.users (lower(username));

CREATE TRIGGER users_touch_updated_at
    BEFORE UPDATE ON m4.users
    FOR EACH ROW EXECUTE FUNCTION m4.touch_updated_at();

-- ---------------------------------------------------------------- recipient_groups
-- audience entspricht m3.recommendations.audience: die Gruppe bekommt den Text ihrer Zielgruppe.

CREATE TABLE m4.recipient_groups (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        text        NOT NULL UNIQUE CHECK (name <> ''),
    audience    text        NOT NULL
        CHECK (audience IN ('it_security', 'management', 'executive')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN m4.recipient_groups.audience IS 'Muss zu m3.recommendations.audience passen.';

CREATE TRIGGER recipient_groups_touch_updated_at
    BEFORE UPDATE ON m4.recipient_groups
    FOR EACH ROW EXECUTE FUNCTION m4.touch_updated_at();

-- ---------------------------------------------------------------- recipients

CREATE TABLE m4.recipients (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    group_id         bigint      NOT NULL REFERENCES m4.recipient_groups (id) ON DELETE RESTRICT,
    name             text        NOT NULL CHECK (name <> ''),
    email            text
        CHECK (email ~ '^[^@\s]+@[^@\s]+$'),
    telegram_chat_id text,
    webhook_url      text
        CHECK (webhook_url ~ '^https://'),
    webhook_format   text        NOT NULL DEFAULT 'generic'
        CHECK (webhook_format IN ('teams', 'discord', 'slack', 'mattermost', 'generic')),
    is_active        boolean     NOT NULL DEFAULT true,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (email IS NOT NULL OR telegram_chat_id IS NOT NULL OR webhook_url IS NOT NULL)
);

COMMENT ON TABLE m4.recipients IS 'Empfaenger je Gruppe. Deaktivieren statt loeschen, notification_log verweist darauf. Bei Webhooks ist ein Empfaenger ein Kanal.';
COMMENT ON COLUMN m4.recipients.webhook_url IS 'Geheimnis: in der Oberflaeche nur maskiert anzeigen, nie ins Audit-Log oder in Fehlermeldungen schreiben.';
COMMENT ON COLUMN m4.recipients.webhook_format IS 'Bestimmt das JSON-Format der Nachricht (Teams, Discord, Slack und Mattermost erwarten unterschiedliche Felder).';

CREATE INDEX recipients_group_id_idx ON m4.recipients (group_id);

CREATE TRIGGER recipients_touch_updated_at
    BEFORE UPDATE ON m4.recipients
    FOR EACH ROW EXECUTE FUNCTION m4.touch_updated_at();

-- ---------------------------------------------------------------- notification_rules
-- Matrix aus Schweregrad, Gruppe, Kanal und Zeitverhalten.
-- risk_level nutzt dieselben Werte wie m3.risk_assessments.risk_level.

CREATE TABLE m4.notification_rules (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    risk_level  text        NOT NULL
        CHECK (risk_level IN ('critical', 'high', 'medium', 'low', 'info')),
    group_id    bigint      NOT NULL REFERENCES m4.recipient_groups (id) ON DELETE CASCADE,
    channel     text        NOT NULL
        CHECK (channel IN ('email', 'telegram', 'webhook')),
    timing      text        NOT NULL DEFAULT 'immediate'
        CHECK (timing IN ('immediate', 'daily', 'weekly')),
    notify_resolved boolean NOT NULL DEFAULT false,
    conditions  jsonb       NOT NULL DEFAULT '{}'
        CHECK (jsonb_typeof(conditions) = 'object'),
    is_active   boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (risk_level, group_id, channel)
);

COMMENT ON TABLE m4.notification_rules IS 'Beispiel: critical -> IT-Security und Geschaeftsfuehrung sofort, medium -> Management woechentlich.';
COMMENT ON COLUMN m4.notification_rules.notify_resolved IS 'Auch Entwarnung senden, wenn ein gemeldeter Treffer in M3 erledigt ist (status = resolved).';
COMMENT ON COLUMN m4.notification_rules.conditions IS 'Zusaetzliche Filter auf Spalten von m3.findings_current, z. B. {"internet_exposed": true, "exclude_trust_labels": ["CONTRADICTORY"]}. Leer = keine Filter.';

CREATE INDEX notification_rules_group_id_idx ON m4.notification_rules (group_id);

CREATE TRIGGER notification_rules_touch_updated_at
    BEFORE UPDATE ON m4.notification_rules
    FOR EACH ROW EXECUTE FUNCTION m4.touch_updated_at();

-- ---------------------------------------------------------------- notification_log
-- Versandprotokoll. Verhindert Doppelmeldungen und haelt gesammelte Meldungen (daily/weekly) bis zum Versand vor.
--
-- Genau einmal: M3 legt bei JEDER Aenderung der Eingangswerte (z. B. neuer EPSS-Wert) eine neue
-- risk_assessment_id an. Deshalb ist nicht die Bewertung, sondern der Treffer (match_id) der Schluessel:
--   * alert:    nur senden, wenn fuer (match_id, recipient_id, channel) noch kein alert existiert
--               oder risk_rank hoeher ist als der hoechste bisher gemeldete (Eskalation, z. B. neu in KEV).
--   * resolved: einmal je Bewertung, die erledigt wurde (oeffnet M3 den Treffer wieder, gibt es eine neue Bewertung).
-- Die Eskalationspruefung macht /notify; die UNIQUE-Bedingung ist die harte Sicherung gegen Doppelversand.
--
-- match_id und risk_assessment_id verweisen logisch auf M3, bewusst ohne Fremdschluessel.

CREATE TABLE m4.notification_log (
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind               text        NOT NULL DEFAULT 'alert'
        CHECK (kind IN ('alert', 'resolved')),
    match_id           bigint      NOT NULL,
    risk_assessment_id bigint      NOT NULL,
    raw_item_id        bigint      REFERENCES public.raw_items (id) ON DELETE RESTRICT,  -- NULL = Inventarfund ohne Meldung
    risk_level         text        NOT NULL
        CHECK (risk_level IN ('critical', 'high', 'medium', 'low', 'info')),
    risk_rank          smallint    GENERATED ALWAYS AS (m4.risk_rank(risk_level)) STORED,
    rule_id            bigint      REFERENCES m4.notification_rules (id) ON DELETE SET NULL,
    recipient_id       bigint      NOT NULL REFERENCES m4.recipients (id) ON DELETE RESTRICT,
    channel            text        NOT NULL
        CHECK (channel IN ('email', 'telegram', 'webhook')),
    status             text        NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'sent', 'failed', 'skipped')),
    scheduled_for      timestamptz NOT NULL DEFAULT now(),
    attempts           smallint    NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at    timestamptz,
    digest_id          uuid,
    error_message      text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    sent_at            timestamptz,
    UNIQUE (risk_assessment_id, recipient_id, channel, kind),
    CHECK ((status = 'sent') = (sent_at IS NOT NULL)),
    CHECK (status NOT IN ('failed', 'skipped') OR error_message IS NOT NULL)
);

COMMENT ON COLUMN m4.notification_log.raw_item_id IS 'NULL bei Inventarfunden. /notify sendet nur sofort, wenn m3.findings_current.immediate_notify wahr ist.';
COMMENT ON COLUMN m4.notification_log.scheduled_for IS 'Wann der Eintrag faellig ist: sofort bei immediate, naechster Tages- bzw. Wochentermin bei daily/weekly.';
COMMENT ON COLUMN m4.notification_log.next_attempt_at IS 'Nach einem Fehlschlag: frueheste naechste Wiederholung. NULL = keine weitere Wiederholung.';
COMMENT ON COLUMN m4.notification_log.digest_id IS 'Gleiche ID = in derselben Sammelnachricht verschickt.';
COMMENT ON COLUMN m4.notification_log.error_message IS 'Vor dem Speichern bereinigen (keine Tokens, keine URLs mit Schluessel). Bei skipped der Grund, z. B. Empfaenger ohne E-Mail-Adresse.';

-- Faellige Eintraege fuer /notify
CREATE INDEX notification_log_due_idx ON m4.notification_log (scheduled_for) WHERE status = 'queued';
CREATE INDEX notification_log_retry_idx ON m4.notification_log (next_attempt_at) WHERE status = 'failed';
-- Eskalationspruefung: hoechste bisher gemeldete Stufe je Treffer, Empfaenger und Kanal
CREATE INDEX notification_log_match_idx ON m4.notification_log (match_id, recipient_id, channel, kind, risk_rank);
CREATE INDEX notification_log_recipient_idx ON m4.notification_log (recipient_id);

-- ---------------------------------------------------------------- item_status
-- Bearbeitungsstatus je Meldung. Eigene Tabelle, weil raw_items M1 gehoert.
-- Keine Zeile = Status "new". Aenderungen stehen zusaetzlich im audit_log.
-- Eine Zeile gehoert entweder zu einer Meldung (raw_item_id) oder zu einem Inventarfund ohne Meldung
-- (match_id aus m3, wie bei notification_log ohne Fremdschluessel).

CREATE TABLE m4.item_status (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    raw_item_id bigint      UNIQUE REFERENCES public.raw_items (id) ON DELETE CASCADE,
    match_id    bigint      UNIQUE,
    status      text        NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'in_progress', 'done', 'irrelevant')),
    note        text,
    updated_by  bigint      REFERENCES m4.users (id) ON DELETE RESTRICT,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE m4.item_status ADD CONSTRAINT item_status_one_target CHECK (num_nonnulls(raw_item_id, match_id) = 1);

COMMENT ON TABLE m4.item_status IS 'Feedback je Meldung oder Inventarfund, kann spaeter zur Verbesserung der Bewertung genutzt werden.';

CREATE INDEX item_status_status_idx ON m4.item_status (status);

CREATE TRIGGER item_status_touch_updated_at
    BEFORE UPDATE ON m4.item_status
    FOR EACH ROW EXECUTE FUNCTION m4.touch_updated_at();

-- ---------------------------------------------------------------- audit_log
-- Aenderungen an Quellen, Regeln, Empfaengern, Inventar, Benutzern sowie Anmeldungen. Nur anhaengen.
-- username ist ein Schnappschuss, damit der Eintrag auch bei geaendertem Benutzernamen lesbar bleibt.

CREATE TABLE m4.audit_log (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    bigint      REFERENCES m4.users (id) ON DELETE RESTRICT,
    username   text,
    action     text        NOT NULL
        CHECK (action IN (
            'create', 'update', 'delete', 'import',
            'login', 'login_failed', 'logout', 'password_change',
            'run_now', 'suppress', 'unsuppress', 'test_notification'
        )),
    entity     text        NOT NULL CHECK (entity <> ''),
    entity_id  text,
    details    jsonb       NOT NULL DEFAULT '{}'
        CHECK (jsonb_typeof(details) = 'object'),
    ip_address inet,
    created_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN m4.audit_log.details IS 'Alter und neuer Wert. Niemals Passwoerter, Hashes, Tokens oder Webhook-URLs.';

CREATE INDEX audit_log_created_at_idx ON m4.audit_log (created_at DESC);
CREATE INDEX audit_log_entity_idx ON m4.audit_log (entity, entity_id);
CREATE INDEX audit_log_user_id_idx ON m4.audit_log (user_id);

CREATE TRIGGER audit_log_append_only
    BEFORE UPDATE OR DELETE ON m4.audit_log
    FOR EACH ROW EXECUTE FUNCTION m4.forbid_change();

-- ---------------------------------------------------------------- Startdaten
-- Gruppen und Standardregeln nach Projektidee 2.8. Empfaenger pflegt der Admin in der Oberflaeche.

INSERT INTO m4.recipient_groups (name, audience) VALUES
    ('IT-Security',        'it_security'),
    ('Management',         'management'),
    ('Geschaeftsfuehrung', 'executive');

INSERT INTO m4.notification_rules (risk_level, group_id, channel, timing)
SELECT r.risk_level, g.id, 'email', r.timing
FROM (VALUES
    ('critical', 'IT-Security',        'immediate'),
    ('critical', 'Geschaeftsfuehrung', 'immediate'),
    ('high',     'IT-Security',        'immediate'),
    ('medium',   'Management',         'weekly')
) AS r (risk_level, group_name, timing)
JOIN m4.recipient_groups g ON g.name = r.group_name;

COMMIT;
