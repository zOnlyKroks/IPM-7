-- Run ONLY against a disposable database with m1_initial.sql and m4_initial.sql loaded.
-- Rauchtest fuer m4_initial.sql: legt Testdaten an, prueft Constraints, rollt alles zurueck.
-- Alle Testdaten sind synthetisch (example.invalid).
\set ON_ERROR_STOP on
BEGIN;
DO $$
DECLARE
    s bigint; r1 bigint; u1 bigint; g1 bigint; rc1 bigint; rule1 bigint; a1 bigint; n int;
BEGIN
    INSERT INTO public.sources(name,url,connector,source_type)
      VALUES ('m4 test','https://example.invalid','rss','authority') RETURNING id INTO s;
    INSERT INTO public.raw_items(source_id,external_id,url,title,translation_status,content_hash,title_de,body_de)
      VALUES (s,'1','https://example.invalid/1','Testmeldung','not_needed',repeat('4',64),'Testmeldung','')
      RETURNING id INTO r1;

    -- Startdaten vorhanden
    SELECT count(*) INTO n FROM m4.recipient_groups;
    IF n <> 3 THEN RAISE EXCEPTION 'expected 3 recipient groups, got %', n; END IF;
    SELECT count(*) INTO n FROM m4.notification_rules;
    IF n <> 4 THEN RAISE EXCEPTION 'expected 4 default rules, got %', n; END IF;

    -- users: Benutzername ohne Ruecksicht auf Gross-/Kleinschreibung eindeutig
    INSERT INTO m4.users(username,password_hash,role) VALUES ('Analyst1','$argon2id$test','analyst') RETURNING id INTO u1;
    BEGIN
        INSERT INTO m4.users(username,password_hash) VALUES ('analyst1','$argon2id$test');
        RAISE EXCEPTION 'duplicate username (case-insensitive) accepted';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;
    BEGIN
        INSERT INTO m4.users(username,password_hash,role) VALUES ('someone','$argon2id$test','superuser');
        RAISE EXCEPTION 'invalid role accepted';
    EXCEPTION WHEN check_violation THEN NULL;
    END;

    -- recipients: mindestens ein Kanal, Webhook nur https
    SELECT id INTO g1 FROM m4.recipient_groups WHERE audience = 'it_security';
    INSERT INTO m4.recipients(group_id,name,email) VALUES (g1,'SOC','soc@example.invalid') RETURNING id INTO rc1;
    BEGIN
        INSERT INTO m4.recipients(group_id,name) VALUES (g1,'ohne Kanal');
        RAISE EXCEPTION 'recipient without channel accepted';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
    BEGIN
        INSERT INTO m4.recipients(group_id,name,webhook_url) VALUES (g1,'http','http://example.invalid/hook');
        RAISE EXCEPTION 'non-https webhook accepted';
    EXCEPTION WHEN check_violation THEN NULL;
    END;

    -- notification_log: risk_rank wird berechnet, Doppelversand je Bewertung verhindert
    SELECT id INTO rule1 FROM m4.notification_rules WHERE risk_level = 'high' AND group_id = g1;
    INSERT INTO m4.notification_log(match_id,risk_assessment_id,raw_item_id,risk_level,rule_id,recipient_id,channel)
      VALUES (900001,800001,r1,'high',rule1,rc1,'email');
    SELECT risk_rank INTO n FROM m4.notification_log WHERE risk_assessment_id = 800001;
    IF n <> 4 THEN RAISE EXCEPTION 'risk_rank for high should be 4, got %', n; END IF;
    BEGIN
        INSERT INTO m4.notification_log(match_id,risk_assessment_id,raw_item_id,risk_level,recipient_id,channel)
          VALUES (900001,800001,r1,'high',rc1,'email');
        RAISE EXCEPTION 'duplicate notification accepted';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;
    -- Entwarnung zur selben Bewertung ist erlaubt
    INSERT INTO m4.notification_log(kind,match_id,risk_assessment_id,raw_item_id,risk_level,recipient_id,channel)
      VALUES ('resolved',900001,800001,r1,'high',rc1,'email');
    BEGIN
        UPDATE m4.notification_log SET status = 'sent' WHERE risk_assessment_id = 800001 AND kind = 'alert';
        RAISE EXCEPTION 'sent without sent_at accepted';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
    BEGIN
        UPDATE m4.notification_log SET status = 'skipped' WHERE risk_assessment_id = 800001 AND kind = 'alert';
        RAISE EXCEPTION 'skipped without reason accepted';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
    UPDATE m4.notification_log SET status = 'sent', sent_at = now() WHERE risk_assessment_id = 800001 AND kind = 'alert';

    -- Inventarfund ohne Meldung: Versand und Status sind moeglich, Doppelversand bleibt verhindert
    INSERT INTO m4.notification_log(match_id,risk_assessment_id,risk_level,recipient_id,channel)
      VALUES (900002,800002,'high',rc1,'email');
    BEGIN
        INSERT INTO m4.notification_log(match_id,risk_assessment_id,risk_level,recipient_id,channel)
          VALUES (900002,800002,'high',rc1,'email');
        RAISE EXCEPTION 'duplicate inventory notification accepted';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;
    INSERT INTO m4.item_status(match_id,status,updated_by) VALUES (900002,'irrelevant',u1);
    BEGIN
        INSERT INTO m4.item_status(match_id,status) VALUES (900002,'done');
        RAISE EXCEPTION 'two states for one finding accepted';
    EXCEPTION WHEN unique_violation THEN NULL;
    END;
    BEGIN
        INSERT INTO m4.item_status(status) VALUES ('new');
        RAISE EXCEPTION 'item status without target accepted';
    EXCEPTION WHEN check_violation THEN NULL;
    END;
    BEGIN
        INSERT INTO m4.item_status(raw_item_id,match_id) VALUES (r1,900003);
        RAISE EXCEPTION 'item status with two targets accepted';
    EXCEPTION WHEN check_violation THEN NULL;
    END;

    -- item_status
    INSERT INTO m4.item_status(raw_item_id,status,updated_by) VALUES (r1,'in_progress',u1);
    BEGIN
        UPDATE m4.item_status SET status = 'unknown' WHERE raw_item_id = r1;
        RAISE EXCEPTION 'invalid item status accepted';
    EXCEPTION WHEN check_violation THEN NULL;
    END;

    -- audit_log: nur anhaengen
    INSERT INTO m4.audit_log(user_id,username,action,entity,entity_id,ip_address)
      VALUES (u1,'Analyst1','run_now','pipeline',NULL,'127.0.0.1') RETURNING id INTO a1;
    BEGIN
        UPDATE m4.audit_log SET username = 'x' WHERE id = a1;
        RAISE EXCEPTION 'audit_log update accepted';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM NOT LIKE '%nur zum Anhaengen%' THEN RAISE; END IF;
    END;
    BEGIN
        DELETE FROM m4.audit_log WHERE id = a1;
        RAISE EXCEPTION 'audit_log delete accepted';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM NOT LIKE '%nur zum Anhaengen%' THEN RAISE; END IF;
    END;
    -- Benutzer mit Audit-Eintraegen lassen sich nicht loeschen (nur deaktivieren)
    BEGIN
        DELETE FROM m4.users WHERE id = u1;
        RAISE EXCEPTION 'user with audit entries deleted';
    EXCEPTION WHEN foreign_key_violation THEN NULL;
    END;

    RAISE NOTICE 'M4 smoke test OK';
END $$;
ROLLBACK;
