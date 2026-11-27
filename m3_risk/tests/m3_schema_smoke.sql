-- Run ONLY against a disposable database with m1_initial.sql, m2_initial.sql and m3_initial.sql loaded.
-- Rauchtest fuer m3_initial.sql: legt Testdaten an, prueft Constraints und Views, rollt alles zurueck.
-- Keine Ollama-Verbindung noetig. Alle Testdaten sind synthetisch (example.invalid, CVE-2099-*).
\set ON_ERROR_STOP on
BEGIN;
DO $$
DECLARE
    s bigint; r1 bigint; r2 bigint; a1 bigint; a2 bigint;
    img bigint; lib bigint; fw bigint; ai bigint;
    m1 bigint; m2v bigint; m3i bigint; ra1 bigint; ra2 bigint; n int;
BEGIN
    INSERT INTO public.sources(name,url,connector,source_type)
      VALUES ('m3 test','https://example.invalid','rss','authority') RETURNING id INTO s;
    INSERT INTO public.raw_items(source_id,external_id,url,title,translation_status,content_hash,cve_ids,title_de,body_de)
      VALUES (s,'1','https://example.invalid/1','Testmeldung CVE','not_needed',repeat('1',64),'{CVE-2099-0001}','Testmeldung CVE','')
      RETURNING id INTO r1;
    INSERT INTO public.raw_items(source_id,external_id,url,title,translation_status,content_hash,title_de,body_de)
      VALUES (s,'2','https://example.invalid/2','Testmeldung Geo','not_needed',repeat('2',64),'Geo','')
      RETURNING id INTO r2;

    INSERT INTO m3.assets(asset_key,name,asset_type,criticality,internet_exposed)
      VALUES ('fw-01','Firewall','firewall',5,true) RETURNING id INTO a1;
    INSERT INTO m3.assets(asset_key,name,asset_type,criticality)
      VALUES ('srv-ai','KI-Server','server',3) RETURNING id INTO a2;

    INSERT INTO m3.sbom_components(asset_id,origin,component_type,name,vendor,version,vendor_norm,product_norm,cpe23)
      VALUES (a1,'manual','firmware','TestOS','TestVendor','7.2.4','testvendor','testos','cpe:2.3:o:testvendor:testos:7.2.4:*:*:*:*:*:*:*')
      RETURNING id INTO fw;
    INSERT INTO m3.sbom_components(asset_id,origin,component_type,name,vendor,version,vendor_norm,product_norm,vendor_country)
      VALUES (a2,'manual','ai_model','qwen2.5:7b','Alibaba','7b','alibaba','qwen2.5','CN') RETURNING id INTO ai;
    INSERT INTO m3.sbom_components(asset_id,origin,component_type,name,version,purl,image_ref,sbom_sha256)
      VALUES (a2,'sbom','container_image','n8n','1.0','pkg:docker/n8n@1.0','n8n:1.0',repeat('a',64)) RETURNING id INTO img;
    INSERT INTO m3.sbom_components(asset_id,parent_component_id,origin,component_type,name,version,purl,image_ref,sbom_sha256)
      VALUES (a2,img,'sbom','library','axios','1.6.0','pkg:npm/axios@1.6.0','n8n:1.0',repeat('a',64)) RETURNING id INTO lib;

    -- doppelte manuelle Komponente muss scheitern
    BEGIN
        INSERT INTO m3.sbom_components(asset_id,origin,component_type,name,vendor_norm,product_norm)
          VALUES (a1,'manual','firmware','TestOS2','testvendor','testos');
        RAISE EXCEPTION 'duplicate manual component accepted';
    EXCEPTION WHEN unique_violation THEN NULL; END;

    -- CVE-Treffer direkt
    INSERT INTO m3.matches(raw_item_id,component_id,cve_id,match_key,match_method,confidence,version_status,is_direct,dependency_path)
      VALUES (r1,fw,'CVE-2099-0001','CVE-2099-0001','cpe_version',0.95,'affected',true,ARRAY[fw]) RETURNING id INTO m1;
    -- indirekter Treffer ueber SBOM
    INSERT INTO m3.matches(raw_item_id,component_id,cve_id,match_key,match_method,confidence,version_status,is_direct,dependency_path)
      VALUES (r1,lib,'CVE-2099-0001','CVE-2099-0001','purl_version',0.9,'affected',false,ARRAY[img,lib]);
    -- vendor_exposure
    INSERT INTO m3.matches(raw_item_id,component_id,match_key,match_method,confidence,version_status,is_direct,dependency_path)
      VALUES (r2,ai,'raw:'||r2,'vendor_exposure',0.6,'not_applicable',true,ARRAY[ai]) RETURNING id INTO m2v;

    -- falscher match_key / Pfad / resolved ohne Grund muessen scheitern
    BEGIN
        INSERT INTO m3.matches(raw_item_id,component_id,cve_id,match_key,match_method,confidence,version_status,is_direct,dependency_path)
          VALUES (r1,ai,'CVE-2099-0001','raw:1','cpe_version',0.9,'affected',true,ARRAY[ai]);
        RAISE EXCEPTION 'bad match_key accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;
    BEGIN
        INSERT INTO m3.matches(raw_item_id,component_id,cve_id,match_key,match_method,confidence,version_status,is_direct,dependency_path)
          VALUES (r1,ai,'CVE-2099-0001','CVE-2099-0001','cpe_version',0.9,'affected',true,ARRAY[fw]);
        RAISE EXCEPTION 'bad dependency_path accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;
    BEGIN
        UPDATE m3.matches SET status='resolved' WHERE id=m1;
        RAISE EXCEPTION 'resolved without reason accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;

    INSERT INTO m3.risk_assessments(match_id,scoring_branch,score,risk_level,action_code,policy_version,
        cvss_score,cvss_version,kev_listed,asset_criticality,internet_exposed,match_confidence,
        trust_score,trust_label,category,factor_breakdown,risk_fingerprint)
      VALUES (m1,'cve',92,'critical','patch_immediately','v1',9.8,'3.1',true,5,true,0.95,
        0.8,'CONFIRMED','VULNERABILITY','{"cvss":40}','fp1') RETURNING id INTO ra1;
    INSERT INTO m3.risk_assessments(match_id,scoring_branch,score,risk_level,action_code,policy_version,
        asset_criticality,internet_exposed,match_confidence,trust_score,trust_label,category,factor_breakdown,risk_fingerprint)
      VALUES (m2v,'vendor_exposure',40,'medium','review_vendor_dependency','v1',3,false,0.6,
        0.5,'UNCONFIRMED','GEOPOLITICS','{"criticality":20}','fp2') RETURNING id INTO ra2;

    -- vendor_exposure darf nicht high sein
    BEGIN
        INSERT INTO m3.risk_assessments(match_id,scoring_branch,score,risk_level,action_code,policy_version,
            asset_criticality,internet_exposed,match_confidence,category,factor_breakdown,risk_fingerprint,is_current)
          VALUES (m2v,'vendor_exposure',80,'high','x','v1',3,false,0.6,'GEOPOLITICS','{}','fp',false);
        RAISE EXCEPTION 'vendor_exposure high accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;
    -- zweite aktuelle Bewertung je Treffer muss scheitern
    BEGIN
        INSERT INTO m3.risk_assessments(match_id,scoring_branch,score,risk_level,action_code,policy_version,
            asset_criticality,internet_exposed,match_confidence,category,factor_breakdown,risk_fingerprint)
          VALUES (m1,'cve',50,'medium','x','v1',5,true,0.9,'VULNERABILITY','{}','fp');
        RAISE EXCEPTION 'two current assessments accepted';
    EXCEPTION WHEN unique_violation THEN NULL; END;

    INSERT INTO m3.recommendations(risk_assessment_id,audience,fact_package,text,llm_model,prompt_version,validation_status)
      VALUES (ra1,'it_security','{"cve":"CVE-2099-0001"}','TestOS auf fw-01 sofort aktualisieren.','qwen2.5:7b','v1','passed'),
             (ra1,'management','{"cve":"CVE-2099-0001"}','Kritische Luecke in der Firewall.','template','v1','fallback_template');
    INSERT INTO m3.evidence(risk_assessment_id,claim_key,claim_text,source_kind,raw_item_id,source_url)
      VALUES (ra1,'kev_listed','In CISA KEV gelistet','cve_fact',NULL,'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'),
             (ra1,'report','Meldung','raw_item',r1,'https://example.invalid/1');

    INSERT INTO m3.processing(raw_item_id,status,category,match_fingerprint,risk_fingerprint)
      VALUES (r1,'done','VULNERABILITY','m','r');
    INSERT INTO m3.processing(raw_item_id,status,attempts,last_error) VALUES (r2,'failed',1,'x');

    INSERT INTO m3.suppressions(component_id,match_key,reason,created_by) VALUES (lib,'CVE-2099-0001','nicht genutzt','analyst');

    -- Views
    SELECT count(*) INTO n FROM m3.findings_current;
    ASSERT n = 2, 'findings_current should show 2 assessed open findings, got ' || n;  -- indirekter Treffer noch ohne Bewertung
    SELECT count(*) INTO n FROM m3.findings_history;
    ASSERT n = 3, 'findings_history should show 3, got ' || n;
    ASSERT (SELECT recommendations->>'it_security' FROM m3.findings_current WHERE match_id=m1) LIKE 'TestOS%';
    ASSERT (SELECT jsonb_array_length(evidence) FROM m3.findings_current WHERE match_id=m1) = 2;
    ASSERT (SELECT dependency_path_names FROM m3.findings_history WHERE component_id=lib) = ARRAY['n8n','axios'];
    ASSERT (SELECT highest_risk_level FROM m3.assets_overview WHERE asset_key='fw-01') = 'critical';
    ASSERT (SELECT open_finding_count FROM m3.assets_overview WHERE asset_key='srv-ai') = 1;

    -- Meldungstreffer duerfen immer sofort gemeldet werden (die Regeln in M4 entscheiden)
    ASSERT (SELECT bool_and(immediate_notify) FROM m3.findings_current);

    -- Inventarfund ohne Meldung: sofort nur ab high oder bei KEV
    INSERT INTO m3.matches(component_id,cve_id,match_key,match_method,confidence,version_status,is_direct,dependency_path)
      VALUES (fw,'CVE-2099-0002','CVE-2099-0002','cpe_version',0.95,'affected',true,ARRAY[fw]) RETURNING id INTO m3i;
    INSERT INTO m3.risk_assessments(match_id,scoring_branch,score,risk_level,action_code,policy_version,
        kev_listed,asset_criticality,internet_exposed,match_confidence,category,factor_breakdown,risk_fingerprint)
      VALUES (m3i,'cve',45,'medium','patch_scheduled','v1',false,5,true,0.95,'VULNERABILITY','{}','fp3');
    ASSERT (SELECT raw_item_id IS NULL AND NOT immediate_notify AND url LIKE '%CVE-2099-0002'
              FROM m3.findings_current WHERE match_id=m3i), 'medium inventory finding must not be immediate';
    UPDATE m3.risk_assessments SET kev_listed=true WHERE match_id=m3i;
    ASSERT (SELECT immediate_notify FROM m3.findings_current WHERE match_id=m3i), 'KEV inventory finding is immediate';
    UPDATE m3.risk_assessments SET kev_listed=false, risk_level='high' WHERE match_id=m3i;
    ASSERT (SELECT immediate_notify FROM m3.findings_current WHERE match_id=m3i), 'high inventory finding is immediate';
    -- derselbe Inventarfund darf nicht doppelt entstehen (NULLS NOT DISTINCT)
    BEGIN
        INSERT INTO m3.matches(component_id,cve_id,match_key,match_method,confidence,version_status,is_direct,dependency_path)
          VALUES (fw,'CVE-2099-0002','CVE-2099-0002','cpe_version',0.95,'affected',true,ARRAY[fw]);
        RAISE EXCEPTION 'duplicate inventory match accepted';
    EXCEPTION WHEN unique_violation THEN NULL; END;
    DELETE FROM m3.risk_assessments WHERE match_id=m3i;
    DELETE FROM m3.matches WHERE id=m3i;

    -- Upgrade-Szenario: Treffer erledigt -> verschwindet aus current, bleibt in history
    UPDATE m3.matches SET status='resolved', resolved_at=now(), resolved_reason='version_not_affected' WHERE id=m1;
    ASSERT (SELECT count(*) FROM m3.findings_current WHERE match_id=m1) = 0;
    ASSERT (SELECT resolved_reason FROM m3.findings_history WHERE match_id=m1) = 'version_not_affected';
    ASSERT (SELECT highest_risk_level FROM m3.assets_overview WHERE asset_key='fw-01') IS NULL;

    -- Asset deaktiviert -> aus current verschwunden
    UPDATE m3.assets SET is_active=false WHERE id=a2;
    ASSERT (SELECT count(*) FROM m3.findings_current) = 0;
    RAISE NOTICE 'M3 smoke test OK';
END $$;
ROLLBACK;
