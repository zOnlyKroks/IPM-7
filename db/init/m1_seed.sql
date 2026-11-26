-- Standardquellen. Laeuft beim ersten Start nach m1_initial.sql. Mehrfach ausfuehrbar:
-- vorhandene Quellen (gleicher Name) bleiben unveraendert, Aenderungen macht danach M4.
-- Nachtraeglich in eine bestehende Datenbank:
--   docker compose exec postgres psql -U argos -d argos -f /docker-entrypoint-initdb.d/m1_seed.sql
-- max_items begrenzt die grossen Feeds, weil M2 nur wenige Meldungen je Lauf analysiert.

INSERT INTO sources (name, url, connector, source_type, language, trust_weight,
                     is_primary_source, is_priority, fetch_interval_minutes, config)
VALUES
    -- Fakten
    ('CISA KEV', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        'cisa_kev', 'authority', 'en', 0.95, true, true, 30, '{}'),
    ('NVD', 'https://services.nvd.nist.gov/rest/json/cves/2.0',
        'nvd', 'authority', 'en', 0.95, true, false, 120, '{}'),
    ('EPSS', 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz',
        'epss', 'authority', 'en', 0.80, false, false, 1440, '{}'),
    ('OSV', 'https://api.osv.dev/v1/vulns',
        'osv', 'authority', 'en', 0.80, false, false, 30, '{}'),
    -- Behoerden
    ('BSI CERT-Bund', 'https://wid.cert-bund.de/content/public/securityAdvisory/rss',
        'rss', 'authority', 'de', 0.90, true, false, 30, '{"max_items": 30}'),
    ('CERT-FR', 'https://www.cert.ssi.gouv.fr/feed/',
        'rss', 'authority', 'fr', 0.90, true, false, 60, '{"max_items": 20}'),
    ('JPCERT/CC', 'https://www.jpcert.or.jp/english/rss/jpcert-en.rdf',
        'rss', 'authority', 'en', 0.90, true, false, 60, '{"max_items": 20}'),
    -- Fachpresse
    ('Heise Security', 'https://www.heise.de/security/rss/news-atom.xml',
        'rss', 'press', 'de', 0.60, false, false, 30, '{"max_items": 20}'),
    ('BleepingComputer', 'https://www.bleepingcomputer.com/feed/',
        'rss', 'press', 'en', 0.60, false, false, 30, '{}'),
    ('The Hacker News', 'https://feeds.feedburner.com/TheHackersNews',
        'rss', 'press', 'en', 0.60, false, false, 30, '{"max_items": 20}'),
    -- Social Media (niedriges Gewicht)
    ('Mastodon #cve', 'https://mastodon.social/tags/cve.rss',
        'rss', 'social', 'en', 0.20, false, false, 30, '{"max_items": 20}'),
    ('Mastodon #cybersecurity', 'https://mastodon.social/tags/cybersecurity.rss',
        'rss', 'social', 'en', 0.20, false, false, 30, '{"max_items": 20}')
ON CONFLICT (name) DO NOTHING;
