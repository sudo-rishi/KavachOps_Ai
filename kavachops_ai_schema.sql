-- =====================================================================
-- KavachOps AI database schema (PostgreSQL 13+)
-- Aligned with the current Spring Boot/JPA entities in this repository.
--
-- Intended for a FRESH database. If you already have the old tables,
-- migrate data instead of running this file over them (existing tables
-- are skipped by IF NOT EXISTS and will not be altered).
-- =====================================================================

BEGIN;


-- ─────────────────────────────────────────────────────────────────────
-- Shared helpers
-- ─────────────────────────────────────────────────────────────────────

-- Idempotent enum creation
CREATE OR REPLACE FUNCTION create_enum_if_missing(type_name TEXT, vals TEXT[])
RETURNS VOID AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = type_name) THEN
        EXECUTE format('CREATE TYPE %I AS ENUM (%s)', type_name,
                       (SELECT string_agg(quote_literal(v), ',') FROM unnest(vals) AS v));
    END IF;
END;
$$ LANGUAGE plpgsql;

SELECT create_enum_if_missing('severity_level',      ARRAY['info','low','medium','high','critical']);
SELECT create_enum_if_missing('user_role',           ARRAY['admin','analyst','operator','auditor','viewer']);
SELECT create_enum_if_missing('ids_rule_type',       ARRAY['snort','suricata','custom']);
SELECT create_enum_if_missing('alert_status',        ARRAY['new','investigating','resolved','false_positive']);
SELECT create_enum_if_missing('job_status',          ARRAY['pending','running','completed','failed']);
SELECT create_enum_if_missing('vuln_scan_type',      ARRAY['network','web','host','full']);
SELECT create_enum_if_missing('finding_status',      ARRAY['open','in_progress','patched','accepted_risk']);
SELECT create_enum_if_missing('malware_result',      ARRAY['clean','infected','suspicious','error']);
SELECT create_enum_if_missing('incident_status',     ARRAY['open','investigating','contained','resolved','closed']);
SELECT create_enum_if_missing('incident_action',     ARRAY['created','updated','note','escalated','contained','resolved']);
SELECT create_enum_if_missing('honeypot_kind',       ARRAY['ssh','http','ftp','smtp','telnet','rdp']);
SELECT create_enum_if_missing('notification_kind',   ARRAY['alert','incident','report','system']);
SELECT create_enum_if_missing('notification_channel',ARRAY['email','sms','websocket','slack']);
SELECT create_enum_if_missing('notification_status', ARRAY['pending','sent','failed','read']);
SELECT create_enum_if_missing('report_kind',         ARRAY['security','compliance','executive','incident','vulnerability']);
SELECT create_enum_if_missing('report_format',       ARRAY['pdf','html','csv','json']);
SELECT create_enum_if_missing('report_status',       ARRAY['pending','generating','completed','failed']);

SELECT create_enum_if_missing('ai_service',          ARRAY['chat','translate','transliterate','language_detect','speech_to_text','text_to_speech']);
SELECT create_enum_if_missing('api_call_status',     ARRAY['success','failed','timeout','rate_limited']);
SELECT create_enum_if_missing('ai_insight_type',     ARRAY['summary','triage','translation','recommendation']);

DROP FUNCTION create_enum_if_missing(TEXT, TEXT[]);

-- updated_at trigger function
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ─────────────────────────────────────────────────────────────────────
-- Module 1: Secure Login
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    user_id               BIGSERIAL    PRIMARY KEY,
    username              VARCHAR(50)  UNIQUE NOT NULL,
    email                 VARCHAR(100) UNIQUE NOT NULL,
    password_hash         VARCHAR(255) NOT NULL,
    salt                  VARCHAR(32)  NOT NULL DEFAULT '',
    role                  VARCHAR(20)  NOT NULL,
    is_active             BOOLEAN      NOT NULL DEFAULT TRUE,
    must_change_password  BOOLEAN      NOT NULL DEFAULT FALSE,
    preferred_language    VARCHAR(10)  NOT NULL DEFAULT 'en-IN',   -- BCP-47, e.g. hi-IN, ta-IN
    failed_login_attempts INTEGER      NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
    locked_until          TIMESTAMPTZ,
    last_login_at         TIMESTAMPTZ,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    user_id    BIGINT       NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    ip_address VARCHAR(45)  NOT NULL,
    user_agent VARCHAR(500),
    expires_at TIMESTAMPTZ  NOT NULL,
    is_active  BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_expires ON user_sessions(user_id, expires_at);

-- ─────────────────────────────────────────────────────────────────────
-- Module 2: Network Analysis & IDS
-- ─────────────────────────────────────────────────────────────────────

-- Keep a single-column primary key to match NetworkTraffic. The application
-- currently maps traffic_id as its complete JPA identity.
CREATE TABLE IF NOT EXISTS network_traffic (
    traffic_id       BIGSERIAL    PRIMARY KEY,
    source_ip        VARCHAR(45)  NOT NULL,
    destination_ip   VARCHAR(45)  NOT NULL,
    source_port      INTEGER,
    destination_port INTEGER,
    protocol         VARCHAR(20)  NOT NULL,
    packet_size      INTEGER,
    flags            VARCHAR(50),
    ttl              INTEGER,
    payload_preview  VARCHAR(500),
    interface_name   VARCHAR(50),
    timestamp        TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON network_traffic(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_traffic_source_ip ON network_traffic(source_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_protocol ON network_traffic(protocol);

CREATE TABLE IF NOT EXISTS ids_rules (
    rule_id            BIGSERIAL     PRIMARY KEY,
    rule_name          VARCHAR(200)  NOT NULL UNIQUE,
    rule_content       TEXT          NOT NULL,
    rule_type          VARCHAR(20)   NOT NULL,
    severity           INTEGER       NOT NULL CHECK (severity BETWEEN 1 AND 4),
    is_active          BOOLEAN       NOT NULL DEFAULT TRUE,
    source_ip_pattern  VARCHAR(100),
    dest_ip_pattern    VARCHAR(100),
    port_pattern       VARCHAR(50),
    protocol_pattern   VARCHAR(20),
    payload_pattern    VARCHAR(500),
    match_count        BIGINT        NOT NULL DEFAULT 0,
    created_at         TIMESTAMPTZ   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMPTZ   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS network_alerts (
    alert_id         BIGSERIAL      PRIMARY KEY,
    rule_id          BIGINT         REFERENCES ids_rules(rule_id) ON DELETE SET NULL,
    source_ip        VARCHAR(45)    NOT NULL,
    destination_ip   VARCHAR(45)    NOT NULL,
    source_port      INTEGER,
    destination_port INTEGER,
    severity         VARCHAR(20)    NOT NULL,
    timestamp        TIMESTAMPTZ    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status           VARCHAR(20)    NOT NULL DEFAULT 'new',
    alert_message    VARCHAR(1000),
    protocol         VARCHAR(20),
    packet_data      TEXT,
    alert_type       VARCHAR(50)    DEFAULT 'IDS'
);
CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON network_alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alert_severity ON network_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alert_status   ON network_alerts(status);
CREATE INDEX IF NOT EXISTS idx_alert_rule     ON network_alerts(rule_id);

-- ─────────────────────────────────────────────────────────────────────
-- Module 3: Vulnerability Assessment
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cve_records (
    cve_id          VARCHAR(20)  PRIMARY KEY,
    description     TEXT,
    published_date  DATE,
    cvss_score      DECIMAL(3,1) CHECK (cvss_score BETWEEN 0 AND 10),
    reference_links TEXT[]
);

CREATE TABLE IF NOT EXISTS vulnerability_scans (
    scan_id      BIGSERIAL      PRIMARY KEY,
    scan_name    VARCHAR(200)   NOT NULL,
    scan_type    VARCHAR(20)    NOT NULL,
    targets      VARCHAR(500),
    initiated_by BIGINT         REFERENCES users(user_id) ON DELETE SET NULL,
    scan_status  VARCHAR(20)    NOT NULL DEFAULT 'pending',
    start_time   TIMESTAMPTZ,
    end_time     TIMESTAMPTZ,
    created_at   TIMESTAMPTZ    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMPTZ    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_vscan_initiated_by ON vulnerability_scans(initiated_by);

CREATE TABLE IF NOT EXISTS vulnerability_findings (
    finding_id         BIGSERIAL      PRIMARY KEY,
    scan_id            BIGINT         REFERENCES vulnerability_scans(scan_id) ON DELETE CASCADE,
    host_ip            VARCHAR(45)    NOT NULL,
    cve_id             VARCHAR(20)    REFERENCES cve_records(cve_id) ON DELETE SET NULL,
    vulnerability_name VARCHAR(500)   NOT NULL,
    severity           VARCHAR(20)    NOT NULL,
    status             VARCHAR(20)    NOT NULL DEFAULT 'open',
    description        TEXT,
    remediation        TEXT,
    created_at         TIMESTAMPTZ    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMPTZ    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_vfind_scan_sev ON vulnerability_findings(scan_id, severity);
CREATE INDEX IF NOT EXISTS idx_vfind_cve      ON vulnerability_findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_vfind_status   ON vulnerability_findings(status);

-- ─────────────────────────────────────────────────────────────────────
-- Module 4: Malware Detection & File Integrity
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS malware_scans (
    scan_id               BIGSERIAL      PRIMARY KEY,
    file_path             TEXT           NOT NULL,
    file_name             VARCHAR(500)   NOT NULL,
    file_hash             VARCHAR(64),
    file_size             BIGINT,
    scan_engine           VARCHAR(100)   NOT NULL,
    scan_result           VARCHAR(20)    NOT NULL,
    threat_name           VARCHAR(500),
    yara_rule_matched     VARCHAR(200),
    virustotal_positives  INTEGER,
    virustotal_total      INTEGER,
    quarantined           BOOLEAN        NOT NULL DEFAULT FALSE,
    quarantine_path       TEXT,
    scan_time             TIMESTAMPTZ    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_malware_hash   ON malware_scans(file_hash);
CREATE INDEX IF NOT EXISTS idx_malware_result ON malware_scans(scan_result);
CREATE INDEX IF NOT EXISTS idx_malware_time   ON malware_scans(scan_time);

CREATE TABLE IF NOT EXISTS yara_rules (
    rule_id      SERIAL       PRIMARY KEY,
    rule_name    VARCHAR(200) NOT NULL UNIQUE,
    rule_content TEXT         NOT NULL,
    is_active    BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS virustotal_results (
    result_id    BIGSERIAL    PRIMARY KEY,
    file_hash    VARCHAR(64)  NOT NULL,
    scan_date    TIMESTAMPTZ,
    positives    INTEGER,
    total_scans  INTEGER,
    scan_results JSONB,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_vt_hash ON virustotal_results(file_hash);

-- ─────────────────────────────────────────────────────────────────────
-- Module 5: Incident Management
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
    incident_id     BIGSERIAL       PRIMARY KEY,
    incident_number VARCHAR(50)     UNIQUE NOT NULL,
    title           VARCHAR(500)    NOT NULL,
    description     TEXT,
    severity        VARCHAR(20)     NOT NULL,
    status          VARCHAR(20)     NOT NULL DEFAULT 'open',
    created_by      BIGINT          REFERENCES users(user_id) ON DELETE SET NULL,
    assigned_to     VARCHAR(100),
    source_alert_id BIGINT          REFERENCES network_alerts(alert_id) ON DELETE SET NULL,
    affected_assets VARCHAR(500),
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_incident_status   ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incident_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incident_assigned ON incidents(assigned_to);
CREATE INDEX IF NOT EXISTS idx_incident_alert    ON incidents(source_alert_id);

CREATE TABLE IF NOT EXISTS incident_timeline (
    timeline_id  BIGSERIAL       PRIMARY KEY,
    incident_id  BIGINT          NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    action_type  VARCHAR(20)     NOT NULL,
    description  TEXT            NOT NULL,
    performed_by BIGINT          REFERENCES users(user_id) ON DELETE SET NULL,
    timestamp    TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_timeline_incident ON incident_timeline(incident_id, timestamp);

CREATE TABLE IF NOT EXISTS incident_attachments (
    attachment_id BIGSERIAL    PRIMARY KEY,
    incident_id   BIGINT       NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    file_name     VARCHAR(500) NOT NULL,
    file_path     TEXT         NOT NULL,
    uploaded_by   BIGINT       REFERENCES users(user_id) ON DELETE SET NULL,
    uploaded_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_attach_incident ON incident_attachments(incident_id);

-- ─────────────────────────────────────────────────────────────────────
-- Module 6: Honeypots & Rules Engine
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS honeypots (
    honeypot_id   BIGSERIAL     PRIMARY KEY,
    honeypot_name VARCHAR(200)  NOT NULL,
    honeypot_type VARCHAR(20)   NOT NULL,
    ip_address    VARCHAR(45)   NOT NULL,
    port          INTEGER       NOT NULL CHECK (port BETWEEN 1 AND 65535),
    deployment_type VARCHAR(20) DEFAULT 'manual',
    docker_container_id VARCHAR(64),
    docker_image  VARCHAR(120),
    last_known_state VARCHAR(30),
    is_active     BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMPTZ   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS honeypot_interactions (
    interaction_id BIGSERIAL    PRIMARY KEY,
    honeypot_id    BIGINT       REFERENCES honeypots(honeypot_id) ON DELETE CASCADE,
    attacker_ip    VARCHAR(45)  NOT NULL,
    timestamp      TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    data           TEXT
);
CREATE INDEX IF NOT EXISTS idx_hp_inter_attacker ON honeypot_interactions(attacker_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_hp_inter_honeypot ON honeypot_interactions(honeypot_id);
CREATE INDEX IF NOT EXISTS idx_honeypot_ts ON honeypot_interactions(timestamp);

CREATE TABLE IF NOT EXISTS deception_rules (
    rule_id     SERIAL       PRIMARY KEY,
    rule_name   VARCHAR(200) NOT NULL,
    condition   JSONB        NOT NULL,
    action      JSONB        NOT NULL,
    is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attacker_profiles (
    profile_id   SERIAL         PRIMARY KEY,
    attacker_ip  VARCHAR(45)    NOT NULL UNIQUE,
    first_seen   TIMESTAMPTZ    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen    TIMESTAMPTZ,
    threat_level VARCHAR(20)    NOT NULL DEFAULT 'low',
    updated_at   TIMESTAMPTZ    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────────────────────
-- Module 7: Alert Notification & Report Generation
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notifications (
    notification_id   BIGSERIAL            PRIMARY KEY,
    recipient_id      BIGINT               REFERENCES users(user_id) ON DELETE CASCADE,
    notification_type notification_kind    NOT NULL,
    title             VARCHAR(500)         NOT NULL,
    message           TEXT,
    channel           notification_channel NOT NULL,
    priority          severity_level       NOT NULL DEFAULT 'medium' CHECK (priority <> 'info'),
    status            notification_status  NOT NULL DEFAULT 'pending',
    created_at        TIMESTAMPTZ          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at           TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_notif_recipient_status ON notifications(recipient_id, status);

CREATE TABLE IF NOT EXISTS report_templates (
    template_id   SERIAL        PRIMARY KEY,
    name          VARCHAR(200)  NOT NULL,
    report_type   report_kind   NOT NULL,
    template      JSONB         NOT NULL,
    parameters    JSONB,
    output_format report_format NOT NULL DEFAULT 'pdf',
    is_active     BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMPTZ   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS generated_reports (
    report_id    BIGSERIAL     PRIMARY KEY,
    template_id  INTEGER       REFERENCES report_templates(template_id) ON DELETE SET NULL,
    generated_by BIGINT        REFERENCES users(user_id) ON DELETE SET NULL,
    parameters   JSONB,
    file_path    TEXT,
    file_size    BIGINT,
    status       report_status NOT NULL DEFAULT 'pending',
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_genreport_template ON generated_reports(template_id);
CREATE INDEX IF NOT EXISTS idx_genreport_user     ON generated_reports(generated_by);

-- ─────────────────────────────────────────────────────────────────────
-- Module 8: Windows Event Logs
-- ─────────────────────────────────────────────────────────────────────

-- Keep log_id as the single-column identity used by WindowsEventLog.
CREATE TABLE IF NOT EXISTS windows_event_logs (
    log_id               BIGSERIAL    PRIMARY KEY,
    event_id             BIGINT       NOT NULL,
    channel              VARCHAR(100) NOT NULL,
    level                VARCHAR(20)  NOT NULL,
    source               VARCHAR(200) NOT NULL,
    computer_name        VARCHAR(200),
    user_name            VARCHAR(200),
    event_time           TIMESTAMPTZ  NOT NULL,
    message              TEXT,
    raw_xml              TEXT,
    is_security_relevant BOOLEAN      NOT NULL DEFAULT FALSE,
    alert_generated      BOOLEAN      NOT NULL DEFAULT FALSE,
    ingested_at          TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_winevent_timestamp ON windows_event_logs(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_winevent_id       ON windows_event_logs(event_id);
CREATE INDEX IF NOT EXISTS idx_winevent_channel  ON windows_event_logs(channel);
CREATE INDEX IF NOT EXISTS idx_winevent_level    ON windows_event_logs(level);
CREATE INDEX IF NOT EXISTS idx_winevent_security ON windows_event_logs(is_security_relevant)
    WHERE is_security_relevant = TRUE;

-- ─────────────────────────────────────────────────────────────────────
-- Module 9: AI Analysis (Sarvam AI API)
-- ─────────────────────────────────────────────────────────────────────
-- API keys are NEVER stored in the database. api_key_ref names the
-- environment variable / secret-manager entry that holds the real key.
CREATE TABLE IF NOT EXISTS ai_provider_configs (
    config_id        SERIAL       PRIMARY KEY,
    provider         VARCHAR(50)  NOT NULL UNIQUE DEFAULT 'sarvam',
    base_url         VARCHAR(255) NOT NULL,
    api_key_ref      VARCHAR(100) NOT NULL,
    default_model    VARCHAR(100),
    default_language VARCHAR(10)  NOT NULL DEFAULT 'en-IN',
    timeout_seconds  INTEGER      NOT NULL DEFAULT 30 CHECK (timeout_seconds > 0),
    is_active        BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by       BIGINT       REFERENCES users(user_id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One row per Sarvam API call (usage, cost tracking, audit, debugging).
-- Prompts/responses are not stored here; keep sensitive content out of logs.
CREATE TABLE IF NOT EXISTS sarvam_api_requests (
    request_id          BIGSERIAL       PRIMARY KEY,
    config_id           INTEGER         REFERENCES ai_provider_configs(config_id) ON DELETE SET NULL,
    user_id             BIGINT          REFERENCES users(user_id) ON DELETE SET NULL,
    service             ai_service      NOT NULL,
    model               VARCHAR(100),
    source_language     VARCHAR(10),
    target_language     VARCHAR(10),
    input_chars         INTEGER         CHECK (input_chars >= 0),
    prompt_tokens       INTEGER         CHECK (prompt_tokens >= 0),
    completion_tokens   INTEGER         CHECK (completion_tokens >= 0),
    total_tokens        INTEGER         CHECK (total_tokens >= 0),
    audio_seconds       NUMERIC(10,2)   CHECK (audio_seconds >= 0),
    latency_ms          INTEGER         CHECK (latency_ms >= 0),
    http_status         INTEGER,
    status              api_call_status NOT NULL,
    error_message       VARCHAR(1000),
    provider_request_id VARCHAR(100),
    related_alert_id    BIGINT          REFERENCES network_alerts(alert_id) ON DELETE SET NULL,
    related_incident_id BIGINT          REFERENCES incidents(incident_id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sarvam_req_created  ON sarvam_api_requests(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sarvam_req_user     ON sarvam_api_requests(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sarvam_req_service  ON sarvam_api_requests(service, status);
CREATE INDEX IF NOT EXISTS idx_sarvam_req_alert    ON sarvam_api_requests(related_alert_id);
CREATE INDEX IF NOT EXISTS idx_sarvam_req_incident ON sarvam_api_requests(related_incident_id);

-- AI-generated output attached to an alert or incident
-- (summaries, triage notes, translations into Indian languages).
CREATE TABLE IF NOT EXISTS ai_insights (
    insight_id   BIGSERIAL       PRIMARY KEY,
    request_id   BIGINT          REFERENCES sarvam_api_requests(request_id) ON DELETE SET NULL,
    alert_id     BIGINT          REFERENCES network_alerts(alert_id) ON DELETE CASCADE,
    incident_id  BIGINT          REFERENCES incidents(incident_id) ON DELETE CASCADE,
    insight_type ai_insight_type NOT NULL,
    language     VARCHAR(10)     NOT NULL DEFAULT 'en-IN',
    content      TEXT            NOT NULL,
    created_at   TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (alert_id IS NOT NULL OR incident_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS idx_insight_alert    ON ai_insights(alert_id);
CREATE INDEX IF NOT EXISTS idx_insight_incident ON ai_insights(incident_id);

-- ─────────────────────────────────────────────────────────────────────
-- ─────────────────────────────────────────────────────────────────────
-- ─────────────────────────────────────────────────────────────────────
-- updated_at triggers
-- ─────────────────────────────────────────────────────────────────────
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'users','ids_rules','vulnerability_scans','vulnerability_findings',
        'yara_rules','incidents','honeypots','deception_rules',
        'attacker_profiles','report_templates','ai_provider_configs'
    ]
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS trg_%1$s_updated_at ON %1$I', t);
        EXECUTE format(
            'CREATE TRIGGER trg_%1$s_updated_at BEFORE UPDATE ON %1$I
             FOR EACH ROW EXECUTE FUNCTION set_updated_at()', t);
    END LOOP;
END $$;

-- ─────────────────────────────────────────────────────────────────────
-- Seed data
-- ─────────────────────────────────────────────────────────────────────

-- Default admin is created by DefaultUserBootstrap in the Spring application.

-- Sarvam AI provider (key is read from the SARVAM_API_KEY environment variable).
-- Set default_model to the Sarvam model you use, e.g. after checking their docs.
INSERT INTO ai_provider_configs (provider, base_url, api_key_ref, default_language)
VALUES ('sarvam', 'https://api.sarvam.ai', 'SARVAM_API_KEY', 'en-IN')
ON CONFLICT (provider) DO NOTHING;

-- Default IDS rules use the integer scale used by IdsRule:
-- 1=low, 2=medium, 3=high, 4=critical.
INSERT INTO ids_rules (rule_name, rule_content, rule_type, severity, source_ip_pattern, port_pattern, protocol_pattern)
VALUES
    ('SSH Brute Force Detection',  'alert tcp any any -> any 22 (msg:"SSH Brute Force"; threshold:type both,track by_src,count 5,seconds 60;)', 'custom', 3, NULL, '22',        'TCP'),
    ('RDP Brute Force Detection',  'alert tcp any any -> any 3389 (msg:"RDP Attack"; threshold:type both,track by_src,count 3,seconds 60;)',     'custom', 3, NULL, '3389',      'TCP'),
    ('HTTP to Non-Standard Port',  'alert tcp any any -> any 8080:9090 (msg:"HTTP Non-Standard Port";)',                                         'custom', 1, NULL, '8080-9090', 'TCP'),
    ('ICMP Flood Detection',       'alert icmp any any -> any any (msg:"ICMP Flood";)',                                                          'custom', 2, NULL, 'any',       'ICMP'),
    ('DNS Over Non-Standard Port', 'alert udp any any -> any 53 (msg:"DNS Query";)',                                                             'custom', 1, NULL, '53',        'UDP'),
    ('Suspicious PowerShell',      'alert tcp any any -> any any (msg:"PowerShell in payload"; content:"powershell";)',                          'custom', 4, NULL, 'any',       'TCP'),
    ('Port Scan Detection',        'alert tcp any any -> any 1:1024 (msg:"Port Scan";)',                                                         'custom', 2, NULL, '1-1024',    'TCP'),
    ('Telnet Access',              'alert tcp any any -> any 23 (msg:"Telnet Access Detected";)',                                                'custom', 3, NULL, '23',        'TCP'),
    ('FTP Clear Text',             'alert tcp any any -> any 21 (msg:"FTP Clear Text Auth";)',                                                   'custom', 2, NULL, '21',        'TCP'),
    ('SMB Lateral Movement',       'alert tcp any any -> any 445 (msg:"SMB Access";)',                                                           'custom', 3, NULL, '445',       'TCP')
ON CONFLICT (rule_name) DO NOTHING;

COMMIT;
