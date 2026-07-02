-- Univerkon Control — initial schema
-- Aligned with docs/spec.md v0.5. Comments reference spec sections for traceability.
-- PRAGMA foreign_keys = ON is set per-connection in Go (internal/storage), not here.

-- ── Organizations & Access (spec §3) ──────────────────────────────────────

CREATE TABLE organizations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- org_id NULL => super_admin, global scope (§3 "Роли")
CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id          INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT,                          -- NULL if OIDC-only account
    oidc_subject    TEXT,                           -- 'sub' claim from the org's OIDC provider
    role            TEXT NOT NULL CHECK (role IN ('super_admin','org_admin','operator','viewer')),
    totp_enabled    INTEGER NOT NULL DEFAULT 0,      -- secret itself lives in `secrets`, owner_type='user'
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK ((role = 'super_admin') = (org_id IS NULL))
);

CREATE TABLE sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,               -- refresh token, hashed — never store raw
    ip          TEXT,
    user_agent  TEXT,
    expires_at  DATETIME NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sessions_user ON sessions(user_id);

CREATE TABLE ip_allowlist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      INTEGER REFERENCES organizations(id) ON DELETE CASCADE,  -- NULL = applies globally
    cidr        TEXT NOT NULL,
    label       TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ── Secrets — envelope encryption (spec §6, ADR-0001) ─────────────────────
-- Every ciphertext is AES-256-GCM'd with master.key before landing here.
-- master.key itself is never stored in this database.

CREATE TABLE secrets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    class       TEXT NOT NULL CHECK (class IN ('A','B','C')),  -- §6: CP / server / module secrets
    owner_type  TEXT NOT NULL,                                  -- 'server' | 'user' | 'notification_channel' | 'license' | 's3_pool'
    owner_id    INTEGER NOT NULL,
    key_name    TEXT NOT NULL,                                  -- e.g. 'ssh_private_key', 'db_password', 'totp_secret'
    ciphertext  BLOB NOT NULL,
    nonce       BLOB NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (owner_type, owner_id, key_name)
);

-- ── Servers (spec §5.1) ─────────────────────────────────────────────────────

CREATE TABLE servers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id          INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL DEFAULT 22,
    ssh_user        TEXT NOT NULL,
    auth_type       TEXT NOT NULL CHECK (auth_type IN ('key','password')),
    type            TEXT NOT NULL CHECK (type IN ('docker_only','full','mock')) DEFAULT 'docker_only',
    environment     TEXT NOT NULL CHECK (environment IN ('prod','staging','dev')) DEFAULT 'prod',
    is_self         INTEGER NOT NULL DEFAULT 0,      -- [THIS] marker §2 — hosts CP itself, delete-protected
    status          TEXT NOT NULL CHECK (status IN ('online','offline','unknown')) DEFAULT 'unknown',
    last_checked_at DATETIME,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (org_id, name)
);

CREATE INDEX idx_servers_org ON servers(org_id);

-- ── S3 pool (spec §5.7) ───────────────────────────────────────────────────────

CREATE TABLE s3_pool (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id          INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    mode            TEXT NOT NULL CHECK (mode IN ('managed','external')),
    endpoint        TEXT,
    bucket_prefix   TEXT,
    server_id       INTEGER REFERENCES servers(id),  -- where managed MinIO runs, when mode='managed'
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- credentials for each pool live in `secrets`, owner_type='s3_pool'

-- ── Module registry (spec §5.2, §16.1 for deps semantics) ─────────────────────

CREATE TABLE module_catalog (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key         TEXT NOT NULL UNIQUE,               -- 'testikon', 'didaktikon', 'gateway', 'launcher', ...
    name        TEXT NOT NULL,                       -- 'Тестикон'
    deps        TEXT NOT NULL DEFAULT '[]',           -- JSON array of module keys
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE module_versions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    module_catalog_id   INTEGER NOT NULL REFERENCES module_catalog(id) ON DELETE CASCADE,
    version             TEXT NOT NULL,                -- semver
    image               TEXT NOT NULL,
    compose_ref         TEXT NOT NULL,                -- path/URL to the compose template
    vars_schema         TEXT NOT NULL,                -- JSON Schema backing the config form, §5.2
    healthcheck_url     TEXT,
    demo_mode           TEXT,                          -- JSON: limits/banner/expiry_days, §5.4
    released_at         DATETIME NOT NULL,
    UNIQUE (module_catalog_id, version)
);

CREATE TABLE module_installations (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id               INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    module_catalog_id       INTEGER NOT NULL REFERENCES module_catalog(id),
    installed_version_id    INTEGER NOT NULL REFERENCES module_versions(id),
    status                  TEXT NOT NULL CHECK (status IN ('running','stopped','error','deploying')) DEFAULT 'deploying',
    demo_mode               INTEGER NOT NULL DEFAULT 0,        -- §5.4 — no active license
    config                  TEXT NOT NULL DEFAULT '{}',         -- JSON, currently-applied config
    config_pending          TEXT,                                -- JSON, edited-not-applied — drift detection §5.2
    s3_pool_id              INTEGER REFERENCES s3_pool(id),
    deployed_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deployed_by_user_id     INTEGER REFERENCES users(id),
    UNIQUE (server_id, module_catalog_id)
);

CREATE INDEX idx_installations_server ON module_installations(server_id);

-- ── Licenses (spec §5.4) ──────────────────────────────────────────────────────

CREATE TABLE licenses (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id                  INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    module_installation_id  INTEGER REFERENCES module_installations(id) ON DELETE SET NULL,
    license_key             TEXT NOT NULL,
    issued_at               DATETIME NOT NULL,
    expires_at              DATETIME NOT NULL,
    status                  TEXT NOT NULL CHECK (status IN ('active','expiring_soon','expired','revoked')) DEFAULT 'active',
    last_heartbeat_at       DATETIME,
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- JWS token itself lives in `secrets`, owner_type='license'

CREATE INDEX idx_licenses_expiry ON licenses(expires_at);   -- feeds the 30/14/7/3-day alert cron, §5.4

-- ── Deployments — history & rollback (spec §5.3) ───────────────────────────────

CREATE TABLE deployments (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id               INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    module_installation_id  INTEGER REFERENCES module_installations(id) ON DELETE SET NULL,
    kind                    TEXT NOT NULL CHECK (kind IN ('install','update','rollback','config_apply')),
    from_version_id         INTEGER REFERENCES module_versions(id),
    to_version_id           INTEGER REFERENCES module_versions(id),
    status                  TEXT NOT NULL CHECK (status IN ('pending','running','success','failed')) DEFAULT 'pending',
    scheduled_at            DATETIME,                 -- §5.5 "Расписание операций"
    started_at              DATETIME,
    finished_at             DATETIME,
    log                     TEXT,                      -- full SSE log, retained for history per §5.3
    initiated_by_user_id    INTEGER REFERENCES users(id),
    created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_deployments_server ON deployments(server_id, created_at);

-- ── Backups (spec §7) ────────────────────────────────────────────────────────

CREATE TABLE backup_schedules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type     TEXT NOT NULL CHECK (target_type IN ('cp','server')),
    target_id       INTEGER,                          -- server_id; NULL when target_type='cp'
    cron            TEXT NOT NULL,
    retention_kind  TEXT NOT NULL DEFAULT '30d',        -- template: 7d | 30d | 90d | custom
    retention_value TEXT,                                -- count or period, when retention_kind='custom'
    s3_pool_id      INTEGER NOT NULL REFERENCES s3_pool(id),
    enabled         INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE backups (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    schedule_id     INTEGER REFERENCES backup_schedules(id) ON DELETE SET NULL,
    target_type     TEXT NOT NULL CHECK (target_type IN ('cp','server')),
    target_id       INTEGER,
    snapshot_ref    TEXT NOT NULL,                      -- path in S3 — whole-app snapshot, §7
    size_bytes      INTEGER,
    checksum        TEXT,
    valid           INTEGER,                             -- NULL until validated, then 0/1 — §7 "Валидация"
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      DATETIME                              -- per retention policy
);

CREATE INDEX idx_backups_target ON backups(target_type, target_id);

-- ── Notifications (spec §5.6) ────────────────────────────────────────────────

CREATE TABLE notification_channels (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    type        TEXT NOT NULL CHECK (type IN ('telegram','max','email')),
    config      TEXT NOT NULL DEFAULT '{}',            -- non-secret config (chat_id, smtp_host, to[])
    enabled     INTEGER NOT NULL DEFAULT 1
);
-- bot tokens / smtp password live in `secrets`, owner_type='notification_channel'

CREATE TABLE notification_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event_type  TEXT NOT NULL,                          -- 'license_expiring_30d', 'deploy_failed', ...
    channel_ids TEXT NOT NULL DEFAULT '[]',              -- JSON array of notification_channels.id
    UNIQUE (org_id, event_type)
);

-- ── Audit log (spec §5.10) ────────────────────────────────────────────────────

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    org_id      INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
    action      TEXT NOT NULL,                          -- 'server.create', 'deploy.start', 'secret.read', ...
    target_type TEXT,
    target_id   INTEGER,
    metadata    TEXT NOT NULL DEFAULT '{}',              -- JSON
    ip          TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_created ON audit_log(created_at);
