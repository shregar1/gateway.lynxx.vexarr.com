-- Lynxx Gateway — Full DDL (SQLite)
-- Generated from live schema on hostx-beta
-- Tables, indexes, triggers, foreign keys, unique constraints

PRAGMA foreign_keys = ON;

-- ============================================================
-- Migration tracking (sqlx)
-- ============================================================

CREATE TABLE _sqlx_migrations (
  version        BIGINT    PRIMARY KEY,
  description    TEXT      NOT NULL,
  installed_on   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  success        BOOLEAN   NOT NULL,
  checksum       BLOB      NOT NULL,
  execution_time BIGINT    NOT NULL
);

-- ============================================================
-- Lookup tables (enums)
-- ============================================================

CREATE TABLE user_type_lk (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  urn         TEXT NOT NULL UNIQUE DEFAULT (
    lower(hex(randomblob(4))) || '-' ||
    lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    substr('89ab', abs(random()) % 4 + 1, 1) ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    lower(hex(randomblob(6)))
  ),
  code        TEXT NOT NULL UNIQUE,
  label       TEXT NOT NULL,
  description TEXT NOT NULL,
  is_deleted  INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE lb_strategy_lk (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  urn         TEXT NOT NULL UNIQUE DEFAULT (
    lower(hex(randomblob(4))) || '-' ||
    lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    substr('89ab', abs(random()) % 4 + 1, 1) ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    lower(hex(randomblob(6)))
  ),
  code        TEXT NOT NULL UNIQUE,
  label       TEXT NOT NULL,
  description TEXT NOT NULL,
  is_deleted  INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ============================================================
-- Projects
-- ============================================================

CREATE TABLE projects (
  id          TEXT    PRIMARY KEY,
  urn         TEXT    NOT NULL UNIQUE DEFAULT (
    lower(hex(randomblob(4))) || '-' ||
    lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    substr('89ab', abs(random()) % 4 + 1, 1) ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    lower(hex(randomblob(6)))
  ),
  name        TEXT    NOT NULL,
  description TEXT    NOT NULL DEFAULT '',
  is_deleted  INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ============================================================
-- Core gateway tables
-- ============================================================

CREATE TABLE services (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  urn                  TEXT    NOT NULL UNIQUE DEFAULT (
    lower(hex(randomblob(4))) || '-' ||
    lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    substr('89ab', abs(random()) % 4 + 1, 1) ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    lower(hex(randomblob(6)))
  ),
  name                 TEXT    NOT NULL,
  url                  TEXT    NOT NULL,
  retries              INTEGER NOT NULL DEFAULT 3,
  connect_timeout_ms   INTEGER NOT NULL DEFAULT 5000,
  enabled              INTEGER NOT NULL DEFAULT 1,
  lb_strategy          TEXT    NOT NULL DEFAULT 'round-robin',
  lb_strategy_id       INTEGER NOT NULL DEFAULT 1 REFERENCES lb_strategy_lk(id),
  tls_verify           INTEGER NOT NULL DEFAULT 1,
  tls_client_cert_path TEXT,
  tls_client_key_path  TEXT,
  tls_ca_path          TEXT,
  is_deleted           INTEGER NOT NULL DEFAULT 0,
  created_at           TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at           TEXT    NOT NULL DEFAULT (datetime('now')),
  source               TEXT    NOT NULL DEFAULT 'api',
  service_type         TEXT    NOT NULL DEFAULT 'api',
  document_root        TEXT,
  index_file           TEXT    NOT NULL DEFAULT 'index.html',
  spa_fallback         INTEGER NOT NULL DEFAULT 0,
  drain_timeout_ms     INTEGER,
  project_id           TEXT    REFERENCES projects(id) ON DELETE SET NULL,
  domain               TEXT    NOT NULL DEFAULT '',
  subdomain            TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE routes (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  urn         TEXT    NOT NULL UNIQUE DEFAULT (
    lower(hex(randomblob(4))) || '-' ||
    lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    substr('89ab', abs(random()) % 4 + 1, 1) ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    lower(hex(randomblob(6)))
  ),
  service_id  INTEGER NOT NULL,
  paths       TEXT    NOT NULL,          -- JSON array: ["/", "/*"]
  methods     TEXT    NOT NULL,          -- JSON array: ["GET", "POST"] or []
  hosts       TEXT    NOT NULL DEFAULT '[]', -- JSON array: ["api.example.com"]
  strip_path  INTEGER NOT NULL DEFAULT 1,
  enabled     INTEGER NOT NULL DEFAULT 1,
  is_deleted  INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  source      TEXT    NOT NULL DEFAULT 'api',
  health_gate INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE TABLE plugins (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  urn        TEXT    NOT NULL UNIQUE DEFAULT (
    lower(hex(randomblob(4))) || '-' ||
    lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    substr('89ab', abs(random()) % 4 + 1, 1) ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    lower(hex(randomblob(6)))
  ),
  name       TEXT    NOT NULL,
  service_id INTEGER NOT NULL,
  route_id   INTEGER NOT NULL,
  enabled    INTEGER NOT NULL DEFAULT 1,
  config     TEXT    NOT NULL,           -- JSON config blob
  is_deleted INTEGER NOT NULL DEFAULT 0,
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT    NOT NULL DEFAULT (datetime('now')),
  source     TEXT    NOT NULL DEFAULT 'api',
  FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
  FOREIGN KEY (route_id)   REFERENCES routes(id)   ON DELETE CASCADE
);

CREATE TABLE targets (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  urn        TEXT    NOT NULL UNIQUE DEFAULT (
    lower(hex(randomblob(4))) || '-' ||
    lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    substr('89ab', abs(random()) % 4 + 1, 1) ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    lower(hex(randomblob(6)))
  ),
  service_id INTEGER NOT NULL,
  url        TEXT    NOT NULL,
  weight     INTEGER NOT NULL DEFAULT 1,
  enabled    INTEGER NOT NULL DEFAULT 1,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT    NOT NULL DEFAULT (datetime('now')),
  zone       TEXT,
  state      TEXT    NOT NULL DEFAULT 'active',
  FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);

CREATE TABLE consumers (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  urn        TEXT    NOT NULL UNIQUE DEFAULT (
    lower(hex(randomblob(4))) || '-' ||
    lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    substr('89ab', abs(random()) % 4 + 1, 1) ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    lower(hex(randomblob(6)))
  ),
  username   TEXT    NOT NULL UNIQUE,
  custom_id  TEXT,
  api_key    TEXT,
  is_deleted INTEGER NOT NULL DEFAULT 0,
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ============================================================
-- Admin & auth
-- ============================================================

CREATE TABLE admin_tokens (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  urn          TEXT    NOT NULL UNIQUE DEFAULT (
    lower(hex(randomblob(4))) || '-' ||
    lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    substr('89ab', abs(random()) % 4 + 1, 1) ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    lower(hex(randomblob(6)))
  ),
  name         TEXT    NOT NULL,
  token_hash   TEXT    NOT NULL UNIQUE,
  role         TEXT    NOT NULL,
  user_type_id INTEGER NOT NULL DEFAULT 3 REFERENCES user_type_lk(id),
  is_deleted   INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  expires_at   TEXT,
  last_used_at TEXT
);

-- ============================================================
-- Observability
-- ============================================================

CREATE TABLE audit_log (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  urn           TEXT NOT NULL UNIQUE DEFAULT (
    lower(hex(randomblob(4))) || '-' ||
    lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    substr('89ab', abs(random()) % 4 + 1, 1) ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    lower(hex(randomblob(6)))
  ),
  ts            TEXT    NOT NULL,
  actor_id      INTEGER NOT NULL,
  actor_name    TEXT,
  actor_role    TEXT,
  action        TEXT    NOT NULL,
  resource_type TEXT    NOT NULL,
  resource_id   INTEGER NOT NULL,
  diff          TEXT,                    -- JSON diff of the change
  hash          TEXT    NOT NULL,        -- SHA-256 hash chain
  prev_hash     TEXT,
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE recordings (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  urn            TEXT    NOT NULL UNIQUE DEFAULT (
    lower(hex(randomblob(4))) || '-' ||
    lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    substr('89ab', abs(random()) % 4 + 1, 1) ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    lower(hex(randomblob(6)))
  ),
  ts             TEXT    NOT NULL,
  method         TEXT    NOT NULL,
  path           TEXT    NOT NULL,
  status         INTEGER NOT NULL,
  duration_ms    INTEGER NOT NULL,
  service_id     INTEGER NOT NULL,
  route_id       INTEGER NOT NULL,
  consumer       TEXT,
  bytes_request  INTEGER NOT NULL,
  bytes_response INTEGER NOT NULL,
  is_deleted     INTEGER NOT NULL DEFAULT 0,
  created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE quota_usage (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  urn            TEXT    NOT NULL UNIQUE DEFAULT (
    lower(hex(randomblob(4))) || '-' ||
    lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    substr('89ab', abs(random()) % 4 + 1, 1) ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    lower(hex(randomblob(6)))
  ),
  period         TEXT    NOT NULL UNIQUE, -- e.g. "2026-05"
  calls_total    INTEGER NOT NULL DEFAULT 0,
  calls_rejected INTEGER NOT NULL DEFAULT 0,
  updated_at     TEXT    NOT NULL
);

-- ============================================================
-- Request logs
-- ============================================================

CREATE TABLE logs (
  id          TEXT    PRIMARY KEY,
  urn         TEXT    NOT NULL UNIQUE DEFAULT (
    lower(hex(randomblob(4))) || '-' ||
    lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    substr('89ab', abs(random()) % 4 + 1, 1) ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    lower(hex(randomblob(6)))
  ),
  ts          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  level       TEXT    NOT NULL DEFAULT 'info',
  message     TEXT    NOT NULL DEFAULT '',
  service_id  TEXT,
  route_id    TEXT,
  project_id  TEXT,
  method      TEXT,
  path        TEXT,
  status      INTEGER,
  duration_ms INTEGER,
  client_ip   TEXT,
  metadata    TEXT,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ============================================================
-- Replication
-- ============================================================

CREATE TABLE _sync_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  urn        TEXT    NOT NULL UNIQUE DEFAULT (
    lower(hex(randomblob(4))) || '-' ||
    lower(hex(randomblob(2))) || '-4' ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    substr('89ab', abs(random()) % 4 + 1, 1) ||
    substr(lower(hex(randomblob(2))),2) || '-' ||
    lower(hex(randomblob(6)))
  ),
  payload    TEXT    NOT NULL,            -- JSON change event
  created_at TEXT    NOT NULL
);

-- ============================================================
-- Indexes
-- ============================================================

CREATE INDEX        idx_projects_urn                   ON projects(urn);
CREATE INDEX        idx_projects_name                  ON projects(name);
CREATE INDEX        idx_services_urn                   ON services(urn);
CREATE INDEX        idx_routes_urn                     ON routes(urn);
CREATE INDEX        idx_plugins_urn                    ON plugins(urn);
CREATE INDEX        idx_targets_urn                    ON targets(urn);
CREATE INDEX        idx_consumers_urn                  ON consumers(urn);
CREATE INDEX        idx_admin_tokens_urn               ON admin_tokens(urn);
CREATE INDEX        idx_audit_log_urn                  ON audit_log(urn);
CREATE INDEX        idx_recordings_urn                 ON recordings(urn);
CREATE INDEX        idx_quota_usage_urn                ON quota_usage(urn);
CREATE INDEX        idx_sync_log_urn                   ON _sync_log(urn);
CREATE INDEX        idx_routes_service                 ON routes(service_id);
CREATE INDEX        idx_plugins_service                ON plugins(service_id);
CREATE INDEX        idx_plugins_route                  ON plugins(route_id);
CREATE INDEX        idx_targets_service                ON targets(service_id);
CREATE INDEX        idx_services_lb_strategy           ON services(lb_strategy_id);
CREATE INDEX        idx_services_project_id            ON services(project_id);
CREATE UNIQUE INDEX idx_consumers_api_key              ON consumers(api_key) WHERE api_key IS NOT NULL;
CREATE INDEX        idx_admin_tokens_hash              ON admin_tokens(token_hash);
CREATE INDEX        idx_admin_tokens_user_type         ON admin_tokens(user_type_id);
CREATE INDEX        idx_audit_ts                       ON audit_log(ts);
CREATE INDEX        idx_audit_actor                    ON audit_log(actor_id);
CREATE INDEX        idx_audit_resource                 ON audit_log(resource_type, resource_id);
CREATE INDEX        idx_recordings_ts                  ON recordings(ts);
CREATE INDEX        idx_recordings_service             ON recordings(service_id);
CREATE INDEX        idx_recordings_route               ON recordings(route_id);
CREATE INDEX        idx_recordings_path                ON recordings(path);
CREATE INDEX        idx_recordings_status              ON recordings(status);

CREATE INDEX        idx_logs_urn                       ON logs(urn);
CREATE INDEX        idx_logs_ts                        ON logs(ts DESC);
CREATE INDEX        idx_logs_service_id                ON logs(service_id);
CREATE INDEX        idx_logs_route_id                  ON logs(route_id);
CREATE INDEX        idx_logs_project_id                ON logs(project_id);
CREATE INDEX        idx_logs_level                     ON logs(level);

-- Partial unique indexes (active-only uniqueness)
CREATE UNIQUE INDEX uq_projects_name_active            ON projects(name) WHERE is_deleted = 0;
CREATE UNIQUE INDEX uq_services_name_active            ON services(name) WHERE is_deleted = 0;
CREATE UNIQUE INDEX uq_consumers_username_active       ON consumers(username) WHERE is_deleted = 0;
CREATE UNIQUE INDEX uq_admin_tokens_hash_active        ON admin_tokens(token_hash) WHERE is_deleted = 0;

-- ============================================================
-- Triggers (auto-update updated_at on row modification)
-- ============================================================

CREATE TRIGGER trg_projects_bump_updated_at
  AFTER UPDATE ON projects FOR EACH ROW
  BEGIN UPDATE projects SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER trg_user_type_lk_bump_updated_at
  AFTER UPDATE ON user_type_lk FOR EACH ROW
  BEGIN UPDATE user_type_lk SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER trg_lb_strategy_lk_bump_updated_at
  AFTER UPDATE ON lb_strategy_lk FOR EACH ROW
  BEGIN UPDATE lb_strategy_lk SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER trg_services_bump_updated_at
  AFTER UPDATE ON services FOR EACH ROW
  BEGIN UPDATE services SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER trg_routes_bump_updated_at
  AFTER UPDATE ON routes FOR EACH ROW
  BEGIN UPDATE routes SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER trg_plugins_bump_updated_at
  AFTER UPDATE ON plugins FOR EACH ROW
  BEGIN UPDATE plugins SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER trg_consumers_bump_updated_at
  AFTER UPDATE ON consumers FOR EACH ROW
  BEGIN UPDATE consumers SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER trg_targets_bump_updated_at
  AFTER UPDATE ON targets FOR EACH ROW
  BEGIN UPDATE targets SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER trg_admin_tokens_bump_updated_at
  AFTER UPDATE ON admin_tokens FOR EACH ROW
  BEGIN UPDATE admin_tokens SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER trg_recordings_bump_updated_at
  AFTER UPDATE ON recordings FOR EACH ROW
  BEGIN UPDATE recordings SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;
