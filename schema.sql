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

-- ============================================================
-- Analytics, Probes, Snapshots, Alerts, IP Rules,
-- Error Pages, Consumer Groups  (migration 013)
-- ============================================================

CREATE TABLE IF NOT EXISTS metric_buckets (
    id              TEXT PRIMARY KEY,
    service_id      TEXT NOT NULL,
    route_id        TEXT,
    bucket_ts       TEXT NOT NULL,
    granularity     TEXT NOT NULL DEFAULT 'minute',
    total_requests  INTEGER NOT NULL DEFAULT 0,
    success_count   INTEGER NOT NULL DEFAULT 0,
    error_4xx       INTEGER NOT NULL DEFAULT 0,
    error_5xx       INTEGER NOT NULL DEFAULT 0,
    total_latency_ms INTEGER NOT NULL DEFAULT 0,
    min_latency_ms  INTEGER,
    max_latency_ms  INTEGER,
    bytes_in        INTEGER NOT NULL DEFAULT 0,
    bytes_out       INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_metric_buckets_service_ts ON metric_buckets(service_id, bucket_ts DESC);
CREATE INDEX IF NOT EXISTS idx_metric_buckets_granularity ON metric_buckets(granularity, bucket_ts);

CREATE TABLE IF NOT EXISTS geo_buckets (
    id              TEXT PRIMARY KEY,
    service_id      TEXT NOT NULL,
    bucket_ts       TEXT NOT NULL,
    country_code    TEXT NOT NULL DEFAULT '',
    city            TEXT NOT NULL DEFAULT '',
    request_count   INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_geo_buckets_service_ts ON geo_buckets(service_id, bucket_ts DESC);

CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    id              TEXT PRIMARY KEY,
    service_id      TEXT NOT NULL,
    consumer_id     TEXT,
    bucket_ts       TEXT NOT NULL,
    allowed         INTEGER NOT NULL DEFAULT 0,
    throttled       INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_service_ts ON rate_limit_buckets(service_id, bucket_ts DESC);

CREATE TABLE IF NOT EXISTS probes (
    id               TEXT PRIMARY KEY,
    service_id       TEXT NOT NULL,
    route_id         TEXT,
    name             TEXT NOT NULL,
    method           TEXT NOT NULL DEFAULT 'GET',
    path             TEXT NOT NULL DEFAULT '/',
    interval_seconds INTEGER NOT NULL DEFAULT 60,
    timeout_ms       INTEGER NOT NULL DEFAULT 5000,
    expected_status  INTEGER NOT NULL DEFAULT 200,
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_probes_service ON probes(service_id);

CREATE TABLE IF NOT EXISTS probe_results (
    id         TEXT PRIMARY KEY,
    probe_id   TEXT NOT NULL,
    ts         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    status     INTEGER,
    latency_ms INTEGER,
    healthy    INTEGER NOT NULL DEFAULT 1,
    error      TEXT,
    FOREIGN KEY (probe_id) REFERENCES probes(id)
);
CREATE INDEX IF NOT EXISTS idx_probe_results_probe_ts ON probe_results(probe_id, ts DESC);

CREATE TABLE IF NOT EXISTS snapshots (
    id          TEXT PRIMARY KEY,
    service_id  TEXT NOT NULL,
    name        TEXT NOT NULL,
    data        TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_snapshots_service ON snapshots(service_id, created_at DESC);

CREATE TABLE IF NOT EXISTS alert_rules (
    id               TEXT PRIMARY KEY,
    service_id       TEXT NOT NULL,
    name             TEXT NOT NULL,
    metric           TEXT NOT NULL,
    operator         TEXT NOT NULL DEFAULT 'gt',
    threshold        REAL NOT NULL,
    window_seconds   INTEGER NOT NULL DEFAULT 300,
    cooldown_seconds INTEGER NOT NULL DEFAULT 600,
    channels         TEXT NOT NULL DEFAULT '[]',
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_alert_rules_service ON alert_rules(service_id);

CREATE TABLE IF NOT EXISTS alert_events (
    id          TEXT PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    service_id  TEXT NOT NULL,
    ts          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    metric      TEXT NOT NULL,
    value       REAL NOT NULL,
    threshold   REAL NOT NULL,
    message     TEXT NOT NULL DEFAULT '',
    resolved    INTEGER NOT NULL DEFAULT 0,
    resolved_at TEXT,
    FOREIGN KEY (rule_id) REFERENCES alert_rules(id),
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_alert_events_service ON alert_events(service_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_alert_events_rule ON alert_events(rule_id, ts DESC);

CREATE TABLE IF NOT EXISTS ip_rules (
    id          TEXT PRIMARY KEY,
    service_id  TEXT NOT NULL,
    route_id    TEXT,
    cidr        TEXT NOT NULL,
    action      TEXT NOT NULL DEFAULT 'deny',
    description TEXT NOT NULL DEFAULT '',
    priority    INTEGER NOT NULL DEFAULT 0,
    enabled     INTEGER NOT NULL DEFAULT 1,
    hits        INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_ip_rules_service ON ip_rules(service_id);

CREATE TABLE IF NOT EXISTS error_pages (
    id           TEXT PRIMARY KEY,
    service_id   TEXT NOT NULL,
    status_code  INTEGER NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'text/html',
    body         TEXT NOT NULL DEFAULT '',
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_error_pages_service ON error_pages(service_id);

CREATE TABLE IF NOT EXISTS consumer_groups (
    id                  TEXT PRIMARY KEY,
    service_id          TEXT NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    rate_limit          INTEGER NOT NULL DEFAULT 100,
    rate_window_seconds INTEGER NOT NULL DEFAULT 60,
    burst_limit         INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_consumer_groups_service ON consumer_groups(service_id);

CREATE TABLE IF NOT EXISTS consumer_group_members (
    group_id    TEXT NOT NULL,
    consumer_id TEXT NOT NULL,
    joined_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (group_id, consumer_id),
    FOREIGN KEY (group_id)    REFERENCES consumer_groups(id),
    FOREIGN KEY (consumer_id) REFERENCES consumers(id)
);

-- ============================================================
-- Cache, Tracing, Transforms, Versioning, Incidents,
-- Webhooks, Load Testing, Marketplace, Cost, Cluster,
-- Rate-Limit Simulator, PKI  (migration 014)
-- ============================================================

CREATE TABLE IF NOT EXISTS cache_entries (
    id              TEXT PRIMARY KEY,
    service_id      TEXT NOT NULL,
    cache_key       TEXT NOT NULL,
    content_hash    TEXT NOT NULL DEFAULT '',
    size_bytes      INTEGER NOT NULL DEFAULT 0,
    ttl_seconds     INTEGER NOT NULL DEFAULT 300,
    hits            INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    is_deleted      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_cache_entries_service ON cache_entries(service_id) WHERE is_deleted = 0;
CREATE UNIQUE INDEX IF NOT EXISTS idx_cache_entries_key ON cache_entries(service_id, cache_key) WHERE is_deleted = 0;

CREATE TABLE IF NOT EXISTS traces (
    id              TEXT PRIMARY KEY,
    trace_id        TEXT NOT NULL,
    service_id      TEXT NOT NULL,
    route_id        TEXT,
    method          TEXT NOT NULL DEFAULT 'GET',
    path            TEXT NOT NULL DEFAULT '/',
    status          INTEGER NOT NULL DEFAULT 200,
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    span_count      INTEGER NOT NULL DEFAULT 0,
    has_errors      INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT,
    started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    is_deleted      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_traces_service ON traces(service_id, started_at) WHERE is_deleted = 0;
CREATE INDEX IF NOT EXISTS idx_traces_trace_id ON traces(trace_id) WHERE is_deleted = 0;

CREATE TABLE IF NOT EXISTS spans (
    id              TEXT PRIMARY KEY,
    trace_id        TEXT NOT NULL,
    span_id         TEXT NOT NULL,
    parent_span_id  TEXT,
    operation       TEXT NOT NULL DEFAULT '',
    service_name    TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'ok',
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    tags            TEXT,
    logs            TEXT,
    started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    is_deleted      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_spans_trace ON spans(trace_id) WHERE is_deleted = 0;

CREATE TABLE IF NOT EXISTS transform_rules (
    id              TEXT PRIMARY KEY,
    service_id      TEXT NOT NULL,
    route_id        TEXT,
    name            TEXT NOT NULL DEFAULT '',
    phase           TEXT NOT NULL DEFAULT 'request',
    action          TEXT NOT NULL DEFAULT 'set_header',
    target          TEXT NOT NULL DEFAULT '',
    value           TEXT NOT NULL DEFAULT '',
    condition       TEXT,
    priority        INTEGER NOT NULL DEFAULT 0,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    is_deleted      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_transform_rules_service ON transform_rules(service_id) WHERE is_deleted = 0;

CREATE TABLE IF NOT EXISTS api_versions (
    id              TEXT PRIMARY KEY,
    service_id      TEXT NOT NULL,
    version         TEXT NOT NULL DEFAULT '',
    base_path       TEXT NOT NULL DEFAULT '',
    upstream_path   TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active',
    deprecated_at   TEXT,
    sunset_at       TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    is_deleted      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_api_versions_service ON api_versions(service_id) WHERE is_deleted = 0;

CREATE TABLE IF NOT EXISTS incidents (
    id              TEXT PRIMARY KEY,
    service_id      TEXT NOT NULL,
    title           TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT 'minor',
    status          TEXT NOT NULL DEFAULT 'investigating',
    description     TEXT NOT NULL DEFAULT '',
    started_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    resolved_at     TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    is_deleted      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_incidents_service ON incidents(service_id) WHERE is_deleted = 0;

CREATE TABLE IF NOT EXISTS incident_updates (
    id              TEXT PRIMARY KEY,
    incident_id     TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT '',
    message         TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    is_deleted      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);
CREATE INDEX IF NOT EXISTS idx_incident_updates_incident ON incident_updates(incident_id) WHERE is_deleted = 0;

CREATE TABLE IF NOT EXISTS webhooks (
    id              TEXT PRIMARY KEY,
    service_id      TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    url             TEXT NOT NULL DEFAULT '',
    events          TEXT NOT NULL DEFAULT '[]',
    secret          TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    retry_count     INTEGER NOT NULL DEFAULT 3,
    timeout_ms      INTEGER NOT NULL DEFAULT 5000,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    is_deleted      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_webhooks_service ON webhooks(service_id) WHERE is_deleted = 0;

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id              TEXT PRIMARY KEY,
    webhook_id      TEXT NOT NULL,
    event_type      TEXT NOT NULL DEFAULT '',
    payload         TEXT NOT NULL DEFAULT '{}',
    response_status INTEGER,
    response_body   TEXT,
    success         INTEGER NOT NULL DEFAULT 0,
    attempts        INTEGER NOT NULL DEFAULT 1,
    delivered_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    is_deleted      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (webhook_id) REFERENCES webhooks(id)
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id) WHERE is_deleted = 0;

CREATE TABLE IF NOT EXISTS load_tests (
    id               TEXT PRIMARY KEY,
    service_id       TEXT NOT NULL,
    name             TEXT NOT NULL DEFAULT '',
    target_rps       INTEGER NOT NULL DEFAULT 100,
    duration_seconds INTEGER NOT NULL DEFAULT 30,
    concurrent_users INTEGER NOT NULL DEFAULT 10,
    method           TEXT NOT NULL DEFAULT 'GET',
    path             TEXT NOT NULL DEFAULT '/',
    headers          TEXT,
    body             TEXT,
    status           TEXT NOT NULL DEFAULT 'pending',
    result           TEXT,
    started_at       TEXT,
    completed_at     TEXT,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    is_deleted       INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_load_tests_service ON load_tests(service_id) WHERE is_deleted = 0;

CREATE TABLE IF NOT EXISTS marketplace_plugins (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    version         TEXT NOT NULL DEFAULT '0.1.0',
    author          TEXT NOT NULL DEFAULT '',
    category        TEXT NOT NULL DEFAULT 'general',
    schema          TEXT NOT NULL DEFAULT '{}',
    readme          TEXT NOT NULL DEFAULT '',
    downloads       INTEGER NOT NULL DEFAULT 0,
    rating          REAL NOT NULL DEFAULT 0.0,
    verified        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    is_deleted      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cost_records (
    id                TEXT PRIMARY KEY,
    service_id        TEXT NOT NULL,
    bucket_ts         TEXT NOT NULL,
    compute_cost      REAL NOT NULL DEFAULT 0.0,
    bandwidth_cost    REAL NOT NULL DEFAULT 0.0,
    storage_cost      REAL NOT NULL DEFAULT 0.0,
    total_cost        REAL NOT NULL DEFAULT 0.0,
    currency          TEXT NOT NULL DEFAULT 'USD',
    requests          INTEGER NOT NULL DEFAULT 0,
    bytes_transferred INTEGER NOT NULL DEFAULT 0,
    is_deleted        INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_cost_records_service ON cost_records(service_id, bucket_ts) WHERE is_deleted = 0;

CREATE TABLE IF NOT EXISTS cluster_nodes (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL DEFAULT '',
    address            TEXT NOT NULL DEFAULT '',
    port               INTEGER NOT NULL DEFAULT 0,
    role               TEXT NOT NULL DEFAULT 'worker',
    status             TEXT NOT NULL DEFAULT 'active',
    version            TEXT NOT NULL DEFAULT '',
    cpu_usage          REAL NOT NULL DEFAULT 0.0,
    memory_usage       REAL NOT NULL DEFAULT 0.0,
    active_connections INTEGER NOT NULL DEFAULT 0,
    last_heartbeat     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    joined_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    is_deleted         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rate_limit_simulations (
    id                  TEXT PRIMARY KEY,
    service_id          TEXT NOT NULL,
    consumer_id         TEXT,
    requests_per_second INTEGER NOT NULL DEFAULT 100,
    duration_seconds    INTEGER NOT NULL DEFAULT 10,
    rate_limit          INTEGER NOT NULL DEFAULT 60,
    window_seconds      INTEGER NOT NULL DEFAULT 60,
    burst               INTEGER NOT NULL DEFAULT 10,
    result              TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    is_deleted          INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (service_id) REFERENCES services(id)
);

CREATE TABLE IF NOT EXISTS certificates (
    id                 TEXT PRIMARY KEY,
    service_id         TEXT,
    domain             TEXT NOT NULL DEFAULT '',
    issuer             TEXT NOT NULL DEFAULT '',
    serial_number      TEXT NOT NULL DEFAULT '',
    not_before         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    not_after          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    fingerprint_sha256 TEXT NOT NULL DEFAULT '',
    auto_renew         INTEGER NOT NULL DEFAULT 1,
    status             TEXT NOT NULL DEFAULT 'active',
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    is_deleted         INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (service_id) REFERENCES services(id)
);
CREATE INDEX IF NOT EXISTS idx_certificates_domain ON certificates(domain) WHERE is_deleted = 0;

-- Triggers for tables with updated_at

CREATE TRIGGER IF NOT EXISTS trg_transform_rules_updated
  AFTER UPDATE ON transform_rules FOR EACH ROW
  BEGIN UPDATE transform_rules SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER IF NOT EXISTS trg_api_versions_updated
  AFTER UPDATE ON api_versions FOR EACH ROW
  BEGIN UPDATE api_versions SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER IF NOT EXISTS trg_incidents_updated
  AFTER UPDATE ON incidents FOR EACH ROW
  BEGIN UPDATE incidents SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER IF NOT EXISTS trg_webhooks_updated
  AFTER UPDATE ON webhooks FOR EACH ROW
  BEGIN UPDATE webhooks SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER IF NOT EXISTS trg_certificates_updated
  AFTER UPDATE ON certificates FOR EACH ROW
  BEGIN UPDATE certificates SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER IF NOT EXISTS trg_probes_updated
  AFTER UPDATE ON probes FOR EACH ROW
  BEGIN UPDATE probes SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER IF NOT EXISTS trg_alert_rules_updated
  AFTER UPDATE ON alert_rules FOR EACH ROW
  BEGIN UPDATE alert_rules SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER IF NOT EXISTS trg_ip_rules_updated
  AFTER UPDATE ON ip_rules FOR EACH ROW
  BEGIN UPDATE ip_rules SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER IF NOT EXISTS trg_error_pages_updated
  AFTER UPDATE ON error_pages FOR EACH ROW
  BEGIN UPDATE error_pages SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER IF NOT EXISTS trg_consumer_groups_updated
  AFTER UPDATE ON consumer_groups FOR EACH ROW
  BEGIN UPDATE consumer_groups SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER IF NOT EXISTS trg_marketplace_plugins_updated
  AFTER UPDATE ON marketplace_plugins FOR EACH ROW
  BEGIN UPDATE marketplace_plugins SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id; END;
