'use strict';
// Persistencia em SQLite usando o modulo nativo node:sqlite (Node >= 22.13):
// sem dependencia nativa de terceiros para compilar = menos superficie de
// supply chain. Todas as queries sao parametrizadas.
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS servers (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  label       TEXT NOT NULL UNIQUE,
  host        TEXT NOT NULL,
  port        INTEGER NOT NULL DEFAULT 22,
  username    TEXT NOT NULL,
  auth_type   TEXT NOT NULL CHECK (auth_type IN ('password', 'key', 'demo')),
  secret_enc  TEXT,                 -- envelope AES-256-GCM (nunca texto puro)
  discovery   TEXT,                 -- JSON opcional (findRoot, findMaxDepth)
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sites (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  server_label     TEXT NOT NULL,
  server_host      TEXT NOT NULL,
  account          TEXT,
  domain           TEXT,
  docroot          TEXT NOT NULL,
  wp_version       TEXT,
  php_version      TEXT,
  status           TEXT NOT NULL,   -- ok | suspended | error | unreachable
  status_detail    TEXT,
  discovery_method TEXT,            -- whm | find | demo
  last_checked_at  TEXT NOT NULL,
  UNIQUE (server_host, docroot)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  actor   TEXT NOT NULL,
  action  TEXT NOT NULL,
  detail  TEXT,
  ip      TEXT
);

CREATE INDEX IF NOT EXISTS idx_sites_server ON sites (server_label);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts);
`;

let db = null;

function openDb(dbPath) {
  if (db) return db;
  if (dbPath !== ':memory:') fs.mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o700 });
  db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  return db;
}

function getDb() {
  if (!db) throw new Error('banco nao inicializado - chame openDb() antes');
  return db;
}

function upsertSite(row) {
  getDb()
    .prepare(
      `INSERT INTO sites (server_label, server_host, account, domain, docroot, wp_version, php_version,
                          status, status_detail, discovery_method, last_checked_at)
       VALUES (:server_label, :server_host, :account, :domain, :docroot, :wp_version, :php_version,
               :status, :status_detail, :discovery_method, :last_checked_at)
       ON CONFLICT (server_host, docroot) DO UPDATE SET
         server_label = excluded.server_label, account = excluded.account, domain = excluded.domain,
         wp_version = excluded.wp_version, php_version = excluded.php_version, status = excluded.status,
         status_detail = excluded.status_detail, discovery_method = excluded.discovery_method,
         last_checked_at = excluded.last_checked_at`
    )
    .run({
      account: null,
      domain: null,
      wp_version: null,
      php_version: null,
      status_detail: null,
      discovery_method: null,
      last_checked_at: new Date().toISOString(),
      ...row,
    });
}

const SITE_COLUMNS =
  'id, server_label, account, domain, docroot, wp_version, php_version, status, status_detail, discovery_method, last_checked_at';

function listSites({ q, status, server } = {}) {
  const where = [];
  const params = {};
  if (q) {
    where.push('(domain LIKE :q OR docroot LIKE :q OR account LIKE :q)');
    params.q = `%${String(q).slice(0, 100)}%`;
  }
  if (status) {
    where.push('status = :status');
    params.status = String(status);
  }
  if (server) {
    where.push('server_label = :server');
    params.server = String(server);
  }
  const sql = `SELECT ${SITE_COLUMNS} FROM sites ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
               ORDER BY server_label, domain, docroot`;
  return getDb().prepare(sql).all(params);
}

// Lista de servidores SEM o segredo - e o que a API expoe.
function listServersPublic() {
  return getDb().prepare('SELECT label, host, port, username, auth_type, created_at FROM servers ORDER BY label').all();
}

function listServersWithSecrets() {
  return getDb().prepare('SELECT label, host, port, username, auth_type, secret_enc, discovery FROM servers ORDER BY label').all();
}

function upsertServer({ label, host, port, username, auth_type, secret_enc, discovery }) {
  getDb()
    .prepare(
      `INSERT INTO servers (label, host, port, username, auth_type, secret_enc, discovery)
       VALUES (:label, :host, :port, :username, :auth_type, :secret_enc, :discovery)
       ON CONFLICT (label) DO UPDATE SET host = excluded.host, port = excluded.port, username = excluded.username,
         auth_type = excluded.auth_type, secret_enc = excluded.secret_enc, discovery = excluded.discovery`
    )
    .run({ label, host, port, username, auth_type, secret_enc: secret_enc ?? null, discovery: discovery ?? null });
}

module.exports = { openDb, getDb, upsertSite, listSites, listServersPublic, listServersWithSecrets, upsertServer };
