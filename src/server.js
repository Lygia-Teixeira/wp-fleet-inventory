'use strict';
// API HTTP somente leitura + pagina estatica.
//   node src/server.js          -> usa o banco configurado em DB_PATH
//   node src/server.js --demo   -> banco em memoria com dados ficticios
const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const { config } = require('./config');
const db = require('./db');
const { audit, listAudit } = require('./audit');
const { createAuthMiddleware } = require('./auth');
const { toCsv, toJson } = require('./export');
const { seedDemo } = require('./demo');

const DEMO = process.argv.includes('--demo');
const STATUSES = new Set(['ok', 'suspended', 'error', 'unreachable']);

function buildApp(authConfig) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', false); // ligue explicitamente se houver proxy reverso confiavel

  app.use((req, res, next) => {
    res.set({
      'Content-Security-Policy':
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
    });
    next();
  });

  app.get('/api/health', (req, res) => res.json({ ok: true, demo: DEMO }));

  const requireAuth = createAuthMiddleware(authConfig);
  const api = express.Router();
  api.use(requireAuth);

  function filtersFrom(query) {
    const status = typeof query.status === 'string' && STATUSES.has(query.status) ? query.status : undefined;
    const q = typeof query.q === 'string' ? query.q : undefined;
    const server = typeof query.server === 'string' ? query.server.slice(0, 64) : undefined;
    return { q, status, server };
  }

  api.get('/sites', (req, res) => {
    const filters = filtersFrom(req.query);
    const sites = db.listSites(filters);
    audit(req.actor, 'sites_list', JSON.stringify(filters), req.ip);
    res.json({ count: sites.length, sites });
  });

  api.get('/sites/export', (req, res) => {
    const format = req.query.format === 'json' ? 'json' : 'csv';
    const filters = filtersFrom(req.query);
    const sites = db.listSites(filters);
    audit(req.actor, 'sites_export', `${format} ${sites.length} linha(s)`, req.ip);
    const stamp = new Date().toISOString().slice(0, 10);
    res.attachment(`wp-inventory-${stamp}.${format}`);
    if (format === 'json') res.type('application/json').send(toJson(sites));
    else res.type('text/csv; charset=utf-8').send(toCsv(sites));
  });

  api.get('/servers', (req, res) => {
    res.json({ servers: db.listServersPublic() });
  });

  api.get('/audit', (req, res) => {
    res.json({ entries: listAudit(req.query.limit) });
  });

  app.use('/api', api);
  app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html' }));

  app.use((err, req, res, _next) => {
    console.error('[erro]', err.message);
    if (!res.headersSent) res.status(500).json({ error: 'erro interno' });
  });
  return app;
}

function main() {
  const authConfig = { ...config.auth };
  if (DEMO) {
    db.openDb(':memory:');
    const n = seedDemo();
    if (!authConfig.apiToken && !authConfig.basicUser) {
      authConfig.apiToken = crypto.randomBytes(24).toString('base64url');
      console.log(`[demo] token temporario da API (vale so para este processo): ${authConfig.apiToken}`);
    }
    console.log(`[demo] ${n} instalacoes ficticias carregadas em memoria (nenhuma conexao SSH).`);
  } else {
    db.openDb(config.dbPath);
  }

  const app = buildApp(authConfig);
  app.listen(config.port, config.bindAddress, () => {
    console.log(`wp-fleet-inventory em http://${config.bindAddress}:${config.port}`);
  });
}

if (require.main === module) main();

module.exports = { buildApp };
