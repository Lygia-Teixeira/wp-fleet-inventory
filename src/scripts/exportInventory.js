'use strict';
// npm run export -- --format csv|json [--out arquivo]
const fs = require('node:fs');
const { config } = require('../config');
const db = require('../db');
const { toCsv, toJson } = require('../export');
const { audit } = require('../audit');

const argv = process.argv.slice(2);
const opt = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};

const format = opt('--format') === 'json' ? 'json' : 'csv';
const out = opt('--out');

db.openDb(config.dbPath);
const rows = db.listSites();
const body = format === 'json' ? toJson(rows) : toCsv(rows);
audit('cli', 'sites_export', `${format} ${rows.length} linha(s)`);

if (out) {
  fs.writeFileSync(out, body, { mode: 0o600 });
  console.log(`${rows.length} linha(s) exportada(s) para ${out}`);
} else {
  process.stdout.write(body);
}
