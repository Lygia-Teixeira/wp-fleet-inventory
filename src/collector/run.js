'use strict';
// CLI da coleta:  npm run collect -- [--server srv-01] [--deep]
// Pensado para rodar via cron/systemd timer. A API HTTP e somente leitura e
// nao dispara coletas (menos superficie para abuso e para carga acidental).
const { config } = require('../config');
const db = require('../db');
const { collectAll } = require('./collector');

function parseArgs(argv) {
  const args = { server: null, deep: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--deep') args.deep = true;
    else if (argv[i] === '--server') args.server = argv[++i] || null;
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  db.openDb(config.dbPath);
  const total = await collectAll({ config, onlyServer: args.server, deep: args.deep });
  console.log(`Coleta concluida: ${total} instalacao(oes).`);
}

main().catch((err) => {
  console.error(`Falha na coleta: ${err.message}`);
  process.exitCode = 1;
});
