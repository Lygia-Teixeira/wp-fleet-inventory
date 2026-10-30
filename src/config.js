'use strict';
// Configuracao centralizada, lida do ambiente (.env via dotenv). Nenhum
// segredo tem valor padrao: se nao estiver definido, o recurso que depende
// dele falha de forma explicita em vez de cair num default inseguro.
const path = require('node:path');
require('dotenv').config({ quiet: true });

const PLACEHOLDER = 'CHANGE_ME';

function str(name, fallback = undefined) {
  const v = process.env[name];
  if (v === undefined || v === '' || v === PLACEHOLDER) return fallback;
  return v;
}

function int(name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = str(name);
  if (raw === undefined) return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${name} invalido: esperado inteiro entre ${min} e ${max}`);
  }
  return n;
}

const root = path.resolve(__dirname, '..');

const config = {
  root,
  port: int('PORT', 8080, { min: 1, max: 65535 }),
  bindAddress: str('BIND_ADDRESS', '127.0.0.1'),
  dbPath: path.resolve(root, str('DB_PATH', './data/inventory.db')),
  knownHostsPath: path.resolve(root, str('KNOWN_HOSTS_PATH', './data/known_hosts')),
  secretsKey: str('SECRETS_KEY'),
  auth: {
    apiToken: str('API_TOKEN'),
    basicUser: str('BASIC_AUTH_USER'),
    basicHash: str('BASIC_AUTH_HASH'),
  },
  collect: {
    maxChannels: int('COLLECT_MAX_CHANNELS', 4, { min: 1, max: 8 }),
    serverConcurrency: int('COLLECT_SERVER_CONCURRENCY', 1, { min: 1, max: 8 }),
    commandTimeoutMs: int('COLLECT_COMMAND_TIMEOUT_MS', 30000, { min: 1000 }),
    serverTimeoutMs: int('COLLECT_SERVER_TIMEOUT_MS', 600000, { min: 10000 }),
    connectRetries: int('COLLECT_CONNECT_RETRIES', 2, { min: 0, max: 5 }),
  },
};

module.exports = { config, PLACEHOLDER };
