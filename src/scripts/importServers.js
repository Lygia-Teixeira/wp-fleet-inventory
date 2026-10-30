'use strict';
// npm run import-servers -- caminho/servers.json
// Le a lista de servidores, busca o segredo (variavel de ambiente ou arquivo
// de chave privada), cifra com AES-256-GCM (AAD = "server:<label>") e grava
// no SQLite. O JSON de entrada nunca contem o segredo em si.
const fs = require('node:fs');
const path = require('node:path');
const { config } = require('../config');
const db = require('../db');
const { encrypt } = require('../crypto/secretBox');
const { audit } = require('../audit');

const LABEL_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
const HOST_RE = /^[a-z0-9.-]{1,253}$|^[0-9a-f:]{2,39}$/i;

function readSecret(server, baseDir) {
  const auth = server.auth || {};
  if (auth.type === 'password') {
    const value = process.env[auth.secretEnv || ''];
    if (!value) throw new Error(`${server.label}: variavel ${auth.secretEnv} vazia`);
    return value;
  }
  if (auth.type === 'key') {
    const keyPath = path.resolve(baseDir, auth.privateKeyPath || '');
    return fs.readFileSync(keyPath, 'utf8');
  }
  throw new Error(`${server.label}: auth.type deve ser "password" ou "key"`);
}

function main() {
  const file = process.argv[2];
  if (!file) throw new Error('uso: npm run import-servers -- servers.json');
  if (!config.secretsKey) throw new Error('SECRETS_KEY nao configurada');
  const input = JSON.parse(fs.readFileSync(file, 'utf8'));
  db.openDb(config.dbPath);

  for (const s of input.servers || []) {
    if (!LABEL_RE.test(s.label || '')) throw new Error(`label invalido: ${s.label}`);
    if (!HOST_RE.test(s.host || '')) throw new Error(`${s.label}: host invalido`);
    const port = Number(s.port || 22);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`${s.label}: porta invalida`);
    const secret = readSecret(s, config.root);
    db.upsertServer({
      label: s.label,
      host: s.host,
      port,
      username: s.username,
      auth_type: s.auth.type,
      secret_enc: encrypt(secret, config.secretsKey, `server:${s.label}`),
      discovery: s.discovery ? JSON.stringify(s.discovery) : null,
    });
    audit('cli', 'server_import', `${s.label} (${s.auth.type})`);
    console.log(`importado: ${s.label} (${s.auth.type}, segredo cifrado)`);
  }
}

try {
  main();
} catch (err) {
  console.error(err.message);
  process.exitCode = 1;
}
