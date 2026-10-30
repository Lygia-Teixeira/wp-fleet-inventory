'use strict';
// Cifra autenticada (AES-256-GCM) para credenciais SSH em repouso.
//
// - A chave vem do ambiente (SECRETS_KEY, 32 bytes em base64), nunca do banco:
//   uma copia solta do .db (backup, snapshot) nao revela nada sem ela.
// - IV aleatorio de 96 bits por cifragem (nunca reutilizado com a mesma chave).
// - AAD (additional authenticated data) amarra o ciphertext ao seu contexto
//   (ex.: "server:srv-01"): copiar o segredo de uma linha para outra no banco
//   faz a decifragem falhar, em vez de entregar a senha do servidor errado.
// - Formato versionado ("v1.") para permitir rotacao de algoritmo/chave.
//
// Limite conhecido: quem tem acesso ao processo ou ao ambiente (.env) tem a
// chave. Para isso o caminho e um cofre externo (Vault, KMS, etc.).
const crypto = require('node:crypto');

const ALGORITHM = 'aes-256-gcm';
const VERSION = 'v1';
const IV_BYTES = 12;
const TAG_BYTES = 16;

function parseKey(keyMaterial) {
  if (Buffer.isBuffer(keyMaterial)) {
    if (keyMaterial.length !== 32) throw new Error('chave precisa ter 32 bytes');
    return keyMaterial;
  }
  if (typeof keyMaterial !== 'string' || keyMaterial.length === 0) {
    throw new Error('SECRETS_KEY ausente - gere uma com `npm run gen-key`');
  }
  const key = Buffer.from(keyMaterial, 'base64');
  if (key.length !== 32) {
    throw new Error('SECRETS_KEY deve ser 32 bytes codificados em base64');
  }
  return key;
}

function encrypt(plainText, keyMaterial, aad = '') {
  const key = parseKey(keyMaterial);
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [VERSION, iv.toString('base64'), tag.toString('base64'), ct.toString('base64')].join('.');
}

function decrypt(envelope, keyMaterial, aad = '') {
  if (typeof envelope !== 'string') throw new Error('envelope invalido');
  const parts = envelope.split('.');
  if (parts.length !== 4 || parts[0] !== VERSION) {
    throw new Error('envelope em formato desconhecido (esperado v1)');
  }
  const [, ivB64, tagB64, ctB64] = parts;
  const key = parseKey(keyMaterial);
  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) throw new Error('envelope corrompido');
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag);
  // final() lanca se a tag nao bater (dado adulterado, AAD ou chave errada).
  return Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64')), decipher.final()]).toString('utf8');
}

function generateKey() {
  return crypto.randomBytes(32).toString('base64');
}

module.exports = { encrypt, decrypt, generateKey };
