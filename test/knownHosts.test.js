'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { parseKnownHosts, verifyHostKey } = require('../src/ssh/knownHosts');

// "Chaves" ficticias: so os bytes importam para a comparacao.
const keyA = crypto.randomBytes(51);
const keyB = crypto.randomBytes(51);
const b64 = (b) => b.toString('base64');

function hashed(token) {
  const salt = crypto.randomBytes(20);
  const mac = crypto.createHmac('sha1', salt).update(token).digest();
  return `|1|${salt.toString('base64')}|${mac.toString('base64')}`;
}

const text = [
  '# comentario',
  `srv-01.example.com,192.0.2.10 ssh-ed25519 ${b64(keyA)}`,
  `[192.0.2.20]:2222 ssh-ed25519 ${b64(keyA)}`,
  `${hashed('192.0.2.30')} ssh-ed25519 ${b64(keyB)}`,
  `@revoked *.example.com ssh-ed25519 ${b64(keyB)}`,
].join('\n');
const entries = parseKnownHosts(text);

test('aceita chave registrada (host em texto)', () => {
  assert.equal(verifyHostKey(entries, 'srv-01.example.com', 22, keyA).ok, true);
  assert.equal(verifyHostKey(entries, '192.0.2.10', 22, keyA).ok, true);
});

test('porta nao padrao usa [host]:porta', () => {
  assert.equal(verifyHostKey(entries, '192.0.2.20', 2222, keyA).ok, true);
  assert.equal(verifyHostKey(entries, '192.0.2.20', 22, keyA).ok, false);
});

test('aceita host hasheado', () => {
  assert.equal(verifyHostKey(entries, '192.0.2.30', 22, keyB).ok, true);
});

test('rejeita chave divergente (MITM)', () => {
  const r = verifyHostKey(entries, 'srv-01.example.com', 22, keyB);
  assert.equal(r.ok, false);
  assert.match(r.reason, /revoked|DIVERGENTE/);
});

test('rejeita host desconhecido', () => {
  const r = verifyHostKey(entries, '192.0.2.99', 22, keyA);
  assert.equal(r.ok, false);
  assert.match(r.reason, /nao consta/);
});

test('@revoked tem precedencia', () => {
  const r = verifyHostKey(entries, 'srv-01.example.com', 22, keyB);
  assert.match(r.reason, /revoked/);
});
