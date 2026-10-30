'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { encrypt, decrypt, generateKey } = require('../src/crypto/secretBox');

const key = generateKey();

test('round-trip com AAD', () => {
  const env = encrypt('senha-de-teste', key, 'server:srv-01');
  assert.match(env, /^v1\./);
  assert.equal(decrypt(env, key, 'server:srv-01'), 'senha-de-teste');
});

test('IV aleatorio: mesmo texto gera envelopes diferentes', () => {
  assert.notEqual(encrypt('x', key), encrypt('x', key));
});

test('AAD diferente (segredo copiado para outro servidor) falha', () => {
  const env = encrypt('segredo', key, 'server:srv-01');
  assert.throws(() => decrypt(env, key, 'server:srv-02'));
});

test('chave errada falha', () => {
  const env = encrypt('segredo', key);
  assert.throws(() => decrypt(env, generateKey()));
});

test('ciphertext adulterado falha (integridade GCM)', () => {
  const env = encrypt('segredo', key);
  const parts = env.split('.');
  const ct = Buffer.from(parts[3], 'base64');
  ct[0] ^= 0x01;
  parts[3] = ct.toString('base64');
  assert.throws(() => decrypt(parts.join('.'), key));
});

test('chave invalida e formato desconhecido sao recusados', () => {
  assert.throws(() => encrypt('x', 'curta'));
  assert.throws(() => encrypt('x', undefined));
  assert.throws(() => decrypt('v0.a.b.c', key));
  assert.throws(() => decrypt('texto-puro', key));
});
