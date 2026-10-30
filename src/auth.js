'use strict';
// Autenticacao minima da API: Bearer token OU Basic com hash bcrypt.
// - comparacao em tempo constante (timingSafeEqual sobre SHA-256, que
//   normaliza o tamanho e nao vaza o comprimento do token);
// - limite de falhas por IP com bloqueio temporario;
// - toda falha vai para a trilha de auditoria.
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const { audit } = require('./audit');

const MAX_FAILURES = 5;
const WINDOW_MS = 10 * 60 * 1000;
const failures = new Map(); // ip -> { count, first }

function sha256(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest();
}

function safeEqual(a, b) {
  return crypto.timingSafeEqual(sha256(a), sha256(b));
}

function isBlocked(ip) {
  const f = failures.get(ip);
  if (!f) return false;
  if (Date.now() - f.first > WINDOW_MS) {
    failures.delete(ip);
    return false;
  }
  return f.count >= MAX_FAILURES;
}

function registerFailure(ip) {
  const f = failures.get(ip);
  if (!f || Date.now() - f.first > WINDOW_MS) failures.set(ip, { count: 1, first: Date.now() });
  else f.count++;
}

function validateAuthConfig(auth) {
  const hasToken = Boolean(auth.apiToken);
  const hasBasic = Boolean(auth.basicUser && auth.basicHash);
  if (!hasToken && !hasBasic) {
    throw new Error('nenhum metodo de autenticacao configurado (API_TOKEN ou BASIC_AUTH_USER + BASIC_AUTH_HASH)');
  }
  if (hasToken && auth.apiToken.length < 32) throw new Error('API_TOKEN precisa ter pelo menos 32 caracteres');
  if (hasBasic && !/^\$2[aby]\$\d{2}\$/.test(auth.basicHash)) throw new Error('BASIC_AUTH_HASH nao parece um hash bcrypt');
}

function createAuthMiddleware(auth) {
  validateAuthConfig(auth);

  return async function requireAuth(req, res, next) {
    const ip = req.ip;
    if (isBlocked(ip)) {
      return res.status(429).json({ error: 'muitas tentativas falhas; aguarde' });
    }
    const header = req.get('authorization') || '';
    const [scheme, value] = header.split(' ', 2);
    let actor = null;

    try {
      if (auth.apiToken && /^bearer$/i.test(scheme || '') && value && safeEqual(value, auth.apiToken)) {
        actor = 'token';
      } else if (auth.basicUser && auth.basicHash && /^basic$/i.test(scheme || '') && value) {
        const decoded = Buffer.from(value, 'base64').toString('utf8');
        const sep = decoded.indexOf(':');
        const user = sep >= 0 ? decoded.slice(0, sep) : '';
        const pass = sep >= 0 ? decoded.slice(sep + 1) : '';
        // bcrypt.compare sempre roda (mesmo com usuario errado) para nao
        // revelar por tempo de resposta se o usuario existe.
        const passOk = await bcrypt.compare(pass, auth.basicHash);
        if (passOk && safeEqual(user, auth.basicUser)) actor = `basic:${auth.basicUser}`;
      }
    } catch {
      actor = null;
    }

    if (!actor) {
      registerFailure(ip);
      audit('anonimo', 'auth_failed', `${req.method} ${req.path}`, ip);
      if (auth.basicUser) res.set('WWW-Authenticate', 'Basic realm="wp-fleet-inventory", charset="UTF-8"');
      return res.status(401).json({ error: 'nao autenticado' });
    }
    failures.delete(ip);
    req.actor = actor;
    return next();
  };
}

module.exports = { createAuthMiddleware, validateAuthConfig, safeEqual };
