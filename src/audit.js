'use strict';
// Trilha de auditoria append-only (no nivel da aplicacao: nao ha rota de
// UPDATE/DELETE). Registra quem consultou/exportou o inventario, falhas de
// autenticacao e cada execucao da coleta. Nunca grava segredos.
const { getDb } = require('./db');

const MAX_DETAIL = 500;

function audit(actor, action, detail = null, ip = null) {
  const safeDetail = detail == null ? null : String(detail).replace(/[\r\n]+/g, ' ').slice(0, MAX_DETAIL);
  getDb()
    .prepare('INSERT INTO audit_log (actor, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(String(actor || 'anonimo').slice(0, 100), String(action).slice(0, 50), safeDetail, ip);
}

function listAudit(limit = 100) {
  const n = Math.min(Math.max(Number.parseInt(limit, 10) || 100, 1), 1000);
  return getDb().prepare('SELECT id, ts, actor, action, detail, ip FROM audit_log ORDER BY id DESC LIMIT ?').all(n);
}

module.exports = { audit, listAudit };
