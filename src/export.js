'use strict';
// Export CSV/JSON do inventario.
// CSV segue RFC 4180 e neutraliza CSV/Formula Injection (OWASP): dominio e
// docroot vem do servidor remoto, e uma celula comecando com = + - @ (ou
// tab/CR) pode virar formula ativa ao abrir no Excel/LibreOffice.

const EXPORT_COLUMNS = [
  'server_label',
  'account',
  'domain',
  'docroot',
  'wp_version',
  'php_version',
  'status',
  'status_detail',
  'discovery_method',
  'last_checked_at',
];

function neutralizeFormula(value) {
  if (typeof value !== 'string') return value;
  return /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
}

function csvCell(value) {
  if (value === null || value === undefined) return '';
  const s = String(neutralizeFormula(String(value)));
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function toCsv(rows, columns = EXPORT_COLUMNS) {
  const lines = [columns.join(',')];
  for (const row of rows) lines.push(columns.map((c) => csvCell(row[c])).join(','));
  return lines.join('\r\n') + '\r\n';
}

function toJson(rows, columns = EXPORT_COLUMNS) {
  const data = rows.map((row) => Object.fromEntries(columns.map((c) => [c, row[c] ?? null])));
  return JSON.stringify({ generated_at: new Date().toISOString(), count: data.length, sites: data }, null, 2);
}

module.exports = { toCsv, toJson, neutralizeFormula, EXPORT_COLUMNS };
