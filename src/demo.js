'use strict';
// Dados ficticios para o modo --demo: nenhum SSH, nenhum servidor real.
// Dominios em example.com/.test e IPs do bloco de documentacao 192.0.2.0/24.
const db = require('./db');
const { audit } = require('./audit');

const SERVERS = [
  { label: 'srv-01', host: 'srv-01.example.com', port: 22, username: 'inventory' },
  { label: 'srv-02', host: '192.0.2.20', port: 2222, username: 'inventory' },
  { label: 'srv-03', host: '192.0.2.30', port: 22, username: 'inventory' },
];

const WP_VERSIONS = ['6.6.2', '6.5.5', '6.4.3', '6.2.6', '5.9.10', '4.9.26'];
const PHP_VERSIONS = ['8.3', '8.2', '8.1', '7.4', '7.4', '5.6'];

// PRNG deterministico: o demo gera sempre o mesmo inventario.
function prng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

function seedDemo() {
  const rand = prng(42);
  const pick = (arr) => arr[Math.floor(rand() * arr.length)];
  const now = new Date().toISOString();

  for (const s of SERVERS) db.upsertServer({ ...s, auth_type: 'demo', secret_enc: null });

  let n = 0;
  for (const srv of SERVERS) {
    const count = 6 + Math.floor(rand() * 5);
    for (let i = 0; i < count; i++) {
      n++;
      const account = `conta${String(n).padStart(2, '0')}`;
      const viaFind = srv.label === 'srv-03';
      const idx = Math.floor(rand() * WP_VERSIONS.length);
      const roll = rand();
      let status = 'ok';
      let detail = null;
      if (roll > 0.92) {
        status = 'suspended';
        detail = 'conta suspensa (WHM)';
      } else if (roll > 0.85) {
        status = 'error';
        detail = 'PHP Fatal error: Uncaught Error: Call to undefined function (versao de PHP incompativel)';
      } else if (roll > 0.8) {
        status = 'unreachable';
        detail = 'timeout de 30000ms em fs.read_wp_version';
      }
      db.upsertSite({
        server_label: srv.label,
        server_host: srv.host,
        account,
        domain: viaFind ? null : `site${n}.example.com`,
        docroot: `/home/${account}/public_html${rand() > 0.85 ? '/blog' : ''}`,
        wp_version: status === 'unreachable' ? null : WP_VERSIONS[idx],
        php_version: viaFind ? null : PHP_VERSIONS[idx] || pick(PHP_VERSIONS),
        status,
        status_detail: detail,
        discovery_method: viaFind ? 'find' : 'whm',
        last_checked_at: now,
      });
    }
  }
  audit('demo', 'demo_seed', `${n} instalacoes ficticias em ${SERVERS.length} servidores`);
  return n;
}

module.exports = { seedDemo };
