'use strict';
// Descoberta de instalacoes WordPress em um servidor.
// 1. WHM API (cPanel): fonte autoritativa - traz dominio, conta, PHP da conta
//    (MultiPHP) e se a conta esta suspensa.
// 2. Fallback `find` por wp-config.php quando nao ha WHM (ou ela falha/expira):
//    sem dominio nem PHP por site, mas o inventario nao fica vazio.
const { commands } = require('../ssh/commands');
const { mapWithConcurrency } = require('../util/concurrency');
const { parseWhmVhosts, parseFindOutput, accountFromDocroot } = require('./parsers');

async function discoverViaWhm(session, log) {
  let res;
  try {
    // A WHM enumera TODAS as contas; em servidores grandes passa dos 30s.
    res = await session.run(commands.whmVhostVersions(), { timeoutMs: 90000 });
  } catch (err) {
    log(`WHM indisponivel (${err.message}) - usando fallback`);
    return null;
  }
  if (res.code !== 0 || !res.stdout.trim()) return null;
  const vhosts = parseWhmVhosts(res.stdout);
  if (vhosts.length === 0) return null;

  // Nem todo vhost e WordPress: confirma wp-config.php (comando leve).
  const checks = await mapWithConcurrency(vhosts, 4, (v) => session.run(commands.hasWpConfig(v.docroot)));
  return vhosts
    .filter((_, i) => checks[i] && !checks[i].error && checks[i].stdout.trim() === 'yes')
    .map((v) => ({ ...v, method: 'whm' }));
}

async function discoverViaFind(session, { findRoot = '/home', findMaxDepth = 4 } = {}) {
  const res = await session.run(commands.findWpConfigs({ root: findRoot, maxDepth: findMaxDepth }), { timeoutMs: 120000 });
  return parseFindOutput(res.stdout).map((docroot) => ({
    docroot,
    domain: null,
    account: accountFromDocroot(docroot),
    phpVersion: null,
    suspended: false,
    method: 'find',
  }));
}

async function discoverInstallations(session, discoveryOpts = {}, log = () => {}) {
  const viaWhm = await discoverViaWhm(session, log);
  if (viaWhm) {
    log(`${viaWhm.length} instalacao(oes) via WHM`);
    return viaWhm;
  }
  const viaFind = await discoverViaFind(session, discoveryOpts);
  log(`${viaFind.length} instalacao(oes) via find`);
  return viaFind;
}

module.exports = { discoverInstallations };
