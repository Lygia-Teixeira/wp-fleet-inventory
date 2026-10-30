'use strict';
// Orquestracao da coleta: servidores em sequencia (ou com concorrencia
// baixa configuravel), UMA conexao SSH por servidor, N canais por conexao.
const fs = require('node:fs');
const { SshSession, isRetryableConnectError } = require('../ssh/session');
const { commands } = require('../ssh/commands');
const { loadKnownHosts } = require('../ssh/knownHosts');
const { decrypt } = require('../crypto/secretBox');
const { mapWithConcurrency, withTimeout, retry } = require('../util/concurrency');
const { discoverInstallations } = require('./discovery');
const { parsePhpBinaryList, parseWpVersionLine, parseWpEvalOutput, domainFromUrl } = require('./parsers');
const db = require('../db');
const { audit } = require('../audit');

function trimDetail(text) {
  return String(text || '').trim().replace(/\s+/g, ' ').slice(0, 300) || null;
}

// Monta o alvo SSH decifrando o segredo so no momento do uso (nunca loga).
function buildTarget(serverRow, secretsKey) {
  const secret = serverRow.secret_enc ? decrypt(serverRow.secret_enc, secretsKey, `server:${serverRow.label}`) : null;
  return {
    label: serverRow.label,
    host: serverRow.host,
    port: serverRow.port,
    username: serverRow.username,
    password: serverRow.auth_type === 'password' ? secret : undefined,
    privateKey: serverRow.auth_type === 'key' ? secret : undefined,
  };
}

// Coleta de uma instalacao. Padrao: leitura estatica de version.php (nao
// executa PHP). Com deep=true: WP-CLI como dono da conta, com o ea-phpXX certo.
async function collectInstallation(session, inst, ctx) {
  const base = {
    account: inst.account,
    domain: inst.domain,
    docroot: inst.docroot,
    php_version: inst.phpVersion,
    discovery_method: inst.method,
  };
  if (inst.suspended) {
    // Conta suspensa ainda "responde" localmente; o status real e suspensa.
    const r = await session.run(commands.readWpVersionFile(inst.docroot));
    return { ...base, wp_version: parseWpVersionLine(r.stdout), status: 'suspended', status_detail: 'conta suspensa (WHM)' };
  }

  const r = await session.run(commands.readWpVersionFile(inst.docroot));
  const wpVersion = parseWpVersionLine(r.stdout);
  if (!wpVersion) {
    return { ...base, wp_version: null, status: 'error', status_detail: 'wp-includes/version.php ausente ou ilegivel' };
  }
  if (!ctx.deep || !ctx.wpCliPath || !inst.account) {
    return { ...base, wp_version: wpVersion, status: 'ok', status_detail: null };
  }

  const phpBinary = inst.phpVersion ? ctx.phpBinaries[inst.phpVersion] || null : null;
  const ev = await session.run(
    commands.wpEvalInfo({ docroot: inst.docroot, account: inst.account, wpCliPath: ctx.wpCliPath, phpBinary }),
    { timeoutMs: 45000 }
  );
  if (ev.code !== 0) {
    return { ...base, wp_version: wpVersion, status: 'error', status_detail: trimDetail(ev.stderr) || 'wp eval falhou' };
  }
  const info = parseWpEvalOutput(ev.stdout);
  return {
    ...base,
    domain: domainFromUrl(info.siteUrl) || base.domain,
    wp_version: info.wpVersion || wpVersion,
    status: 'ok',
    status_detail: null,
  };
}

async function collectServer(serverRow, { secretsKey, knownHosts, collectOpts, deep = false, log = console.log }) {
  const label = serverRow.label;
  const say = (msg) => log(`[${label}] ${msg}`);
  const target = buildTarget(serverRow, secretsKey);
  const discoveryOpts = serverRow.discovery ? JSON.parse(serverRow.discovery) : {};

  const session = new SshSession(target, {
    knownHosts,
    maxChannels: collectOpts.maxChannels,
    commandTimeoutMs: collectOpts.commandTimeoutMs,
  });

  await retry(() => session.connect(), {
    retries: collectOpts.connectRetries,
    baseDelayMs: 2000,
    shouldRetry: isRetryableConnectError,
    onRetry: (err, n, delay) => say(`falha ao conectar (${err.message}); tentativa ${n} em ${delay}ms`),
  });
  say(`conectado (host key ${session.hostKeyFingerprint})`);

  try {
    const installations = await discoverInstallations(session, discoveryOpts, say);
    const ctx = { deep, phpBinaries: {}, wpCliPath: null };
    if (deep) {
      ctx.phpBinaries = parsePhpBinaryList((await session.run(commands.listEaPhpBinaries())).stdout);
      ctx.wpCliPath = (await session.run(commands.whichWpCli())).stdout.trim().split('\n')[0] || null;
      say(`modo profundo: wp-cli=${ctx.wpCliPath || 'ausente'}, PHPs=${Object.keys(ctx.phpBinaries).join(',') || 'nenhum'}`);
    }

    // Concorrencia menor que o limite de canais: no modo profundo cada site
    // faz bootstrap completo do WordPress (CPU/memoria do servidor de producao).
    const perSite = deep ? Math.min(2, collectOpts.maxChannels) : collectOpts.maxChannels;
    const results = await mapWithConcurrency(installations, perSite, (inst) => collectInstallation(session, inst, ctx));

    let ok = 0;
    results.forEach((res, i) => {
      const inst = installations[i];
      const row = res && res.error
        ? {
            account: inst.account,
            domain: inst.domain,
            docroot: inst.docroot,
            php_version: inst.phpVersion,
            discovery_method: inst.method,
            wp_version: null,
            status: 'unreachable',
            status_detail: trimDetail(res.error.message),
          }
        : res;
      if (row.status === 'ok') ok++;
      db.upsertSite({ server_label: label, server_host: target.host, ...row });
    });
    say(`${installations.length} instalacao(oes), ${ok} ok`);
    return installations.length;
  } finally {
    session.close();
  }
}

async function collectAll({ config, onlyServer = null, deep = false, log = console.log }) {
  if (!config.secretsKey) throw new Error('SECRETS_KEY nao configurada');
  if (!fs.existsSync(config.knownHostsPath)) throw new Error(`known_hosts ausente: ${config.knownHostsPath}`);
  const knownHosts = loadKnownHosts(config.knownHostsPath);
  const servers = db.listServersWithSecrets().filter((s) => s.auth_type !== 'demo' && (!onlyServer || s.label === onlyServer));

  audit('coletor', 'collect_start', `${servers.length} servidor(es)${deep ? ', modo profundo' : ''}`);
  let total = 0;
  const outcomes = await mapWithConcurrency(servers, config.collect.serverConcurrency, (srv) =>
    withTimeout(
      collectServer(srv, { secretsKey: config.secretsKey, knownHosts, collectOpts: config.collect, deep, log }),
      config.collect.serverTimeoutMs,
      `servidor excedeu ${config.collect.serverTimeoutMs}ms`
    )
  );
  outcomes.forEach((o, i) => {
    if (o && o.error) {
      log(`[${servers[i].label}] ERRO: ${o.error.message}`);
      audit('coletor', 'collect_server_error', `${servers[i].label}: ${o.error.message}`);
    } else total += o;
  });
  audit('coletor', 'collect_end', `${total} instalacao(oes)`);
  return total;
}

module.exports = { collectAll, collectServer, collectInstallation, buildTarget };
