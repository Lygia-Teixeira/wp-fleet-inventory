'use strict';
// Parsers puros (sem I/O) das saidas remotas. Toda saida remota e tratada
// como dado nao confiavel: validada por regex/JSON.parse, nunca avaliada.

const WP_VERSION_RE = /^\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?$/;

// "ea-php82" -> "8.2", "ea-php74" -> "7.4"; qualquer outra coisa -> null
function normalizeEaPhp(value) {
  const m = /ea-php(\d)(\d{1,2})\b/.exec(String(value ?? ''));
  return m ? `${m[1]}.${Number(m[2])}` : null;
}

// Linhas "/opt/cpanel/ea-php82/root/usr/bin/php" -> { "8.2": caminho }
function parsePhpBinaryList(stdout) {
  const map = {};
  for (const line of String(stdout).split('\n')) {
    const path = line.trim();
    if (!/^\/opt\/cpanel\/ea-php\d{2,3}\/root\/usr\/bin\/php$/.test(path)) continue;
    const version = normalizeEaPhp(path);
    if (version) map[version] = path;
  }
  return map;
}

function isValidWpVersion(v) {
  return typeof v === 'string' && WP_VERSION_RE.test(v);
}

// "$wp_version = '6.6.2';" -> "6.6.2"
function parseWpVersionLine(stdout) {
  const m = /\$wp_version\s*=\s*['"]([^'"]{1,32})['"]\s*;/.exec(String(stdout));
  return m && isValidWpVersion(m[1]) ? m[1] : null;
}

// Saida do `wp eval`: PHP antigo costuma imprimir Notices/Deprecated antes do
// JSON. Pega a ULTIMA linha que seja um objeto JSON valido.
function parseWpEvalOutput(stdout) {
  const lines = String(stdout).split('\n').map((l) => l.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    if (!lines[i].startsWith('{')) continue;
    try {
      const obj = JSON.parse(lines[i]);
      return {
        wpVersion: isValidWpVersion(obj.wp_version) ? obj.wp_version : null,
        siteUrl: typeof obj.siteurl === 'string' && /^https?:\/\//i.test(obj.siteurl) ? obj.siteurl : null,
      };
    } catch {
      /* linha com cara de JSON mas invalida: tenta a anterior */
    }
  }
  return { wpVersion: null, siteUrl: null };
}

function domainFromUrl(url) {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return null;
  }
}

// /home/<conta>/... -> <conta>
function accountFromDocroot(docroot) {
  const m = /^\/home\d*\/([a-z_][a-z0-9_-]{0,31})\//i.exec(String(docroot) + '/');
  return m ? m[1] : null;
}

// JSON da WHM API php_get_vhost_versions -> lista normalizada
function parseWhmVhosts(stdout) {
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return [];
  }
  const versions = parsed?.data?.versions;
  if (!Array.isArray(versions)) return [];
  return versions
    .filter((v) => typeof v.documentroot === 'string' && v.documentroot.startsWith('/') && typeof v.vhost === 'string')
    .map((v) => ({
      docroot: v.documentroot.replace(/\/+$/, ''),
      domain: v.vhost.toLowerCase(),
      account: typeof v.account === 'string' ? v.account : accountFromDocroot(v.documentroot),
      phpVersion: normalizeEaPhp(v.version),
      suspended: v.is_suspended === 1 || v.is_suspended === '1',
    }));
}

// Saida do find (um wp-config.php por linha) -> docroots unicos
function parseFindOutput(stdout) {
  const seen = new Set();
  for (const line of String(stdout).split('\n')) {
    const p = line.trim();
    if (!p.startsWith('/') || !p.endsWith('/wp-config.php')) continue;
    seen.add(p.slice(0, -'/wp-config.php'.length));
  }
  return [...seen].sort();
}

// Comparacao semver simplificada (para destacar versoes desatualizadas)
function compareVersions(a, b) {
  const pa = String(a).split(/[.-]/).map((n) => Number.parseInt(n, 10) || 0);
  const pb = String(b).split(/[.-]/).map((n) => Number.parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return Math.sign(d);
  }
  return 0;
}

module.exports = {
  normalizeEaPhp,
  parsePhpBinaryList,
  isValidWpVersion,
  parseWpVersionLine,
  parseWpEvalOutput,
  domainFromUrl,
  accountFromDocroot,
  parseWhmVhosts,
  parseFindOutput,
  compareVersions,
};
