'use strict';
// Verificacao de host key no formato OpenSSH known_hosts.
//
// Aceitar qualquer host key (o padrao de muitos scripts com ssh2) abre espaco
// para MITM: quem interceptar a rota recebe a senha/assinatura e um shell
// privilegiado na frota inteira. Aqui a conexao so prossegue se a chave
// apresentada pelo servidor for exatamente uma das registradas para aquele
// host:porta. Suporta:
//   - hosts em texto ("host", "[host]:2222", lista separada por virgula)
//   - hosts hasheados (HashKnownHosts yes: "|1|salt|hmac")
//   - curingas simples (* e ?) e negacao (!padrao)
//   - marcador @revoked (rejeita); @cert-authority e ignorado (nao suportado)
const crypto = require('node:crypto');
const fs = require('node:fs');

function hostToken(host, port = 22) {
  return Number(port) === 22 ? host : `[${host}]:${port}`;
}

function globToRegex(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`, 'i');
}

function hashedMatch(field, token) {
  // |1|<salt base64>|<hmac-sha1(salt, host) base64>
  const parts = field.split('|');
  if (parts.length !== 4 || parts[1] !== '1') return false;
  const salt = Buffer.from(parts[2], 'base64');
  const expected = Buffer.from(parts[3], 'base64');
  const actual = crypto.createHmac('sha1', salt).update(token).digest();
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function hostFieldMatches(field, token) {
  if (field.startsWith('|1|')) return hashedMatch(field, token);
  let matched = false;
  for (const pattern of field.split(',')) {
    if (pattern.startsWith('!')) {
      if (globToRegex(pattern.slice(1)).test(token)) return false;
    } else if (globToRegex(pattern).test(token)) {
      matched = true;
    }
  }
  return matched;
}

function parseKnownHosts(text) {
  const entries = [];
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const fields = line.split(/\s+/);
    let marker = null;
    if (fields[0].startsWith('@')) marker = fields.shift();
    if (fields.length < 3) continue;
    const [hosts, keyType, keyB64] = fields;
    entries.push({ marker, hosts, keyType, key: Buffer.from(keyB64, 'base64') });
  }
  return entries;
}

// Retorna { ok, reason }. keyBlob e a chave publica crua (formato wire SSH),
// exatamente o que o ssh2 entrega ao hostVerifier e o que o known_hosts
// guarda em base64.
function verifyHostKey(entries, host, port, keyBlob) {
  const token = hostToken(host, port);
  const candidates = entries.filter((e) => e.marker !== '@cert-authority' && hostFieldMatches(e.hosts, token));
  const sameKey = (e) => e.key.length === keyBlob.length && crypto.timingSafeEqual(e.key, keyBlob);

  if (candidates.some((e) => e.marker === '@revoked' && sameKey(e))) {
    return { ok: false, reason: `host key de ${token} esta marcada como @revoked` };
  }
  const trusted = candidates.filter((e) => e.marker !== '@revoked');
  if (trusted.length === 0) {
    return { ok: false, reason: `${token} nao consta no known_hosts (registre e confirme o fingerprint antes)` };
  }
  if (trusted.some(sameKey)) return { ok: true, reason: null };
  return { ok: false, reason: `HOST KEY DIVERGENTE para ${token} - possivel MITM ou servidor reinstalado` };
}

function fingerprintSha256(keyBlob) {
  return 'SHA256:' + crypto.createHash('sha256').update(keyBlob).digest('base64').replace(/=+$/, '');
}

function loadKnownHosts(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`known_hosts nao encontrado em ${filePath} - sem ele nenhuma conexao e aceita`);
  }
  return parseKnownHosts(fs.readFileSync(filePath, 'utf8'));
}

module.exports = { parseKnownHosts, verifyHostKey, loadKnownHosts, hostToken, fingerprintSha256 };
