'use strict';
// Coletor contra uma sessao SSH falsa (sem rede): valida o fallback
// WHM -> find e a escolha do binario ea-phpXX no modo profundo.
const test = require('node:test');
const assert = require('node:assert/strict');
const { discoverInstallations } = require('../src/collector/discovery');
const { collectInstallation } = require('../src/collector/collector');
const { isCatalogCommand } = require('../src/ssh/commands');

function fakeSession(handlers) {
  const seen = [];
  return {
    seen,
    async run(command) {
      assert.ok(isCatalogCommand(command), 'coletor so deve enviar comandos do catalogo');
      seen.push(command);
      const h = handlers[command.name];
      if (!h) throw new Error(`comando inesperado: ${command.name}`);
      return typeof h === 'function' ? h(command) : h;
    },
  };
}

test('sem WHM, cai para o find', async () => {
  const s = fakeSession({
    'whm.php_get_vhost_versions': { code: 127, stdout: '', stderr: 'whmapi1: not found' },
    'fs.find_wp_configs': { code: 0, stdout: '/home/conta01/public_html/wp-config.php\n', stderr: '' },
  });
  const found = await discoverInstallations(s);
  assert.deepEqual(found, [
    { docroot: '/home/conta01/public_html', domain: null, account: 'conta01', phpVersion: null, suspended: false, method: 'find' },
  ]);
});

test('com WHM, confirma wp-config.php por vhost', async () => {
  const whm = JSON.stringify({
    data: {
      versions: [
        { vhost: 'site1.example.com', documentroot: '/home/conta01/public_html', account: 'conta01', version: 'ea-php74', is_suspended: 0 },
        { vhost: 'estatico.example.com', documentroot: '/home/conta02/public_html', account: 'conta02', version: 'ea-php82', is_suspended: 0 },
      ],
    },
  });
  const s = fakeSession({
    'whm.php_get_vhost_versions': { code: 0, stdout: whm, stderr: '' },
    'fs.test_wp_config': (c) => ({ code: 0, stdout: c.cmd.includes('conta01') ? 'yes\n' : 'no\n', stderr: '' }),
  });
  const found = await discoverInstallations(s);
  assert.equal(found.length, 1);
  assert.equal(found[0].domain, 'site1.example.com');
  assert.equal(found[0].phpVersion, '7.4');
});

test('modo profundo usa o ea-php da conta como interpretador do wp-cli', async () => {
  const s = fakeSession({
    'fs.read_wp_version': { code: 0, stdout: "$wp_version = '5.9.10';\n", stderr: '' },
    'wpcli.eval_info': { code: 0, stdout: 'Deprecated: ...\n{"wp_version":"5.9.10","siteurl":"https://site1.example.com"}\n', stderr: '' },
  });
  const inst = { docroot: '/home/conta01/public_html', domain: null, account: 'conta01', phpVersion: '7.4', suspended: false, method: 'whm' };
  const ctx = {
    deep: true,
    wpCliPath: '/usr/local/bin/wp',
    phpBinaries: { '7.4': '/opt/cpanel/ea-php74/root/usr/bin/php', '8.2': '/opt/cpanel/ea-php82/root/usr/bin/php' },
  };
  const row = await collectInstallation(s, inst, ctx);
  assert.equal(row.status, 'ok');
  assert.equal(row.domain, 'site1.example.com');
  const evalCmd = s.seen.find((c) => c.name === 'wpcli.eval_info').cmd;
  assert.match(evalCmd, /ea-php74/);
  assert.doesNotMatch(evalCmd, /ea-php82/);
});

test('modo padrao nao executa PHP', async () => {
  const s = fakeSession({ 'fs.read_wp_version': { code: 0, stdout: "$wp_version = '6.6.2';", stderr: '' } });
  const inst = { docroot: '/home/conta01/public_html', domain: 'site1.example.com', account: 'conta01', phpVersion: '8.2', suspended: false, method: 'whm' };
  const row = await collectInstallation(s, inst, { deep: false, phpBinaries: {}, wpCliPath: null });
  assert.equal(row.wp_version, '6.6.2');
  assert.deepEqual(s.seen.map((c) => c.name), ['fs.read_wp_version']);
});
