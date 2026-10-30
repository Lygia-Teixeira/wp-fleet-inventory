'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const p = require('../src/collector/parsers');

test('normalizeEaPhp', () => {
  assert.equal(p.normalizeEaPhp('ea-php82'), '8.2');
  assert.equal(p.normalizeEaPhp('ea-php74'), '7.4');
  assert.equal(p.normalizeEaPhp('ea-php56'), '5.6');
  assert.equal(p.normalizeEaPhp('alt-php81'), null);
  assert.equal(p.normalizeEaPhp(null), null);
});

test('parsePhpBinaryList mapeia versao -> binario e ignora lixo', () => {
  const out = [
    '/opt/cpanel/ea-php74/root/usr/bin/php',
    '/opt/cpanel/ea-php82/root/usr/bin/php',
    '/tmp/ea-php99/root/usr/bin/php',
    'garbage',
  ].join('\n');
  assert.deepEqual(p.parsePhpBinaryList(out), {
    '7.4': '/opt/cpanel/ea-php74/root/usr/bin/php',
    '8.2': '/opt/cpanel/ea-php82/root/usr/bin/php',
  });
});

test('parseWpVersionLine le version.php', () => {
  assert.equal(p.parseWpVersionLine("$wp_version = '6.6.2';"), '6.6.2');
  assert.equal(p.parseWpVersionLine('$wp_version = "5.9";'), '5.9');
  assert.equal(p.parseWpVersionLine("$wp_version = '6.7-beta1-58000';"), '6.7-beta1-58000');
  assert.equal(p.parseWpVersionLine("$wp_version = '<script>';"), null);
  assert.equal(p.parseWpVersionLine(''), null);
});

test('parseWpEvalOutput tolera Notices antes do JSON', () => {
  const out = [
    'PHP Deprecated:  Function create_function() is deprecated in /home/x/... on line 3',
    'Notice: Undefined index: foo',
    '{"wp_version":"6.4.3","siteurl":"https://site1.example.com"}',
  ].join('\n');
  assert.deepEqual(p.parseWpEvalOutput(out), { wpVersion: '6.4.3', siteUrl: 'https://site1.example.com' });
});

test('parseWpEvalOutput rejeita valores fora do formato', () => {
  const out = '{"wp_version":"$(id)","siteurl":"javascript:alert(1)"}';
  assert.deepEqual(p.parseWpEvalOutput(out), { wpVersion: null, siteUrl: null });
  assert.deepEqual(p.parseWpEvalOutput('nada aqui'), { wpVersion: null, siteUrl: null });
});

test('accountFromDocroot e domainFromUrl', () => {
  assert.equal(p.accountFromDocroot('/home/conta01/public_html'), 'conta01');
  assert.equal(p.accountFromDocroot('/home2/conta02/public_html/blog'), 'conta02');
  assert.equal(p.accountFromDocroot('/var/www/html'), null);
  assert.equal(p.domainFromUrl('https://Site1.Example.com/'), 'site1.example.com');
  assert.equal(p.domainFromUrl('nao-e-url'), null);
});

test('parseWhmVhosts normaliza a resposta da WHM API', () => {
  const json = JSON.stringify({
    data: {
      versions: [
        { vhost: 'site1.example.com', documentroot: '/home/conta01/public_html', account: 'conta01', version: 'ea-php74', is_suspended: 0 },
        { vhost: 'site2.example.com', documentroot: '/home/conta02/public_html/', account: 'conta02', version: 'ea-php82', is_suspended: 1 },
        { vhost: 'sem-docroot.example.com' },
      ],
    },
  });
  assert.deepEqual(p.parseWhmVhosts(json), [
    { docroot: '/home/conta01/public_html', domain: 'site1.example.com', account: 'conta01', phpVersion: '7.4', suspended: false },
    { docroot: '/home/conta02/public_html', domain: 'site2.example.com', account: 'conta02', phpVersion: '8.2', suspended: true },
  ]);
  assert.deepEqual(p.parseWhmVhosts('nao json'), []);
});

test('parseFindOutput deduplica e ignora linhas invalidas', () => {
  const out = '/home/a/public_html/wp-config.php\n/home/a/public_html/wp-config.php\n/home/b/public_html/blog/wp-config.php\nfind: permission denied\n';
  assert.deepEqual(p.parseFindOutput(out), ['/home/a/public_html', '/home/b/public_html/blog']);
});

test('compareVersions', () => {
  assert.equal(p.compareVersions('6.6.2', '6.5'), 1);
  assert.equal(p.compareVersions('5.9', '5.9.0'), 0);
  assert.equal(p.compareVersions('4.9.26', '6.0'), -1);
});
