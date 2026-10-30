'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { shq } = require('../src/ssh/shellQuote');
const { commands, isCatalogCommand } = require('../src/ssh/commands');

test('shq envolve em aspas simples', () => {
  assert.equal(shq('/home/conta/public_html'), "'/home/conta/public_html'");
});

test('shq escapa aspas simples internas', () => {
  assert.equal(shq("it's"), "'it'\\''s'");
});

test('shq neutraliza metacaracteres de shell', () => {
  for (const evil of ['$(id)', '`id`', 'a;rm -rf /', 'a && b', 'x|y', '"$HOME"', 'a\nb']) {
    const q = shq(evil);
    assert.ok(q.startsWith("'") && q.endsWith("'"));
  }
});

test('shq recusa nulo e byte NUL', () => {
  assert.throws(() => shq(null));
  assert.throws(() => shq(undefined));
  assert.throws(() => shq('a\0b'));
});

test('shq: round-trip real em /bin/sh quando disponivel', (t) => {
  const payloads = ["x'$(echo PWNED)'", '`echo PWNED`', "a'b\"c$d\\e", ' espacos  e\ttab '];
  try {
    execFileSync('sh', ['-c', 'true']);
  } catch {
    t.skip('sh indisponivel neste sistema');
    return;
  }
  for (const p of payloads) {
    const out = execFileSync('sh', ['-c', `printf '%s' ${shq(p)}`]).toString();
    assert.equal(out, p);
  }
});

test('catalogo: comandos aceitos so quando criados pelo catalogo', () => {
  assert.equal(isCatalogCommand(commands.whichWpCli()), true);
  assert.equal(isCatalogCommand({ name: 'fake', cmd: 'rm -rf /' }), false);
  assert.equal(isCatalogCommand('id'), false);
  const c = commands.hasWpConfig('/home/a/public_html');
  assert.throws(() => {
    'use strict';
    c.cmd = 'id';
  });
});

test('catalogo: docroot malicioso vira argumento literal', () => {
  const c = commands.readWpVersionFile("/home/x/$(touch /tmp/p)'`id`");
  assert.ok(c.cmd.includes("'/home/x/$(touch /tmp/p)'\\''`id`/wp-includes/version.php'"));
});

test('catalogo: valida caminho, profundidade e conta', () => {
  assert.throws(() => commands.hasWpConfig('relativo/x'));
  assert.throws(() => commands.hasWpConfig('/home/../etc'));
  assert.throws(() => commands.findWpConfigs({ maxDepth: 99 }));
  assert.throws(() => commands.wpEvalInfo({ docroot: '/home/a', account: 'a;id', wpCliPath: '/usr/local/bin/wp' }));
  const ok = commands.wpEvalInfo({
    docroot: '/home/conta1/public_html',
    account: 'conta1',
    wpCliPath: '/usr/local/bin/wp',
    phpBinary: '/opt/cpanel/ea-php74/root/usr/bin/php',
  });
  assert.match(ok.cmd, /^sudo -n -u 'conta1' -- '\/opt\/cpanel\/ea-php74\/root\/usr\/bin\/php' '\/usr\/local\/bin\/wp'/);
  assert.match(ok.cmd, /--skip-plugins --skip-themes/);
  assert.doesNotMatch(ok.cmd, /--allow-root/);
});
