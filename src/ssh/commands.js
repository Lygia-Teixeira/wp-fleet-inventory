'use strict';
// Catalogo FECHADO de comandos remotos - todos read-only.
//
// SshSession.run() so aceita objetos criados aqui (verificado por um WeakSet
// privado do modulo), entao nenhum outro ponto do codigo consegue mandar uma
// string arbitraria para o servidor. Todo argumento variavel passa por shq().
// Revisar este arquivo == revisar tudo o que o coletor pode fazer na frota.
const { shq } = require('./shellQuote');

const registry = new WeakSet();

function define(name, cmd) {
  const command = Object.freeze({ name, cmd });
  registry.add(command);
  return command;
}

function isCatalogCommand(command) {
  return typeof command === 'object' && command !== null && registry.has(command);
}

const ACCOUNT_RE = /^[a-z_][a-z0-9_-]{0,31}$/i;

function assertAbsolutePath(p) {
  if (typeof p !== 'string' || !p.startsWith('/') || p.split('/').includes('..')) {
    throw new Error(`caminho remoto invalido: ${JSON.stringify(p)}`);
  }
  return p;
}

// Codigo PHP fixo usado no modo profundo: so LE versao e siteurl.
const WP_INFO_PHP =
  'echo json_encode(array("wp_version" => get_bloginfo("version"), "siteurl" => get_option("siteurl")));';

const commands = {
  // cPanel/WHM: lista vhosts com docroot, conta, versao PHP (MultiPHP) e
  // flag de suspensao. Requer privilegio de leitura na WHM API.
  whmVhostVersions: () => define('whm.php_get_vhost_versions', 'whmapi1 --output=json php_get_vhost_versions 2>/dev/null'),

  // Fallback sem WHM: procura wp-config.php, ignorando lixeiras/backups e
  // configs dentro de wp-content (plugins de backup costumam copiar o arquivo).
  findWpConfigs: ({ root = '/home', maxDepth = 4 } = {}) => {
    const depth = Number(maxDepth);
    if (!Number.isInteger(depth) || depth < 1 || depth > 8) throw new Error('maxDepth fora do intervalo 1..8');
    return define(
      'fs.find_wp_configs',
      `find ${shq(assertAbsolutePath(root))} -maxdepth ${depth} -type f -name wp-config.php ` +
        `-not -path '*/wp-content/*' -not -path '*/.trash/*' -not -ipath '*backup*' 2>/dev/null; true`
    );
  },

  hasWpConfig: (docroot) =>
    define('fs.test_wp_config', `test -f ${shq(`${assertAbsolutePath(docroot)}/wp-config.php`)} && echo yes || echo no`),

  // Modo padrao (sem executar PHP): le $wp_version direto de
  // wp-includes/version.php. Nenhum codigo do site e carregado.
  readWpVersionFile: (docroot) =>
    define(
      'fs.read_wp_version',
      `grep -m1 -E ${shq('^\\$wp_version[[:space:]]*=')} ${shq(`${assertAbsolutePath(docroot)}/wp-includes/version.php`)} 2>/dev/null; true`
    ),

  // Binarios PHP do EasyApache (ea-phpXX), um por versao instalada.
  listEaPhpBinaries: () =>
    define('php.list_ea_binaries', 'for b in /opt/cpanel/ea-php*/root/usr/bin/php; do [ -x "$b" ] && echo "$b"; done; true'),

  whichWpCli: () => define('wpcli.which', 'command -v wp 2>/dev/null; true'),

  // Modo profundo (opcional): bootstrap do WordPress via WP-CLI para obter o
  // siteurl do banco. Tres decisoes de seguranca:
  //  1. roda como o DONO da conta (sudo -u), nunca como root - codigo PHP de
  //     terceiros nao deve executar com privilegio do coletor;
  //  2. --skip-plugins --skip-themes: nao carrega codigo de plugin/tema
  //     (eventualmente comprometido) so para ler duas opcoes;
  //  3. invoca o binario ea-phpXX da conta como interpretador do phar do
  //     WP-CLI. O phar tem shebang "#!/usr/bin/env php", entao variaveis como
  //     WP_CLI_PHP nao trocam o interpretador: sem isso o site roda sob o PHP
  //     padrao do sistema e instalacoes antigas quebram com erro fatal.
  wpEvalInfo: ({ docroot, account, wpCliPath, phpBinary = null }) => {
    if (!ACCOUNT_RE.test(String(account))) throw new Error('conta invalida para sudo -u');
    const php = phpBinary ? `${shq(assertAbsolutePath(phpBinary))} ` : '';
    return define(
      'wpcli.eval_info',
      `sudo -n -u ${shq(account)} -- ${php}${shq(assertAbsolutePath(wpCliPath))} ` +
        `--path=${shq(assertAbsolutePath(docroot))} --skip-plugins --skip-themes --no-color eval ${shq(WP_INFO_PHP)}`
    );
  },
};

module.exports = { commands, isCatalogCommand, ACCOUNT_RE };
