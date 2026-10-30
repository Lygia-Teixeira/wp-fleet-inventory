'use strict';
// Uma conexao SSH por servidor, N canais multiplexados sobre ela.
//
// Abrir uma conexao TCP nova por comando gera dezenas de handshakes/logins
// em segundos - exatamente o padrao que firewalls como CSF/lfd e fail2ban
// interpretam como forca bruta, banindo o IP do coletor. Aqui ha UM login por
// servidor; os comandos rodam como canais (exec) sobre a mesma sessao,
// limitados por um semaforo abaixo do MaxSessions do sshd (padrao 10).
const { Client } = require('ssh2');
const { isCatalogCommand } = require('./commands');
const { verifyHostKey, fingerprintSha256 } = require('./knownHosts');
const { Semaphore } = require('../util/concurrency');

const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;

class HostKeyError extends Error {}

class SshSession {
  /**
   * @param {object} target  { label, host, port, username, password?, privateKey? }
   * @param {object} opts    { knownHosts (entries), maxChannels, connectTimeoutMs, commandTimeoutMs }
   */
  constructor(target, { knownHosts, maxChannels = 4, connectTimeoutMs = 15000, commandTimeoutMs = 30000 } = {}) {
    if (!Array.isArray(knownHosts)) throw new Error('known_hosts obrigatorio - nao ha modo "aceitar qualquer chave"');
    this.target = target;
    this.knownHosts = knownHosts;
    this.connectTimeoutMs = connectTimeoutMs;
    this.commandTimeoutMs = commandTimeoutMs;
    this.channels = new Semaphore(maxChannels);
    this.client = null;
    this.hostKeyFingerprint = null;
  }

  connect() {
    const { host, port = 22, username, password, privateKey } = this.target;
    return new Promise((resolve, reject) => {
      const client = new Client();
      let hostKeyFailure = null;
      const timer = setTimeout(() => {
        client.destroy();
        reject(new Error(`timeout de conexao (${this.connectTimeoutMs}ms)`));
      }, this.connectTimeoutMs);

      client
        .on('ready', () => {
          clearTimeout(timer);
          this.client = client;
          resolve(this);
        })
        .on('error', (err) => {
          clearTimeout(timer);
          reject(hostKeyFailure ? new HostKeyError(hostKeyFailure) : err);
        })
        .connect({
          host,
          port,
          username,
          password,
          privateKey,
          readyTimeout: this.connectTimeoutMs,
          // Sem agent forwarding nem keyboard-interactive: superficie minima.
          agentForward: false,
          tryKeyboard: false,
          hostVerifier: (keyBlob) => {
            this.hostKeyFingerprint = fingerprintSha256(keyBlob);
            const { ok, reason } = verifyHostKey(this.knownHosts, host, port, keyBlob);
            if (!ok) hostKeyFailure = `${reason} (apresentada: ${this.hostKeyFingerprint})`;
            return ok;
          },
        });
    });
  }

  /** Executa um comando do catalogo read-only. Respeita o limite de canais. */
  run(command, { timeoutMs = this.commandTimeoutMs } = {}) {
    if (!isCatalogCommand(command)) {
      return Promise.reject(new Error('comando recusado: so comandos do catalogo read-only podem ser executados'));
    }
    if (!this.client) return Promise.reject(new Error('sessao SSH nao conectada'));
    return this.channels.use(() => this.#exec(command, timeoutMs));
  }

  #exec(command, timeoutMs) {
    return new Promise((resolve, reject) => {
      let stream = null;
      let settled = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        fn(value);
      };
      const timer = setTimeout(() => {
        if (stream) stream.close(); // libera o canal no servidor
        finish(reject, new Error(`timeout de ${timeoutMs}ms em ${command.name}`));
      }, timeoutMs);

      this.client.exec(command.cmd, (err, ch) => {
        if (err) return finish(reject, err);
        stream = ch;
        let stdout = '';
        let stderr = '';
        let bytes = 0;
        const guard = (chunk) => {
          bytes += chunk.length;
          if (bytes > MAX_OUTPUT_BYTES) {
            ch.close();
            finish(reject, new Error(`saida acima de ${MAX_OUTPUT_BYTES} bytes em ${command.name}`));
            return false;
          }
          return true;
        };
        ch.on('data', (d) => guard(d) && (stdout += d.toString('utf8')));
        ch.stderr.on('data', (d) => guard(d) && (stderr += d.toString('utf8')));
        // erro no CANAL (nao na conexao) precisa de listener, senao vira
        // excecao nao tratada e a promise fica pendurada ate o timeout.
        ch.on('error', (e) => finish(reject, e));
        ch.on('close', (code) => finish(resolve, { stdout, stderr, code }));
      });
    });
  }

  close() {
    if (this.client) this.client.end();
    this.client = null;
  }
}

function isRetryableConnectError(err) {
  if (err instanceof HostKeyError) return false; // nunca "tentar de novo" um MITM
  // Falha de autenticacao repetida e o que dispara ban no lfd/fail2ban.
  if (err && err.level === 'client-authentication') return false;
  return true;
}

module.exports = { SshSession, HostKeyError, isRetryableConnectError };
