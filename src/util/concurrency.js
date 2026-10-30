'use strict';
// Primitivas de controle de carga: semaforo, pool limitado, timeout e retry
// com backoff exponencial + jitter.

class Semaphore {
  constructor(limit) {
    if (!Number.isInteger(limit) || limit < 1) throw new Error('limite do semaforo invalido');
    this.limit = limit;
    this.active = 0;
    this.queue = [];
  }

  async acquire() {
    if (this.active < this.limit) {
      this.active++;
      return;
    }
    await new Promise((resolve) => this.queue.push(resolve));
    // a vaga foi transferida por release(); active ja contabiliza este waiter
  }

  release() {
    const next = this.queue.shift();
    if (next) next();
    else this.active--;
  }

  async use(fn) {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }
}

// Executa fn sobre items com no maximo `limit` em paralelo, preservando a
// ordem dos resultados. Erros individuais viram { error } em vez de abortar
// o lote inteiro (um site quebrado nao pode derrubar o inventario do servidor).
async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      try {
        results[i] = await fn(items[i], i);
      } catch (error) {
        results[i] = { error };
      }
    }
  }
  const workers = Array.from({ length: Math.min(limit, items.length) }, worker);
  await Promise.all(workers);
  return results;
}

function withTimeout(promise, ms, message = `timeout apos ${ms}ms`) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function backoffDelay(attempt, { baseDelayMs = 1000, maxDelayMs = 15000, random = Math.random } = {}) {
  const exp = Math.min(maxDelayMs, baseDelayMs * 2 ** attempt);
  // "full jitter": espalha as tentativas para nao bater no servidor em rajada
  return Math.round(exp / 2 + random() * (exp / 2));
}

async function retry(fn, { retries = 2, shouldRetry = () => true, onRetry = () => {}, ...delayOpts } = {}) {
  let attempt = 0;
  for (;;) {
    try {
      return await fn(attempt);
    } catch (err) {
      if (attempt >= retries || !shouldRetry(err)) throw err;
      const delay = backoffDelay(attempt, delayOpts);
      onRetry(err, attempt + 1, delay);
      await sleep(delay);
      attempt++;
    }
  }
}

module.exports = { Semaphore, mapWithConcurrency, withTimeout, retry, backoffDelay, sleep };
