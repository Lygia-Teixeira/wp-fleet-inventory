'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { mapWithConcurrency, Semaphore, retry, backoffDelay, withTimeout, sleep } = require('../src/util/concurrency');
const { toCsv, neutralizeFormula } = require('../src/export');

test('mapWithConcurrency nunca passa do limite e preserva a ordem', async () => {
  let active = 0;
  let peak = 0;
  const out = await mapWithConcurrency([1, 2, 3, 4, 5, 6, 7], 3, async (n) => {
    active++;
    peak = Math.max(peak, active);
    await sleep(5);
    active--;
    if (n === 4) throw new Error('falhou');
    return n * 2;
  });
  assert.ok(peak <= 3);
  assert.equal(out[0], 2);
  assert.equal(out[6], 14);
  assert.match(out[3].error.message, /falhou/);
});

test('Semaphore limita uso simultaneo', async () => {
  const sem = new Semaphore(2);
  let active = 0;
  let peak = 0;
  await Promise.all(
    Array.from({ length: 6 }, () =>
      sem.use(async () => {
        active++;
        peak = Math.max(peak, active);
        await sleep(3);
        active--;
      })
    )
  );
  assert.equal(peak, 2);
});

test('retry respeita shouldRetry e numero de tentativas', async () => {
  let calls = 0;
  await assert.rejects(
    retry(async () => {
      calls++;
      throw Object.assign(new Error('auth'), { level: 'client-authentication' });
    }, { retries: 3, baseDelayMs: 1, shouldRetry: (e) => e.level !== 'client-authentication' })
  );
  assert.equal(calls, 1, 'falha de autenticacao nao deve ser repetida');

  calls = 0;
  const v = await retry(async () => {
    if (++calls < 3) throw new Error('rede');
    return 'ok';
  }, { retries: 3, baseDelayMs: 1 });
  assert.equal(v, 'ok');
  assert.equal(calls, 3);
});

test('backoffDelay cresce e respeita o teto', () => {
  const r = () => 1;
  assert.equal(backoffDelay(0, { baseDelayMs: 100, random: r }), 100);
  assert.equal(backoffDelay(2, { baseDelayMs: 100, random: r }), 400);
  assert.equal(backoffDelay(10, { baseDelayMs: 100, maxDelayMs: 1000, random: r }), 1000);
});

test('withTimeout rejeita promessas lentas', async () => {
  await assert.rejects(withTimeout(sleep(50), 5), /timeout/);
});

test('CSV neutraliza formula injection e escapa aspas', () => {
  assert.equal(neutralizeFormula('=HYPERLINK("x")'), '\'=HYPERLINK("x")');
  const csv = toCsv([{ domain: '=1+1', docroot: '/home/a,"b"' }], ['domain', 'docroot']);
  assert.equal(csv, 'domain,docroot\r\n\'=1+1,"/home/a,""b"""\r\n');
});
