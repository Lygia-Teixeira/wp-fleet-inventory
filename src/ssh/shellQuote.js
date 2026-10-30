'use strict';
// Quoting POSIX para argumentos embutidos em comandos remotos.
//
// Caminhos de docroot e nomes de conta vem do PROPRIO servidor remoto (saida
// da WHM API ou do `find`). Um diretorio chamado `x$(curl ...|sh)` ou com
// aspas/backticks executaria codigo se fosse concatenado cru na string do
// comando. Aspas simples sao a unica forma de quoting em sh que nao
// interpreta NENHUM metacaractere; a unica coisa a tratar e a propria aspa
// simples: fecha, emite \' e reabre ('\'').
function shq(value) {
  if (value === null || value === undefined) {
    throw new TypeError('shq: valor nulo/indefinido nao pode virar argumento de shell');
  }
  const s = String(value);
  // NUL nao pode existir em argv; se apareceu, o dado e invalido/malicioso.
  if (s.includes('\0')) throw new Error('shq: argumento contem byte NUL');
  return `'${s.replace(/'/g, "'\\''")}'`;
}

module.exports = { shq };
