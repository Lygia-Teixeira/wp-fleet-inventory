'use strict';
// Gera o hash bcrypt para BASIC_AUTH_HASH. Le a senha do stdin (nao do argv,
// que fica no historico do shell e visivel em `ps`).
//   echo -n 'senha-forte' | npm run hash-password
const bcrypt = require('bcryptjs');

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => (input += c));
process.stdin.on('end', () => {
  const password = input.replace(/\r?\n$/, '');
  if (password.length < 12) {
    console.error('senha muito curta (minimo 12 caracteres)');
    process.exitCode = 1;
    return;
  }
  console.log(bcrypt.hashSync(password, 12));
});
