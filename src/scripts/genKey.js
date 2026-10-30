'use strict';
// Gera 32 bytes aleatorios em base64 - serve para SECRETS_KEY e API_TOKEN.
const { generateKey } = require('../crypto/secretBox');

console.log(generateKey());
