// Answers JSON requests, one per line on stdin, with two reference implementations
// installed by `npm install --prefix tests/upstream forwarded-parse@2.1.2 proxy-addr@2.0.8`:
// forwarded-parse (an RFC 7239 parser) and proxy-addr (the trust walk behind Express).
'use strict';

const path = require('path');
const readline = require('readline');

const modules = path.join(__dirname, 'upstream', 'node_modules');
const parse = require(path.join(modules, 'forwarded-parse'));
const proxyaddr = require(path.join(modules, 'proxy-addr'));

function answer(request) {
  if (request.op === 'parse') {
    return parse(request.header);
  }
  if (request.op === 'trust') {
    return proxyaddr.compile(request.trust)(request.addr, 0);
  }
  if (request.op === 'walk') {
    const req = { headers: { 'x-forwarded-for': request.xff }, socket: { remoteAddress: request.peer } };
    // A number is a hop count, the way Express turns `trust proxy` = n into a function.
    const trust = typeof request.trust === 'number'
      ? function (addr, i) { return i < request.trust; }
      : request.trust;
    return proxyaddr(req, trust);
  }
  throw new Error('unknown op');
}

const lines = [];
readline.createInterface({ input: process.stdin })
  .on('line', function (line) {
    let reply;
    try {
      reply = { ok: answer(JSON.parse(line)) };
    } catch (error) {
      reply = { error: String(error && error.message).slice(0, 80) };
    }
    lines.push(JSON.stringify(reply));
  })
  .on('close', function () {
    process.stdout.write(lines.join('\n') + '\n');
  });
