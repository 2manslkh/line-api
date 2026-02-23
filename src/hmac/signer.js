#!/usr/bin/env node
/**
 * LINE HMAC Signer — Node.js service for computing X-Hmac headers.
 * 
 * Modes:
 *   1. CLI:    node signer.js sign <accessToken> <path> [body]
 *   2. Server: node signer.js serve [port]  (HTTP JSON API on localhost)
 * 
 * The WASM module is loaded once and reused for all requests.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');

// Static token from the public Chrome extension (not a personal secret).
// This is embedded in the published extension and used by all Chrome extension users.
// Origin: chrome-extension://ophjlpahpchlmihnnnihgmmeilfjmjjc
const CHROME_TOKEN = "wODdrvWqmdP4Zliay-iF3cz3KZcK0ekrial868apg06TXeCo7A1hIQO0ESElHg6D";
const VERSION = "3.7.1";

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

let _module = null;
let _secureKey = null;

async function loadModule() {
  if (_module) return _module;

  const wasmPath = path.join(__dirname, '..', '..', 'lstm.wasm');
  const wasmBinary = fs.readFileSync(wasmPath);
  const sandboxPath = path.join(__dirname, '..', '..', 'lstmSandbox.js');
  const sandbox = fs.readFileSync(sandboxPath, 'utf-8');

  // Extract Emscripten module 75511
  const mStart = sandbox.indexOf('75511:(e,t,r)=>{');
  const bStart = sandbox.indexOf('{', mStart);
  let depth = 0, end = bStart;
  for (let i = bStart; i < sandbox.length; i++) {
    if (sandbox[i] === '{') depth++;
    else if (sandbox[i] === '}') depth--;
    if (depth === 0) { end = i + 1; break; }
  }

  // Extract module 1426 (process polyfill)
  const m1426Start = sandbox.indexOf('1426:e=>{');
  const b1426Start = sandbox.indexOf('{', m1426Start + 7);
  depth = 0;
  let end1426 = b1426Start;
  for (let i = b1426Start; i < sandbox.length; i++) {
    if (sandbox[i] === '{') depth++;
    else if (sandbox[i] === '}') depth--;
    if (depth === 0) { end1426 = i + 1; break; }
  }

  // Setup globals
  const origin = 'chrome-extension://ophjlpahpchlmihnnnihgmmeilfjmjjc';
  globalThis.window = globalThis;
  globalThis.window.crypto = {
    getRandomValues: (arr) => { crypto.randomFillSync(arr); return arr; },
    subtle: crypto.webcrypto?.subtle,
  };
  globalThis.window.origin = origin;
  globalThis.window.location = { origin, href: origin };
  globalThis.self = globalThis;
  if (!globalThis.document) globalThis.document = { currentScript: { src: '' } };

  const mod1426 = { exports: {} };
  new Function('e', sandbox.slice(b1426Start, end1426))(mod1426);

  const r = (id) => id === 1426 ? mod1426.exports : {};
  const modObj = { exports: {} };
  new Function('e', 't', 'r', sandbox.slice(bStart, end))(modObj, modObj.exports, r);

  _module = await modObj.exports({ wasmBinary });
  return _module;
}

async function getSecureKey() {
  if (_secureKey) return _secureKey;
  const mod = await loadModule();
  _secureKey = mod.SecureKey.loadToken(CHROME_TOKEN);
  return _secureKey;
}

async function computeHmac(accessToken, reqPath, body = '') {
  const mod = await loadModule();
  const secureKey = await getSecureKey();

  const versionHash = new Uint8Array(sha256(VERSION));
  const tokenHash = new Uint8Array(sha256(accessToken));
  const derivedKey = secureKey.deriveKey(versionHash, tokenHash);

  const hmacObj = new mod.Hmac(derivedKey);
  const message = new TextEncoder().encode(reqPath + body);
  const digest = hmacObj.digest(message);

  return Buffer.from(new Uint8Array(digest.buffer || digest)).toString('base64');
}

// ── CLI Mode ──
async function cli() {
  const [,, cmd, ...args] = process.argv;

  if (cmd === 'sign') {
    const [accessToken = '', reqPath, body] = args;
    if (reqPath === undefined) {
      console.error('Usage: node signer.js sign <accessToken> <path> [body]');
      process.exit(1);
    }
    const hmac = await computeHmac(accessToken, reqPath, body || '');
    // Output just the HMAC value for easy piping
    process.stdout.write(hmac);
  } else if (cmd === 'serve') {
    await startServer(parseInt(args[0]) || 18944);
  } else {
    console.error('Usage: node signer.js <sign|serve> ...');
    process.exit(1);
  }
}

// ── Server Mode ──
async function startServer(port) {
  // Pre-load the module
  await loadModule();
  await getSecureKey();
  console.error(`HMAC signer ready, loading took ${process.uptime().toFixed(1)}s`);

  const server = http.createServer(async (req, res) => {
    if (req.method !== 'POST' || req.url !== '/sign') {
      res.writeHead(404);
      res.end('Not found');
      return;
    }

    let body = '';
    for await (const chunk of req) body += chunk;

    try {
      const { accessToken, path: reqPath, body: reqBody } = JSON.parse(body);
      const hmac = await computeHmac(accessToken, reqPath, reqBody || '');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ hmac }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
  });

  server.listen(port, '127.0.0.1', () => {
    console.error(`HMAC signer listening on http://127.0.0.1:${port}/sign`);
  });
}

cli().catch(e => { console.error(e); process.exit(1); });
