/**
 * Test LINE HMAC v2 — run the WASM using extracted Emscripten module with proper deps.
 */

const fs = require('fs');
const pathMod = require('path');
const crypto = require('crypto');

const CHROME_TOKEN = "YOUR_CHROME_TOKEN_HERE";
const VERSION = "3.7.1";

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

async function main() {
  const accessToken = process.argv[2] || 'test';
  const reqPath = process.argv[3] || '/test';
  const reqBody = process.argv[4] || '';
  const expectedHmac = process.argv[5];

  const wasmPath = pathMod.join(__dirname, '..', 'lstm.wasm');
  const wasmBinary = fs.readFileSync(wasmPath);
  const sandboxPath = pathMod.join(__dirname, '..', 'lstmSandbox.js');
  const sandbox = fs.readFileSync(sandboxPath, 'utf-8');

  // Extract module 75511 (Emscripten factory) 
  const mStart = sandbox.indexOf('75511:(e,t,r)=>{');
  const bStart = sandbox.indexOf('{', mStart);
  let depth = 0, end = bStart;
  for (let i = bStart; i < sandbox.length; i++) {
    if (sandbox[i] === '{') depth++;
    else if (sandbox[i] === '}') depth--;
    if (depth === 0) { end = i + 1; break; }
  }

  // Also extract module 1426 (process polyfill)
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
  if (!globalThis.document) {
    globalThis.document = { currentScript: { src: '' } };
  }

  // Build module 1426
  const mod1426 = { exports: {} };
  const fn1426 = new Function('e', sandbox.slice(b1426Start, end1426));
  fn1426(mod1426);

  // Build the require function for the Emscripten module
  const requireMap = {
    1426: mod1426.exports,
  };
  const r = (id) => requireMap[id] || {};

  // Execute module 75511
  const modExports = {};
  const modObj = { exports: modExports };
  const moduleCode = sandbox.slice(bStart, end);
  const fn = new Function('e', 't', 'r', moduleCode);
  fn(modObj, modExports, r);

  const factory = modObj.exports;
  console.log('Calling Emscripten factory...');
  
  const mod = await factory({ 
    wasmBinary,
    locateFile: (path) => pathMod.join(__dirname, '..', path),
  });
  
  console.log('isAvailable:', mod.isAvailable());

  // loadToken
  console.log('\nCalling SecureKey.loadToken...');
  const secureKey = mod.SecureKey.loadToken(CHROME_TOKEN);
  console.log('SecureKey:', secureKey);

  // deriveKey
  const versionHash = new Uint8Array(sha256(VERSION));
  const tokenHash = new Uint8Array(sha256(accessToken));
  console.log('Deriving key...');
  const derivedKey = secureKey.deriveKey(versionHash, tokenHash);
  console.log('derivedKey:', derivedKey);

  // HMAC
  const hmacObj = new mod.Hmac(derivedKey);
  const message = new TextEncoder().encode(reqPath + reqBody);
  const digest = hmacObj.digest(message);
  
  let result;
  if (typeof digest === 'string') {
    result = digest;
  } else {
    result = Buffer.from(new Uint8Array(digest.buffer || digest)).toString('base64');
  }
  
  console.log('\nX-Hmac:', result);
  if (expectedHmac) {
    console.log('Expected:', expectedHmac);
    console.log(result === expectedHmac ? '✅ MATCH!' : '❌ NO MATCH');
  }
}

main().catch(e => console.error('Fatal:', e));
