/**
 * Test LINE HMAC signing using the actual WASM module.
 * 
 * Usage: node test_hmac.js <accessToken> <path> <body> [expectedHmac]
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CHROME_TOKEN = "wODdrvWqmdP4Zliay-iF3cz3KZcK0ekrial868apg06TXeCo7A1hIQO0ESElHg6D";
const VERSION = "3.7.1";

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

async function loadModule() {
  const wasmPath = path.join(__dirname, '..', 'lstm.wasm');
  const wasmBinary = fs.readFileSync(wasmPath);
  const sandboxPath = path.join(__dirname, '..', 'lstmSandbox.js');
  const sandboxContent = fs.readFileSync(sandboxPath, 'utf-8');

  const moduleStart = sandboxContent.indexOf('75511:(e,t,r)=>{');
  const bodyStart = sandboxContent.indexOf('{', moduleStart);
  let depth = 0, end = bodyStart;
  for (let i = bodyStart; i < sandboxContent.length; i++) {
    if (sandboxContent[i] === '{') depth++;
    else if (sandboxContent[i] === '}') depth--;
    if (depth === 0) { end = i + 1; break; }
  }
  const moduleCode = sandboxContent.slice(bodyStart, end);

  globalThis.document = { currentScript: { src: '' } };
  globalThis.location = { href: '' };
  globalThis.window = globalThis;
  globalThis.window.crypto = {
    getRandomValues: (arr) => { crypto.randomFillSync(arr); return arr; }
  };
  globalThis.window.origin = 'chrome-extension://ophjlpahpchlmihnnnihgmmeilfjmjjc';
  globalThis.self = globalThis.window;

  const r = (id) => ({});
  const moduleExports = {};
  const moduleObj = { exports: moduleExports };

  eval(`(function(e, t, r_fn) ${moduleCode})(moduleObj, moduleExports, r)`);

  const factory = moduleObj.exports;
  const mod = await factory({ wasmBinary });
  return mod;
}

async function main() {
  const accessToken = process.argv[2];
  const reqPath = process.argv[3];
  const reqBody = process.argv[4] || "";
  const expectedHmac = process.argv[5];

  if (!accessToken || !reqPath) {
    console.log('Usage: node test_hmac.js <accessToken> <path> [body] [expectedHmac]');
    process.exit(1);
  }

  console.log('Loading WASM module...');
  const mod = await loadModule();
  console.log('Module loaded. isAvailable:', mod.isAvailable());

  // List all SecureKey static methods
  console.log('\nSecureKey:', Object.getOwnPropertyNames(mod.SecureKey));
  console.log('SecureKey.prototype:', Object.getOwnPropertyNames(mod.SecureKey.prototype));
  console.log('SecureKey.loadToken.length:', mod.SecureKey.loadToken.length);
  console.log('SecureKey.loadToken.argCount:', mod.SecureKey.loadToken.argCount);
  console.log('SecureKey.loadKey.length:', mod.SecureKey.loadKey?.length);
  console.log('Hmac.prototype.digest.length:', mod.Hmac.prototype.digest?.length);
  console.log('deriveKey.length:', mod.SecureKey.prototype.deriveKey?.length);
  
  // Try loadToken
  console.log('\nLoading token...');
  try {
    // Try different input formats
    let secureKey;
    for (const [label, input] of [
      ['string', CHROME_TOKEN],
      ['Uint8Array (utf8)', new TextEncoder().encode(CHROME_TOKEN)],
      ['Uint8Array (b64dec)', new Uint8Array(Buffer.from(CHROME_TOKEN.replace(/-/g,'+').replace(/_/g,'/') + '==', 'base64'))],
    ]) {
      try {
        console.log(`  Trying ${label}...`);
        secureKey = mod.SecureKey.loadToken(input);
        console.log(`  ✅ Success with ${label}`);
        break;
      } catch(e) {
        console.log(`  ❌ ${label}: ${e.message}`);
      }
    }
    if (!secureKey) { console.log('All loadToken attempts failed'); return; }
    console.log('SecureKey loaded:', secureKey);
    console.log('SecureKey instance methods:', Object.getOwnPropertyNames(Object.getPrototypeOf(secureKey)));

    // deriveKey(lS, sha256(accessToken))
    const versionHash = new Uint8Array(sha256(VERSION));
    const tokenHash = new Uint8Array(sha256(accessToken));
    
    console.log('\nDeriving key...');
    console.log('  versionHash:', Buffer.from(versionHash).toString('hex'));
    console.log('  tokenHash:', Buffer.from(tokenHash).toString('hex'));
    
    const derivedKey = secureKey.deriveKey(versionHash, tokenHash);
    console.log('  derivedKey:', derivedKey);
    
    // Create HMAC
    console.log('\nComputing HMAC...');
    const hmacObj = new mod.Hmac(derivedKey);
    const message = new TextEncoder().encode(reqPath + reqBody);
    console.log('  message length:', message.length);
    
    const digest = hmacObj.digest(message);
    console.log('  digest (raw):', digest);
    
    // Try to convert to base64
    let digestBytes;
    if (digest instanceof Uint8Array) {
      digestBytes = digest;
    } else if (typeof digest === 'string') {
      digestBytes = Buffer.from(digest);
    } else {
      console.log('  digest type:', typeof digest, digest.constructor?.name);
      digestBytes = new Uint8Array(digest);
    }
    
    const b64 = Buffer.from(digestBytes).toString('base64');
    console.log('\nX-Hmac:', b64);
    
    if (expectedHmac) {
      console.log('Expected:', expectedHmac);
      console.log('Match:', b64 === expectedHmac ? '✅ YES!' : '❌ NO');
    }
  } catch(e) {
    console.error('Error:', e.message || e);
    console.error(e.stack);
  }
}

main().catch(console.error);
