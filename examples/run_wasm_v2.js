/**
 * Run lstm.wasm using the Emscripten glue extracted from ltsmSandbox.js.
 * 
 * The module 75511 is the Emscripten factory. We extract it and run it
 * to get the full module with SecureKey, Hmac, etc.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

const CHROME_TOKEN = "wODdrvWqmdP4Zliay-iF3cz3KZcK0ekrial868apg06TXeCo7A1hIQO0ESElHg6D";
const VERSION = "3.7.1";

async function main() {
  const wasmPath = path.join(__dirname, '..', 'lstm.wasm');
  const wasmBinary = fs.readFileSync(wasmPath);
  
  // The Emscripten module factory expects wasmBinary to be provided
  // Let's extract and adapt module 75511
  const sandboxPath = path.join(__dirname, '..', 'lstmSandbox.js');
  const sandboxContent = fs.readFileSync(sandboxPath, 'utf-8');
  
  // Find module 75511
  const moduleStart = sandboxContent.indexOf('75511:(e,t,r)=>{');
  const bodyStart = sandboxContent.indexOf('{', moduleStart);
  
  let depth = 0, end = bodyStart;
  for (let i = bodyStart; i < sandboxContent.length; i++) {
    if (sandboxContent[i] === '{') depth++;
    else if (sandboxContent[i] === '}') depth--;
    if (depth === 0) { end = i + 1; break; }
  }
  
  // Extract the inner factory function (the Emscripten module)
  // It's: (()=>{ var e=...; return function(t) { ... } })()
  // We need to find that inner factory
  const moduleCode = sandboxContent.slice(bodyStart, end);
  
  // Write it as a standalone module for inspection
  const standaloneCode = `
    // Emscripten factory - extracted from ltsmSandbox.js module 75511
    const wasmBinary = require('fs').readFileSync('${wasmPath}');
    
    // Provide minimal environment
    globalThis.document = { currentScript: { src: '' } };
    globalThis.location = { href: '' };
    
    // The module factory
    const r = (id) => {
      if (id === 1426) {
        // r(1426) - likely a polyfill or helper, stub it
        return {};
      }
      return {};
    };
    
    const moduleExports = {};
    const moduleObj = { exports: moduleExports };
    
    // Execute the webpack module
    (function(e, t, r_fn) ${moduleCode})(moduleObj, moduleExports, r);
    
    // The module should have exported a factory function
    console.log('Module exports:', Object.keys(moduleExports));
    console.log('Module.exports type:', typeof moduleObj.exports);
    
    async function init() {
      let factory;
      if (typeof moduleObj.exports === 'function') {
        factory = moduleObj.exports;
      } else if (typeof moduleExports.default === 'function') {
        factory = moduleExports.default;
      } else {
        // Try to find the factory
        for (const [k, v] of Object.entries(moduleExports)) {
          if (typeof v === 'function') {
            console.log('  Found function:', k);
            factory = v;
          }
        }
      }
      
      if (!factory) {
        console.log('No factory found');
        return;
      }
      
      console.log('Calling factory with wasmBinary...');
      try {
        const mod = await factory({ wasmBinary: wasmBinary });
        console.log('Module loaded!');
        console.log('Module keys:', Object.keys(mod).filter(k => !k.startsWith('_')).slice(0, 30));
        
        // Check for our target classes
        for (const name of ['SecureKey', 'Hmac', 'AesKey', 'E2EEKey', 'Curve25519Key', 'isAvailable']) {
          if (mod[name]) {
            console.log(\`  \${name}: \${typeof mod[name]}\`);
            if (typeof mod[name] === 'function') {
              console.log(\`    methods: \${Object.getOwnPropertyNames(mod[name].prototype || {}).join(', ')}\`);
            }
          }
        }
        
        if (mod.isAvailable && mod.isAvailable()) {
          console.log('\\nModule is available! Trying HMAC flow...');
          
          // loadToken
          const secureKey = mod.SecureKey.loadToken(CHROME_TOKEN);
          console.log('SecureKey loaded:', secureKey);
          
          // deriveKey(lS, sha256(accessToken))
          const versionHash = sha256(VERSION);
          const testTokenHash = sha256('test_token');
          
          const derivedKey = secureKey.deriveKey(
            new Uint8Array(versionHash),
            new Uint8Array(testTokenHash)
          );
          console.log('Derived key:', Buffer.from(derivedKey).toString('hex'));
          
          // Hmac
          const hmacObj = new mod.Hmac(derivedKey);
          const testMsg = new TextEncoder().encode('/test');
          const digest = hmacObj.digest(testMsg);
          console.log('HMAC digest:', Buffer.from(digest).toString('base64'));
        }
      } catch(e) {
        console.error('Factory error:', e.message || e);
      }
    }
    
    init().catch(console.error);
  `;
  
  fs.writeFileSync(path.join(__dirname, 'run_emscripten.js'), standaloneCode);
  console.log('Written run_emscripten.js');
  
  // Try to run it
  const { execSync } = require('child_process');
  try {
    const result = execSync('node run_emscripten.js', { 
      cwd: __dirname, 
      timeout: 10000,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe']
    });
    console.log(result);
  } catch(e) {
    console.log('STDOUT:', e.stdout?.slice(0, 2000));
    console.log('STDERR:', e.stderr?.slice(0, 2000));
  }
}

main();
