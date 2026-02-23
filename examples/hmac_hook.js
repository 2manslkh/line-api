/**
 * LINE HMAC Black-Box Hook v2 — WASM-level interception
 * 
 * Hooks WebAssembly.instantiate to intercept the crypto WASM module,
 * AND patches the sandbox message handler to log HMAC request/response.
 * 
 * Inject BEFORE the extension loads (via Tampermonkey/content script on
 * the sandbox page, or paste in console and reload).
 * 
 * Alternative: paste in sandbox iframe console AFTER load to hook
 * the already-instantiated objects (Part 2 below).
 */

(() => {
  const log = (...args) => console.log('%c[HMAC-HOOK]', 'color: #C9A962; font-weight: bold', ...args);
  const hex = buf => Array.from(new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer || buf))
    .map(b => b.toString(16).padStart(2, '0')).join('');

  // ========== PART 1: Hook WebAssembly.instantiate (must run before WASM loads) ==========
  
  const origInstantiate = WebAssembly.instantiate;
  WebAssembly.instantiate = async function(source, imports) {
    log('WebAssembly.instantiate called');
    const result = await origInstantiate.call(this, source, imports);
    const instance = result.instance || result;
    const exports = instance.exports;
    
    log('WASM exports:', Object.keys(exports));
    
    // Hook all exported functions to log calls
    for (const [name, fn] of Object.entries(exports)) {
      if (typeof fn === 'function') {
        instance.exports[name] = function(...args) {
          if (name.match(/hmac|sign|derive|key|digest|hash/i)) {
            log(`WASM.${name}(`, args, ')');
          }
          const ret = fn.apply(this, args);
          if (name.match(/hmac|sign|derive|key|digest|hash/i)) {
            log(`WASM.${name} →`, ret);
          }
          return ret;
        };
      }
    }
    
    return result;
  };

  const origInstantiateStreaming = WebAssembly.instantiateStreaming;
  if (origInstantiateStreaming) {
    WebAssembly.instantiateStreaming = async function(source, imports) {
      log('WebAssembly.instantiateStreaming called');
      const result = await origInstantiateStreaming.call(this, source, imports);
      const exports = result.instance.exports;
      
      log('WASM exports (streaming):', Object.keys(exports));
      
      for (const [name, fn] of Object.entries(exports)) {
        if (typeof fn === 'function') {
          result.instance.exports[name] = function(...args) {
            if (name.match(/hmac|sign|derive|key|digest|hash/i)) {
              log(`WASM.${name}(`, args, ')');
            }
            const ret = fn.apply(this, args);
            if (name.match(/hmac|sign|derive|key|digest|hash/i)) {
              log(`WASM.${name} →`, ret);
            }
            return ret;
          };
        }
      }
      
      return result;
    };
  }

  // ========== PART 2: Hook already-loaded objects (paste after page load) ==========
  
  // Find and hook the message handler to intercept GET_HMAC commands
  const origAddEventListener = self.addEventListener;
  self.addEventListener = function(type, handler, ...rest) {
    if (type === 'message') {
      const wrapped = function(event) {
        const data = event.data;
        if (data?.command === 'get_hmac' || data?.payload?.accessToken) {
          log('INCOMING get_hmac', {
            accessToken: data.payload?.accessToken?.slice(0, 20) + '...',
            path: data.payload?.path,
            body: data.payload?.body?.slice(0, 200),
          });
        }
        return handler.call(this, event);
      };
      return origAddEventListener.call(this, type, wrapped, ...rest);
    }
    return origAddEventListener.call(this, type, handler, ...rest);
  };

  // Hook postMessage to catch the HMAC result
  const origPostMessage = self.postMessage;
  self.postMessage = function(msg, ...args) {
    if (msg && typeof msg === 'object') {
      log('OUTGOING postMessage', JSON.stringify(msg).slice(0, 500));
    }
    return origPostMessage.call(this, msg, ...args);
  };

  // Hook crypto.subtle.digest to catch SHA-256 calls (tm function)
  const origDigest = crypto.subtle.digest.bind(crypto.subtle);
  crypto.subtle.digest = async function(algo, data) {
    const result = await origDigest(algo, data);
    const bytes = new Uint8Array(data);
    let str;
    try { str = new TextDecoder().decode(bytes); } catch(e) { str = null; }
    log('SHA-256', {
      input: str || hex(data).slice(0, 80),
      inputLen: bytes.length,
      output: hex(result),
    });
    return result;
  };

  log('v2 hooks installed.');
  log('If WASM already loaded, reload the sandbox page with this script pre-injected.');
  log('Otherwise, trigger any LINE API call now.');
})();
