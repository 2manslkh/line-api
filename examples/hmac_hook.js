/**
 * LINE HMAC Black-Box Hook
 * 
 * Paste this in the LINE Chrome extension's sandbox iframe console,
 * or inject via content script. It hooks crypto.subtle to capture
 * all HMAC-related operations.
 * 
 * Usage: Open LINE extension → F12 → find the sandbox iframe context
 *        → paste this in console → trigger any API call
 */

(() => {
  const log = (...args) => console.log('%c[HMAC-HOOK]', 'color: #C9A962; font-weight: bold', ...args);
  const hex = buf => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));

  // Hook crypto.subtle.importKey
  const origImportKey = crypto.subtle.importKey.bind(crypto.subtle);
  crypto.subtle.importKey = async function(format, keyData, algo, extractable, usages) {
    if (algo?.name === 'HMAC' || algo === 'HMAC') {
      log('importKey HMAC', {
        format,
        keyHex: hex(keyData),
        keyB64: b64(keyData),
        keyLen: new Uint8Array(keyData).length,
        algo,
      });
    }
    return origImportKey(format, keyData, algo, extractable, usages);
  };

  // Hook crypto.subtle.sign
  const origSign = crypto.subtle.sign.bind(crypto.subtle);
  crypto.subtle.sign = async function(algo, key, data) {
    const result = await origSign(algo, key, data);
    if (algo === 'HMAC' || algo?.name === 'HMAC') {
      const dataBytes = new Uint8Array(data);
      let dataStr;
      try { dataStr = new TextDecoder().decode(dataBytes); } catch(e) { dataStr = '(binary)'; }
      log('sign HMAC', {
        dataHex: hex(data),
        dataStr: dataStr.slice(0, 500),
        dataLen: dataBytes.length,
        resultHex: hex(result),
        resultB64: b64(result),
      });
    }
    return result;
  };

  // Hook crypto.subtle.digest (catches SHA-256 calls = tm function)
  const origDigest = crypto.subtle.digest.bind(crypto.subtle);
  crypto.subtle.digest = async function(algo, data) {
    const result = await origDigest(algo, data);
    const dataBytes = new Uint8Array(data);
    let dataStr;
    try { dataStr = new TextDecoder().decode(dataBytes); } catch(e) { dataStr = '(binary)'; }
    log('digest', {
      algo,
      inputStr: dataStr.slice(0, 200),
      inputLen: dataBytes.length,
      outputHex: hex(result),
    });
    return result;
  };

  // Hook postMessage to catch HMAC results going back
  const origPostMessage = self.postMessage?.bind(self);
  if (origPostMessage) {
    self.postMessage = function(msg, ...args) {
      if (msg?.type === 'RESPONSE' || msg?.data) {
        log('postMessage', JSON.stringify(msg).slice(0, 500));
      }
      return origPostMessage(msg, ...args);
    };
  }

  log('Hooks installed. Trigger any LINE API call to capture HMAC flow.');
  log('Look for: digest("3.7.1") → digest(accessToken) → importKey → sign');
})();
