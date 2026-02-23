/**
 * Load lstm.wasm directly in Node.js and call deriveKey + Hmac.
 * 
 * This is an Emscripten module — we need to provide the expected imports.
 */

const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const CHROME_TOKEN = "YOUR_CHROME_TOKEN_HERE";
const VERSION = "3.7.1";
const ACCESS_TOKEN = process.argv[2] || "test_token";
const REQ_PATH = process.argv[3] || "/api/v4/test";
const REQ_BODY = process.argv[4] || "";

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

async function main() {
  const wasmPath = path.join(__dirname, '..', 'lstm.wasm');
  const wasmBuffer = fs.readFileSync(wasmPath);

  // Emscripten expects certain imports — stub them out to discover what's needed
  const memory = new WebAssembly.Memory({ initial: 256, maximum: 2048 });
  const table = new WebAssembly.Table({ initial: 128, element: 'anyfunc' });

  // Collect all import requirements first
  const wasmModule = await WebAssembly.compile(wasmBuffer);
  const imports = WebAssembly.Module.imports(wasmModule);
  const exports_desc = WebAssembly.Module.exports(wasmModule);

  console.log("=== WASM IMPORTS ===");
  for (const imp of imports) {
    console.log(`  ${imp.module}.${imp.name} (${imp.kind})`);
  }
  
  console.log("\n=== WASM EXPORTS ===");
  for (const exp of exports_desc) {
    console.log(`  ${exp.name} (${exp.kind})`);
  }

  // Build stub imports
  const stubImports = {};
  for (const imp of imports) {
    if (!stubImports[imp.module]) stubImports[imp.module] = {};
    
    if (imp.kind === 'function') {
      stubImports[imp.module][imp.name] = function(...args) {
        // console.log(`IMPORT CALL: ${imp.module}.${imp.name}(${args.join(', ')})`);
        return 0;
      };
    } else if (imp.kind === 'memory') {
      stubImports[imp.module][imp.name] = memory;
    } else if (imp.kind === 'table') {
      stubImports[imp.module][imp.name] = table;
    } else if (imp.kind === 'global') {
      stubImports[imp.module][imp.name] = new WebAssembly.Global({ value: 'i32', mutable: true }, 0);
    }
  }

  try {
    const instance = await WebAssembly.instantiate(wasmBuffer, stubImports);
    console.log("\n=== INSTANTIATED ===");
    console.log("Export names:", Object.keys(instance.instance.exports));
    
    // Try to find and call exported functions
    const ex = instance.instance.exports;
    for (const [name, fn] of Object.entries(ex)) {
      if (typeof fn === 'function') {
        console.log(`  ${name}: function (${fn.length} params)`);
      }
    }
  } catch (e) {
    console.error("Instantiation failed:", e.message);
    console.log("\nThis is expected — Emscripten modules need proper runtime setup.");
    console.log("We need the JS glue code that initializes the module.");
  }
}

main().catch(console.error);
