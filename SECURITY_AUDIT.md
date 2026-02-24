# Security Audit — LINE Client

**Date:** 2026-02-23  
**Auditor:** Automated (Claude)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 4 |
| LOW | 3 |

---

## Findings

### HIGH-1: Token files saved without restrictive permissions

**Files:** `src/auth/token.py`, `login.py`, `login_thrift.py`, `src/auth/qr.py`, `src/auth/qr_chrome.py`, `src/auth/qr_login.py`

Tokens are saved to `~/.line-client/tokens.json` and `~/.line-client/session.json` as plain JSON with default file permissions (typically 0644). Any local user can read these files and hijack the LINE session.

**Fix:** Set `0600` permissions on token files and `0700` on the directory.

```python
import os, stat
CACHE_DIR.mkdir(parents=True, exist_ok=True)
os.chmod(CACHE_DIR, stat.S_IRWXU)  # 0700
# After writing:
os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
```

---

### HIGH-2: Debug/analysis output files committed to repo

**Files:** `output.txt`, `hmac_output.txt`, `hmac2.txt`, `results.txt`

These files contain analysis output including local filesystem paths, partial HMAC implementation details, and references to token structures. `hmac_output.txt` is 2.8MB of extracted JS containing crypto implementation details. While not containing actual secrets, they leak local environment info and shouldn't be in the repo.

**Fix:** Add to `.gitignore` and remove from tracking. ✅ **Implemented below.**

---

### MEDIUM-1: Large binary/JS files in repo (lstm.wasm + lstmSandbox.js)

**Files:** `lstm.wasm` (2.2MB), `lstmSandbox.js` (2.4MB)

These are extracted from the LINE Chrome extension. They contain the HMAC signing implementation but no standalone secrets — the HMAC computation requires a runtime auth token. However, they bloat the repo and their redistribution may violate LINE's terms of service.

**Recommendation:** Consider using `.gitignore` for these and documenting how to extract them, or host them separately.

---

### MEDIUM-2: HTTP used for local HMAC signer communication

**File:** `src/hmac/__init__.py` (lines 52, 99)

The HMAC signer uses `http://127.0.0.1:{port}/sign` for local subprocess communication. This is localhost-only and not a real network risk, but could be exploited by local processes sniffing loopback traffic.

**Recommendation:** Low priority. Could add a shared secret/nonce for local IPC but this is acceptable for a dev tool.

---

### MEDIUM-3: .gitignore missing entries for debug output files

**File:** `.gitignore`

Missing entries for: `output.txt`, `hmac_output.txt`, `hmac2.txt`, `results.txt`, `*.wasm`, `*.session`, `line_pin.txt`, `line_session.json`.

**Fix:** Updated `.gitignore`. ✅ **Implemented below.**

---

### MEDIUM-4: No token encryption at rest

**Files:** `src/auth/token.py`, `login.py`

Auth tokens and refresh tokens are stored as plaintext JSON. If the machine is compromised, tokens are immediately usable.

**Recommendation:** Consider encrypting tokens at rest using OS keyring (`keyring` package) or at minimum obfuscating them. Low priority for a personal dev tool.

---

### LOW-1: Hardcoded PIN code in email login

**File:** `src/auth/email.py`

```python
pincode = b"202202"
```

This appears to be a fixed E2EE PIN for the login flow. Not a leaked secret per se, but hardcoding it reduces flexibility.

---

### LOW-2: No pinned dependency versions

**File:** `requirements.txt`

Dependencies use `>=` minimum versions without upper bounds. This could lead to breaking changes or supply chain attacks via malicious updates.

**Recommendation:** Pin exact versions or use `~=` compatible release specifiers.

---

### LOW-3: Chrome extension version/identity hardcoded

**Files:** `src/config.py`, `login.py`

The Chrome extension version (`3.7.1`, `3.0.3`) and extension ID are hardcoded. Not a security issue per se, but could cause auth failures when LINE updates the extension.

---

## No Issues Found

- **No hardcoded tokens/API keys/secrets** in Python source code
- **No sensitive data in git history** (checked deleted files and token-related commits)
- **No session files** (`line_session.json`, `line_pin.txt`) committed to repo
- **All API calls use HTTPS** (endpoints in `config.py` all use `https://`)
- **WASM/JS files** contain no embedded secrets (they implement crypto primitives that require runtime tokens)

---

## Changes Implemented

1. Updated `.gitignore` with additional entries
2. Removed debug output files from git tracking
