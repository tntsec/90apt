# AGENTS.md

Browser-based ADB tool: Android device connected over USB, buttons to enable/disable wireless ADB (port 5555, no password). Pure static front-end — no backend, no npm, no package.json, no build tooling.

## Run & verify
- Serve: `node serve.js` (or double-click `start.bat`) → open `http://localhost:8000`. `serve.js` honors a `PORT` env var override; it listens on `0.0.0.0`.
- No linter/tests. Syntax check only: `node --check js/*.js`.
- Manual ADB verify uses `platform-tools/adb.exe` (NOT on PATH), e.g. `platform-tools\adb.exe connect <ip>:5555`.

## Architecture
- Scripts attach to a shared `window.WebADB` namespace. Load order in `index.html` is required: `adb-protocol.js` → `adb-crypto.js` → `adb-transport.js` → `adb-client.js` → `app.js`.
- Layers: protocol (24-byte LE packet framing + CRC32) → transport (WebUSB bulk endpoints, buffered reader) → crypto (RSA auth) → client (CNXN/AUTH handshake, OPEN/WRTE/OKAY/CLSE multiplexing) → app (UI).

## Gotchas
- `webadb.html` is a GENERATED single-file bundle (CSS + all JS inlined) for static hosting. After editing any file under `js/` or `css/`, regenerate it or it silently goes stale. No build script is committed.
- ADB auth is NOT standard WebCrypto: adbd's `RSA_sign(NID_sha1, token)` treats the 20-byte token itself as the SHA-1 digest, so the signed message is `DigestInfo(SHA1) || token` via raw PKCS#1 v1.5 `m^d mod n` — do NOT pre-hash the token (`SHA1(token)` or `SHA1(token || SHA1(modulus))` are both rejected by adbd → infinite AUTH TOKEN retry loop). Do not use WebCrypto `sign` either (it would re-hash the token). See `js/adb-crypto.js`. The public key payload (AUTH arg0=3) is the 524-byte little-endian `RSAPublicKey` struct (n0inv, rr = 2^4096 mod n) base64-encoded + `" <comment>\0"` — `buildPublicKeyBlob` already produces the correct wire string.
- CRITICAL AUTH FLOW (Android 9+, verified against A11 `daemon/auth.cpp` + `adb.cpp` + `client/auth.cpp`): adbd NEVER requests the host's public key. The host signs each AUTH TOKEN; when the signature is rejected adbd just sends a new token (`send_auth_request`, backed off to 1 Hz after 256 failures). After the host has "used up" its private keys it must PROACTIVELY send AUTH RSAPUBLICKEY — that is what triggers the on-device "Allow USB debugging" dialog (`adbd_auth_confirm_key`). `_authLoop` in `js/adb-client.js` implements this: token #1 → SIGNATURE, subsequent tokens → RSAPUBLICKEY (and it still answers explicit RSAPUBLICKEY requests from very old adbd). Symptom of the old bug: endless TOKEN↔SIGNATURE loop, NO dialog ever appears on the phone. Wire checksum is NOT validated by adbd on receive (`check_header` checks magic + length only), so the CRC32 in `buildPacket` is harmless.
- WebUSB requires a secure context: localhost or HTTPS only. `file://` never works (Chrome treats it insecure). End-to-end testing needs a physical device with USB debugging enabled; first connect shows an on-device "Allow USB debugging" prompt. Key is persisted in localStorage under `webadb.adb.key.v1`.
- `tcpip:5555` and `usb` services restart adbd, so the USB connection drops after execution — expected behavior, not a bug (handled in `js/app.js`).
- `start.bat` and `serve.js` console output must stay ASCII: Chinese text in a .bat breaks under cmd's GBK code page.
- The machine's `python` is a Windows Store stub that fails to launch servers — use `node serve.js`.
- UI copy is Simplified Chinese; keep new UI strings in Chinese.
