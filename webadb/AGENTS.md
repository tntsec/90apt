# AGENTS.md

Browser-based ADB tool: Android device connected over USB, buttons to enable/disable wireless ADB (port 5555, no password). Pure static front-end — no backend, no npm, no package.json, no build tooling.

## Run & verify
- Serve: `node serve.js` (or double-click `start.bat`) → open `http://localhost:8000`.
- No linter/tests. Syntax check only: `node --check js/*.js`.
- Manual ADB verify uses `platform-tools/adb.exe` (NOT on PATH), e.g. `platform-tools\adb.exe connect <ip>:5555`.

## Architecture
- Scripts attach to a shared `window.WebADB` namespace. Load order in `index.html` is required: `adb-protocol.js` → `adb-crypto.js` → `adb-transport.js` → `adb-client.js` → `app.js`.
- Layers: protocol (24-byte LE packet framing + CRC32) → transport (WebUSB bulk endpoints, buffered reader) → crypto (RSA auth) → client (CNXN/AUTH handshake, OPEN/WRTE/OKAY/CLSE multiplexing) → app (UI).

## Gotchas
- `webadb.html` is a GENERATED single-file bundle (CSS + all JS inlined) for static hosting. After editing any file under `js/` or `css/`, regenerate it or it silently goes stale. No build script is committed.
- ADB auth is NOT standard WebCrypto: it signs a pre-hashed digest (token || SHA1(modulus)) via raw PKCS#1 v1.5 `m^d mod n` (WebCrypto would double-hash), and the public key is a 524-byte little-endian `RSAPublicKey` struct (n0inv, rr = 2^4096 mod n). See `js/adb-crypto.js`.
- WebUSB requires a secure context: localhost or HTTPS only. `file://` never works (Chrome treats it insecure). End-to-end testing needs a physical device with USB debugging enabled; first connect shows an on-device "Allow USB debugging" prompt. Key is persisted in localStorage under `webadb.adb.key.v1`.
- `tcpip:5555` and `usb` services restart adbd, so the USB connection drops after execution — expected behavior, not a bug (handled in `js/app.js`).
- `start.bat` and `serve.js` console output must stay ASCII: Chinese text in a .bat breaks under cmd's GBK code page.
- The machine's `python` is a Windows Store stub that fails to launch servers — use `node serve.js`.
- UI copy is Simplified Chinese; keep new UI strings in Chinese.
