# Hash Generator

Compute cryptographic and checksum digests in the browser — nothing is uploaded.

- **MD5** — local implementation (not in the Web Crypto API). Broken for security; use for checksums / legacy interop.
- **CRC32** — 32-bit checksum for accidental-corruption detection.
- **SHA-1 / SHA-256 / SHA-384 / SHA-512** — via the browser's `crypto.subtle`.
- **HMAC** — keyed hashing over the SHA family.

Text mode hashes live as you type; File mode reads a chosen file into memory and hashes it.
Output as lowercase hex, uppercase hex, or Base64. A compare box highlights the algorithm whose
digest matches a pasted value. Text input, output encoding and HMAC settings persist in the URL.

## Develop

```
npm install
npm run dev
npm run build
```

Engine: [`src/hash.ts`](src/hash.ts) + [`src/md5.ts`](src/md5.ts). Verified against published test
vectors (RFC 1321, FIPS 180, RFC 4231). Static site on Cloudflare Workers.

Part of [Tiny Tools](https://tinytools.correia95.workers.dev).
