// Unified hashing API. SHA family via crypto.subtle; MD5 via local implementation;
// CRC32 for a quick non-cryptographic checksum.
import { md5 } from './md5.ts';

export type Algo = 'MD5' | 'CRC32' | 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

export const ALGOS: Algo[] = ['MD5', 'CRC32', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];

export const ALGO_NOTE: Record<Algo, string> = {
  MD5: 'Broken for security. Fine as a file checksum or for legacy interop.',
  CRC32: 'A 32-bit checksum, not a hash. Detects accidental corruption only.',
  'SHA-1': 'Deprecated for signatures (collisions are practical). Still seen in Git and older systems.',
  'SHA-256': 'The usual modern choice. Used in TLS certificates, blockchains and file integrity.',
  'SHA-384': 'SHA-2 truncated to 384 bits.',
  'SHA-512': 'SHA-2 with a 512-bit output and 64-bit internal words.',
};

export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += (bytes[i] + 0x100).toString(16).slice(1);
  return s;
}

export function toBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(bytes: Uint8Array): Uint8Array {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  c = (c ^ 0xffffffff) >>> 0;
  return new Uint8Array([(c >>> 24) & 0xff, (c >>> 16) & 0xff, (c >>> 8) & 0xff, c & 0xff]);
}

export async function hashBytes(algo: Algo, bytes: Uint8Array): Promise<Uint8Array> {
  if (algo === 'MD5') return md5(bytes);
  if (algo === 'CRC32') return crc32(bytes);
  const copy = bytes.slice();
  const buf = await crypto.subtle.digest(algo, copy);
  return new Uint8Array(buf);
}

export async function hashText(algo: Algo, text: string): Promise<Uint8Array> {
  return hashBytes(algo, new TextEncoder().encode(text));
}

// HMAC-<sha> using crypto.subtle (MD5/CRC32 not supported for HMAC here)
export async function hmac(algo: Algo, key: string, text: string): Promise<Uint8Array | null> {
  if (algo === 'MD5' || algo === 'CRC32') return null;
  const k = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(key),
    { name: 'HMAC', hash: algo },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(text));
  return new Uint8Array(sig);
}
