import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ALGOS,
  ALGO_NOTE,
  Algo,
  hashBytes,
  hashText,
  hmac,
  toBase64,
  toHex,
} from './hash';

type Mode = 'text' | 'file';
type Enc = 'hex' | 'HEX' | 'base64';

function encode(bytes: Uint8Array, enc: Enc): string {
  if (enc === 'base64') return toBase64(bytes);
  const h = toHex(bytes);
  return enc === 'HEX' ? h.toUpperCase() : h;
}

function useCopied() {
  const [key, setKey] = useState<string | null>(null);
  const t = useRef<number>();
  return {
    key,
    copy: (text: string, k: string) => {
      navigator.clipboard.writeText(text).then(() => {
        setKey(k);
        window.clearTimeout(t.current);
        t.current = window.setTimeout(() => setKey(null), 1200);
      }).catch(() => {});
    },
  };
}

function prettySize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export default function App() {
  const p = new URLSearchParams(window.location.search);
  const [mode, setMode] = useState<Mode>('text');
  const [text, setText] = useState(p.get('t') ?? 'The quick brown fox jumps over the lazy dog');
  const [enc, setEnc] = useState<Enc>((p.get('e') as Enc) || 'hex');
  const [hmacOn, setHmacOn] = useState(p.get('h') === '1');
  const [hmacKey, setHmacKey] = useState(p.get('k') ?? '');
  const [compare, setCompare] = useState('');

  const [results, setResults] = useState<Record<string, Uint8Array | null>>({});
  const [file, setFile] = useState<{ name: string; size: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const { key: copiedKey, copy } = useCopied();

  useEffect(() => {
    const u = new URL(window.location.href);
    u.searchParams.set('e', enc);
    if (mode === 'text') {
      u.searchParams.set('t', text);
      if (hmacOn) { u.searchParams.set('h', '1'); u.searchParams.set('k', hmacKey); }
      else { u.searchParams.delete('h'); u.searchParams.delete('k'); }
    }
    window.history.replaceState(null, '', u.toString());
  }, [text, enc, hmacOn, hmacKey, mode]);

  // text hashing (live)
  useEffect(() => {
    if (mode !== 'text') return;
    let live = true;
    (async () => {
      const out: Record<string, Uint8Array | null> = {};
      for (const a of ALGOS) {
        out[a] = hmacOn ? await hmac(a, hmacKey, text) : await hashText(a, text);
      }
      if (live) setResults(out);
    })();
    return () => { live = false; };
  }, [text, hmacOn, hmacKey, mode]);

  const onFile = useCallback(async (f: File) => {
    setBusy(true);
    setFile({ name: f.name, size: f.size });
    const buf = new Uint8Array(await f.arrayBuffer());
    const out: Record<string, Uint8Array | null> = {};
    for (const a of ALGOS) out[a] = await hashBytes(a, buf);
    setResults(out);
    setBusy(false);
  }, []);

  const cmpNorm = compare.trim().toLowerCase().replace(/\s+/g, '');
  const rows = useMemo(
    () =>
      ALGOS.map((a) => {
        const bytes = results[a];
        const value = bytes ? encode(bytes, enc) : hmacOn ? '— (HMAC needs SHA)' : '…';
        const hex = bytes ? toHex(bytes) : '';
        const match = cmpNorm.length > 0 && hex.length > 0 && (cmpNorm === hex || cmpNorm === toBase64(bytes!).toLowerCase());
        return { algo: a, value, match, has: !!bytes };
      }),
    [results, enc, cmpNorm, hmacOn],
  );

  return (
    <div className="wrap">
      <header>
        <h1>Hash Generator</h1>
        <p className="sub">
          MD5, SHA-1, SHA-256, SHA-384, SHA-512 and a CRC32 checksum for any text or file. The text
          updates as you type. Everything is computed in your browser — no upload, works offline.
        </p>
      </header>

      <nav className="tabs">
        <button className={mode === 'text' ? 'on' : ''} onClick={() => setMode('text')}>Text</button>
        <button className={mode === 'file' ? 'on' : ''} onClick={() => setMode('file')}>File</button>
      </nav>

      {mode === 'text' ? (
        <>
          <textarea
            className="input"
            value={text}
            spellCheck={false}
            onChange={(e) => setText(e.target.value)}
            placeholder="Type or paste text to hash"
          />
          <div className="meta">
            <span>{new TextEncoder().encode(text).length} bytes · {text.length} chars</span>
            <label className="hmac">
              <input type="checkbox" checked={hmacOn} onChange={(e) => setHmacOn(e.target.checked)} /> HMAC
            </label>
          </div>
          {hmacOn && (
            <input
              className="keyin"
              type="text"
              value={hmacKey}
              onChange={(e) => setHmacKey(e.target.value)}
              placeholder="HMAC secret key"
            />
          )}
        </>
      ) : (
        <label className="drop">
          <input
            type="file"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) onFile(f);
            }}
          />
          <span>
            {file ? (
              <><strong>{file.name}</strong><br />{prettySize(file.size)}{busy ? ' · hashing…' : ''}</>
            ) : (
              'Choose a file to hash — it stays on your device'
            )}
          </span>
        </label>
      )}

      <div className="encbar">
        <div className="seg">
          {(['hex', 'HEX', 'base64'] as Enc[]).map((x) => (
            <button key={x} className={enc === x ? 'on' : ''} onClick={() => setEnc(x)}>
              {x === 'hex' ? 'hex' : x === 'HEX' ? 'HEX' : 'Base64'}
            </button>
          ))}
        </div>
        <input
          className="cmp"
          type="text"
          value={compare}
          onChange={(e) => setCompare(e.target.value)}
          placeholder="Paste a hash to compare"
        />
      </div>

      <ul className="hashes">
        {rows.map((r) => (
          <li key={r.algo} className={r.match ? 'match' : ''}>
            <div className="hrow">
              <span className="name">{r.algo}{r.match && <em> ✓ match</em>}</span>
              <button disabled={!r.has} onClick={() => copy(r.value, r.algo)}>
                {copiedKey === r.algo ? 'Copied' : 'Copy'}
              </button>
            </div>
            <code>{r.value}</code>
            <p className="note">{ALGO_NOTE[r.algo as Algo]}</p>
          </li>
        ))}
      </ul>

      <section className="explain">
        <h2>What a hash is for</h2>
        <p>
          A hash function turns any input into a fixed-length fingerprint. The same input always
          gives the same digest; a one-character change gives a completely different one. Hashes
          verify that a download or a message arrived intact, index content, and — with a salt —
          store passwords.
        </p>
        <h3>Which algorithm should I use?</h3>
        <p>
          For anything security-related, use <strong>SHA-256</strong>. <strong>MD5</strong> and
          <strong> SHA-1</strong> are broken against deliberate collisions and should only be used
          where a legacy system requires them or to spot accidental corruption.
          <strong> CRC32</strong> is a checksum, not a hash — it catches transmission errors and
          nothing more.
        </p>
        <h3>Is my text or file uploaded?</h3>
        <p>
          No. Hashing runs entirely in your browser: the SHA family through the built-in Web Crypto
          API, MD5 and CRC32 in local code. A file you pick is read into memory and never sent. The
          text box contents are put in the page URL so you can bookmark or share the exact input —
          don't use that with anything secret.
        </p>
        <h3>Can I get the original text back from a hash?</h3>
        <p>
          No. Hashing is one-way. "Reversing" a hash means guessing inputs until one matches, which
          only works for short or common values.
        </p>
        <footer>Hash Generator · client-side · no sign-up · MD5 / SHA-1 / SHA-2 / CRC32</footer>
      </section>
    </div>
  );
}
