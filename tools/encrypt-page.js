#!/usr/bin/env node
// Locks an HTML page behind a password so it can be published on a static host
// like GitHub Pages. The output file contains only encrypted data plus a small
// unlock form; the browser decrypts it after the visitor types the password.
//
//   node tools/encrypt-page.js <plain.html> <output.html>
//
// The password is typed into the terminal (hidden) and is never written anywhere.
// Encryption: PBKDF2-SHA256 (600,000 rounds) -> AES-256-GCM, decrypted with WebCrypto.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ITERATIONS = 600000;
const MIN_LENGTH = 12;

const TEMPLATE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Private page</title>
<link rel="stylesheet" href="/style.css">
<style>
.lock{max-width:400px;margin:0 auto;padding:96px 24px 48px}
.lock h1{font-size:30px;margin:0 0 8px}
.lock .hint{color:var(--muted);margin:0 0 28px}
.lock label{display:block;font-size:14px;font-weight:600;margin:0 0 6px}
.lock input{width:100%;font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--ink)}
.lock input:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:var(--accent)}
.lock button{margin-top:12px;width:100%;font:inherit;font-weight:600;padding:10px 14px;border:0;border-radius:10px;background:var(--accent);color:var(--on-accent);cursor:pointer}
.lock button:disabled{opacity:.6;cursor:progress}
.lock .msg{min-height:1.5em;margin:12px 0 0;font-size:15px;color:#b42318}
@media (prefers-color-scheme: dark){.lock .msg{color:#f97066}}
</style>
</head>
<body>
<main class="lock">
  <h1>Private page</h1>
  <p class="hint">Enter the password to view this page.</p>
  <form id="unlock">
    <label for="pw">Password</label>
    <input id="pw" type="password" autocomplete="current-password" required autofocus>
    <button type="submit">Unlock</button>
    <p class="msg" id="msg" role="alert"></p>
  </form>
  <noscript><p>This page needs JavaScript to unlock.</p></noscript>
</main>
<script>
(() => {
  // WebCrypto only works over HTTPS, so move plain-HTTP visits to HTTPS first.
  if (location.protocol === 'http:' && !/^(localhost|127\\.0\\.0\\.1)$/.test(location.hostname)) {
    location.replace('https:' + location.href.slice(5));
    return;
  }
  const P = { salt: '__SALT__', iv: '__IV__', iterations: __ITERATIONS__, data: '__DATA__' };
  const bytes = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const form = document.getElementById('unlock');
  const pw = document.getElementById('pw');
  const msg = document.getElementById('msg');
  const button = form.querySelector('button');

  form.addEventListener('submit', async event => {
    event.preventDefault();
    button.disabled = true;
    button.textContent = 'Unlocking…';
    msg.textContent = '';
    try {
      const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw.value.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
      const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: bytes(P.salt), iterations: P.iterations, hash: 'SHA-256' },
        base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes(P.iv) }, key, bytes(P.data));
      const html = new TextDecoder().decode(plain);
      document.open();
      document.write(html);
      document.close();
    } catch {
      msg.textContent = 'Wrong password. Try again.';
      button.disabled = false;
      button.textContent = 'Unlock';
      pw.select();
    }
  });
})();
</script>
</body>
</html>
`;

function encryptPage(html, password) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(password.normalize('NFC'), salt, ITERATIONS, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  // WebCrypto expects the GCM auth tag appended to the ciphertext.
  const data = Buffer.concat([cipher.update(html, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return TEMPLATE
    .replace('__SALT__', salt.toString('base64'))
    .replace('__IV__', iv.toString('base64'))
    .replace('__ITERATIONS__', String(ITERATIONS))
    .replace('__DATA__', data.toString('base64'));
}

function askHidden(prompt) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      reject(new Error('Run this in an interactive terminal so you can type the password.'));
      return;
    }
    process.stdout.write(prompt);
    stdin.setRawMode(true);
    stdin.setEncoding('utf8');
    stdin.resume();
    let value = '';
    const cleanup = () => {
      stdin.removeListener('data', onData);
      stdin.setRawMode(false);
      stdin.pause();
      process.stdout.write('\n');
    };
    const onData = chunk => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') { cleanup(); resolve(value); return; }
        if (ch === '\u0003') { cleanup(); process.exit(130); }
        if (ch === '\u0008' || ch === '\u007f') { value = value.slice(0, -1); continue; }
        value += ch;
      }
    };
    stdin.on('data', onData);
  });
}

async function main() {
  const [input, output] = process.argv.slice(2);
  if (!input || !output) {
    console.error('Usage: node tools/encrypt-page.js <plain.html> <output.html>');
    process.exit(1);
  }
  const html = fs.readFileSync(input, 'utf8');
  const password = await askHidden('Choose a password: ');
  if ([...password].length < MIN_LENGTH) {
    console.error(`Please use at least ${MIN_LENGTH} characters (a few random words works well).`);
    process.exit(1);
  }
  if (password !== await askHidden('Type it again: ')) {
    console.error('The two passwords did not match. Nothing was written.');
    process.exit(1);
  }
  const page = encryptPage(html, password);
  fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
  fs.writeFileSync(output, page);
  console.log(`Locked page written to ${output} (${Math.round(page.length / 1024)} KB).`);
}

module.exports = { encryptPage };

if (require.main === module) {
  main().catch(err => { console.error(err.message); process.exit(1); });
}
