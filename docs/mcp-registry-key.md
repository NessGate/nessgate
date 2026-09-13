# MCP Registry publishing key — protect, rotate, recover

NessGate is listed in the official MCP Registry as **`com.nessgate/nessgate`**. That namespace is
claimed by **HTTP domain authentication**: an Ed25519 keypair whose *public* half is served at
`https://nessgate.com/.well-known/mcp-registry-auth` and whose *private* half signs the login
challenge when we publish or update the entry.

## Files and where the trust actually lives

- **Private key:** `mcp-key.pem` in the repo root. It is **gitignored** (`/mcp-key*.pem`) and must
  **never** be committed, pasted into chat, or printed. Keep an **offline backup** (password
  manager or encrypted USB) — see below.
- **Public key:** served by an explicit route in `src/worker.js` (constant string
  `v=MCPv1; k=ed25519; p=<base64>`). No static file — the path has no extension, so it needs the
  worker route, not the assets binding.
- **Publisher binary:** `.tools/mcp-publisher.exe` (gitignored; from the
  `modelcontextprotocol/registry` GitHub releases).

**The root of trust is control of nessgate.com, not the key itself.** The registry trusts whoever
can serve the matching public key at the well-known path — i.e. whoever can deploy the Worker.
The keypair is just the current proof-of-control token. This is why losing the private key is
**recoverable** (mint a new one) and why an exposed key is **contained by rotating** (the old key
stops matching the served public key the moment we deploy a new one).

Losing or rotating the key does **not** affect the already-published listing — that entry stays
live. The key only matters for *future* publishes/updates.

## Offline backup (do this once)

Copy the private key out of the project to secure offline storage:

```powershell
Copy-Item C:\NessGate\mcp-key.pem "$env:USERPROFILE\SecureBackups\nessgate-mcp-key.pem"
# then move that copy to a password manager / encrypted USB and delete the loose copy
```

Back up **only** the private key (`mcp-key.pem`). The public key is not secret (it's on the site).

## Rotate the key (if exposed, or as routine hygiene)

Rotation is invisible to users — it only changes the auth token, not any product behaviour.

```bash
cd /c/NessGate
openssl genpkey -algorithm Ed25519 -out mcp-key.pem          # overwrite the old private key
openssl pkey -in mcp-key.pem -pubout -outform DER | tail -c 32 | base64   # -> new PUBLIC key
```

1. Paste the printed public key into the `/.well-known/mcp-registry-auth` route in `src/worker.js`
   (the `p=` value).
2. `git commit` + `npm run deploy`, then confirm:
   `curl https://nessgate.com/.well-known/mcp-registry-auth` shows the new key.
3. Back up the new `mcp-key.pem` offline. The old private key is now useless (it no longer matches
   the served public key) — delete any copies.

## Recover (if the private key is lost)

Same procedure as rotation: generate a fresh key, update the worker route, deploy. The published
listing is unaffected; you regain the ability to publish updates. There is nothing to recover from
a backup unless you want to keep the *same* key — the backup only saves a redeploy.

## Publish or update the registry entry

After rotating/recovering (or any time you bump the version), extract the private key as hex and
log in, then publish:

```bash
cd /c/NessGate
PRIVATE_KEY="$(openssl pkey -in mcp-key.pem -noout -text | grep -A3 'priv:' | tail -n +2 | tr -d ' :\n')"
.tools/mcp-publisher.exe login http --domain nessgate.com --private-key "$PRIVATE_KEY"
.tools/mcp-publisher.exe validate     # server.json must be valid (description <= 100 chars)
.tools/mcp-publisher.exe publish
```

`server.json` (repo root) describes the remote server; bump its `version` before publishing a new
release. The namespace `com.nessgate` is the reverse-DNS of the domain — it cannot be changed
without re-verifying a different domain.

## History

- **2026-09-13:** key rotated once immediately after the initial publish (the first key's private
  half had appeared in a build transcript). Current public key on the site is the rotated one; the
  first key was destroyed.
