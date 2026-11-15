# Vault Ledger — encrypted, self-hosted expense tracker

A private expense tracker with a **password-as-login** design. Your password
finds and decrypts your vault on any device; the encrypted vault file syncs
through **your own GitHub repository**. No third-party servers, no accounts.

## How it works

- Your password is your login. The app derives a vault ID from it
  (PBKDF2-SHA256, 600,000 iterations) and looks up `vault/<id>.json` in your
  repo. **The same password always opens the same vault** — a password that
  already has a vault can never create a new one; a never-used password
  creates a fresh vault.
- Your data is encrypted with a random 256-bit AES-GCM key. That key is
  wrapped twice — once with your password, once with your recovery key —
  so either one unlocks the vault.
- The vault file in your repo is **pure ciphertext**: salts, IVs and encrypted
  payloads only. Anyone can download it from the public repo; nobody can read
  it without your password.
- Devices pull the vault on login and push on every change (GitHub Contents
  API). A device without network falls back to its cached vault in read-only
  mode.

## Features

- Password login from any device + one-time **recovery key**
- Add / edit / delete expenses with categories, notes, and dates
- Monthly budget with remaining balance, progress meter, overspend alerts
- Donut chart by category + daily pace chart, month navigation
- Sync status indicator (SYNCED / READ-ONLY / OFFLINE / SYNC ERROR)
- Auto-locks after 5 minutes of inactivity

## Setup (one time, ~10 minutes)

1. **Create a public GitHub repo** (free Pages requires public), e.g. `vault-ledger`.
2. **Push this code** to it:

   ```bash
   git init && git add . && git commit -m "Vault Ledger"
   git branch -M main
   git remote add origin https://github.com/<you>/<repo>.git
   git push -u origin main
   ```

3. **Fill in `src/config.js`**: set `owner` to your username and `repo` to the
   repo name, commit and push.
4. **Enable Pages**: repo → Settings → Pages → Deploy from a branch →
   `main` / `(root)` → Save. Your app is at `https://<you>.github.io/<repo>/`.
5. **Create a sync token** at
   <https://github.com/settings/personal-access-tokens/new> (fine-grained):
   - Repository access: **Only select repositories** → your repo
   - Permissions → Repository → **Contents: Read and write**
6. Open your site, create your vault (password ≥ 10 characters), save the
   recovery key, then open **Settings → GITHUB SYNC** and paste the token.
   Repeat step 6 on each device (the token stays in that browser only).

## Honest limitations

- **The encrypted vault file is publicly downloadable** (free Pages needs a
  public repo). Security rests entirely on encryption + your password
  strength. Choose a long, unique password — there is no username, so anyone
  worldwide who guesses your exact password opens your vault. This is the
  trade-off you chose with password-only login.
- **Last write wins.** If two devices save at the exact same moment, one
  overwrites the other. For a single user this is rare; the app re-fetches
  the latest state on every login.
- **GitHub sees metadata, not contents**: commit times, file sizes, and your
  token's write access. Never amounts, notes, or categories.
- Deleting the vault file from the repo destroys the data. Old versions
  remain in git history (still encrypted) unless you purge them.
- The page loads JetBrains Mono from Google Fonts. For zero third-party
  requests, self-host the font and replace the `<link>` tags in `index.html`.
