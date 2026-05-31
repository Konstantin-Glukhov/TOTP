# TOTP Vault

A minimal, secure TOTP authenticator extension for Chrome. All secrets are encrypted locally — nothing ever leaves your browser.

## Features

- **Live TOTP generation** — paste any Base32 secret or `otpauth://` URI and get a live code with a countdown ring
- **Encrypted vault** — save secrets under named accounts, protected by a password you choose
- **AES-256-GCM encryption** with PBKDF2 key derivation (600,000 iterations, SHA-256)
- **No network access** — the extension requests only the `storage` permission
- **otpauth:// URI support** — paste a QR code URI directly into the secret field

## Installation

### From source

1. Clone or download this repository
2. Install dependencies and build:
   ```bash
   npm install
   npm run build
   ```
3. Open Chrome and go to `chrome://extensions`
4. Enable **Developer mode** (top-right toggle)
5. Click **Load unpacked** and select the `extension/` folder

### From the Chrome Web Store

_(Link here once published)_

## Usage

### Generate a code without saving

1. Click the extension icon to open the popup
2. Paste your Base32 secret key (e.g. `JBSWY3DPEHPK3PXP`) or a full `otpauth://totp/…` URI into the **Secret** field
3. The six-digit code appears immediately with a 30-second countdown ring
4. Click **Copy** to copy the code to your clipboard

### Save a secret to the vault

1. Enter a secret as above
2. Click **Save to vault**
3. If this is your first save, you'll be prompted to create a vault password — choose a strong one, it cannot be recovered
4. Give the account a name (e.g. `GitHub`) and click **Save**

### View and manage saved accounts

1. Click **Open vault** and enter your password
2. Each account shows its live code and countdown ring
3. Use the **copy**, **edit**, and **delete** buttons on each entry as needed

### Change your vault password

1. Click the ⚙ icon (requires an existing vault)
2. Enter and confirm your new password
3. Click **Confirm** — the vault is re-encrypted immediately with a fresh salt

## Security notes

- Secrets are encrypted with AES-256-GCM before being written to `chrome.storage.local`
- The encryption key is derived from your password using PBKDF2 with 600,000 iterations (SHA-256, 16-byte random salt) — in line with current OWASP recommendations
- The derived key exists only in memory for the duration of the browser session and is never persisted
- `chrome.storage.local` data is stored on disk in Chrome's profile directory. On a shared machine, ensure your OS user account is protected
- TOTP codes are generated entirely with the Web Crypto API — no third-party libraries are involved

## Permissions

| Permission | Why |
|---|---|
| `storage` | Persisting the encrypted vault across browser sessions |

No host permissions, no `tabs`, no network access.

## Building

Requires Node.js 18+.

```bash
npm install       # install TypeScript and build tools
npm run build     # compiles src/popup.ts → extension/popup.js
```

The `extension/` folder is self-contained after building and can be loaded directly into Chrome.

## License

MIT
