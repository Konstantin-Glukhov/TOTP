const CIRC = 2 * Math.PI * 10;
const BLANK_TOTP = "——— ———";

// TOTP

function base32DecodeTable(): Int16Array {
  const table = new Int16Array(128).fill(-1);
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  for (let i = 0; i < 32; i++) table[chars.charCodeAt(i)] = i;
  return table;
}

const BASE32_DECODE = base32DecodeTable();

function normalizeSecret(input: string): string {
  let secret = input.trim();
  if (secret.toLowerCase().startsWith("otpauth://")) {
    try {
      const url = new URL(secret);
      const extracted = url.searchParams.get("secret");
      if (extracted) secret = extracted;
    } catch {
      throw new Error("malformed URI");
    }
  }
  return secret.replace(/([\s-]|=+$)/g, "").toUpperCase();
}

function base32Decode(input: string, validateOnly = false): ArrayBuffer {
  input = normalizeSecret(input);
  if (input.length < 2) throw new Error("Input should be more than 1 character");
  // validate chars
  for (let i = 0; i < input.length; i++)
    if (!(BASE32_DECODE[input.charCodeAt(i)]! >= 0)) throw new Error(`Invalid base32 character: ${input[i]}`);
  if (validateOnly) return new ArrayBuffer(0);
  // decode
  const out = new Uint8Array((input.length * 5) >> 3);
  let bits = 0,
    value = 0,
    pos = 0;
  for (let i = 0; i < input.length; i++) {
    value = (value << 5) | BASE32_DECODE[input.charCodeAt(i)];
    bits += 5;
    if (bits >= 8) {
      out[pos++] = (value >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return pos === out.length ? out.buffer : out.buffer.slice(0, pos);
}

async function updateTOTP(
  secret: HTMLInputElement | string,
  totpEl: HTMLDivElement,
  arc: SVGCircleElement,
  recalculate = false,
  copyBtn: HTMLButtonElement | null = null,
): Promise<void> {
  let secretEl: HTMLInputElement | null = null;
  let enigma: string;

  if (secret instanceof HTMLInputElement) {
    secretEl = secret;
    enigma = secret.value.trim();

    if (!enigma) {
      secretEl.classList.remove("valid", "invalid");
      arc.setAttribute("stroke-dashoffset", String(CIRC));
      return;
    }
  } else {
    enigma = secret;
  }

  const now = Date.now();

  // Always update animation ticker.
  const elapsed = (now / 1000) % 30;
  arc.setAttribute("stroke-dashoffset", String(CIRC * (elapsed / 30)));

  // Unless explicitly requested, only regenerate on a step boundary.
  const secondsRemaining = 30 - Math.floor(elapsed);
  if (!recalculate && secondsRemaining > 29) return;

  const step = Math.floor(now / 30_000);

  try {
    const keyBytes = base32Decode(enigma);

    const msg = new DataView(new ArrayBuffer(8));
    msg.setUint32(4, step, false);

    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);

    const sigBuf = await crypto.subtle.sign("HMAC", key, msg.buffer);
    const sig = new Uint8Array(sigBuf);

    const offset = sig[sig.length - 1] & 0x0f;

    const code =
      (((sig[offset] & 0x7f) << 24) |
        ((sig[offset + 1] & 0xff) << 16) |
        ((sig[offset + 2] & 0xff) << 8) |
        (sig[offset + 3] & 0xff)) %
      1_000_000;

    const totpStr = code.toString().padStart(6, "0");

    totpEl.textContent = `${totpStr.slice(0, 3)} ${totpStr.slice(3)}`;

    totpEl.classList.remove("empty");

    if (secretEl) {
      secretEl.classList.add("valid");
      secretEl.classList.remove("invalid");
    }

    if (copyBtn) {
      copyBtn.disabled = false;
    }
  } catch (error) {
    totpEl.textContent = BLANK_TOTP;
    totpEl.classList.add("empty");

    if (secretEl) {
      secretEl.classList.add("invalid");
      secretEl.classList.remove("valid");
    }

    if (copyBtn) {
      copyBtn.disabled = true;
    }

    arc.setAttribute("stroke-dashoffset", String(CIRC));
    throw error;
  }
}
// Crypto

type StoragePayload = { salt: string; iv: string; ct: string };
type Accounts = Map<string, string>;

const toHex = (b: Uint8Array): string =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const a = new Uint8Array(hex.length / 2);
  a.set(hex.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
  return a;
}

function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

async function deriveKey(password: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const raw = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 600_000, hash: "SHA-256" },
    raw,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptAccounts(key: CryptoKey, data: Accounts): Promise<{ iv: string; ct: string }> {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(JSON.stringify(Object.fromEntries(data))),
  );
  return { iv: toHex(iv), ct: toHex(new Uint8Array(ct)) };
}

async function decryptAccounts(key: CryptoKey, iv: string, ct: string): Promise<Accounts> {
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromHex(iv) }, key, fromHex(ct));
  return new Map(Object.entries(JSON.parse(new TextDecoder().decode(plain))));
}

async function writeVault(key: CryptoKey, salt: string, data: Accounts): Promise<void> {
  const { iv, ct } = await encryptAccounts(key, data);
  await chrome.storage.local.set({ vault: JSON.stringify({ salt, iv, ct }) });
}

// DOM refs
function mustGet<T extends Element>(selector: string, root: ParentNode = document): T {
  const el = root.querySelector<T>(selector);

  if (!el) {
    throw new Error(`Required element not found: "${selector}"`);
  }

  return el;
}
const mainScreen = mustGet<HTMLDivElement>("#main-screen");
const vaultScreen = mustGet<HTMLDivElement>("#vault-screen");
const vaultStatus = mustGet<HTMLSpanElement>("#vault-status-text");
const changePasswordScreen = mustGet<HTMLDivElement>("#change-password-screen");

const mainSecretEl = mustGet<HTMLInputElement>("#main-secret");
const mainTotpEl = mustGet<HTMLDivElement>("#main-totp");
const mainCopyBtn = mustGet<HTMLButtonElement>("#main-copy");
const mainArcEl = mustGet<SVGCircleElement>("#main-ring-arc");
const saveToVaultBtn = mustGet<HTMLButtonElement>("#save-to-vault");
const openVaultBtn = mustGet<HTMLButtonElement>("#open-vault");
const settingsBtn = mustGet<HTMLButtonElement>("#settings-btn");
const mainStatus = mustGet<HTMLSpanElement>("#statusbar-text");

const vaultPasswordOverlay = mustGet<HTMLDivElement>("#vault-pw-overlay");
const vaultPasswordTitle = mustGet<HTMLSpanElement>("#vault-pw-title");
const vaultPasswordHint = mustGet<HTMLSpanElement>("#vault-pw-hint");
const vaultPasswordInput = mustGet<HTMLInputElement>("#vault-pw-input");
const vaultPasswordConfirm = mustGet<HTMLInputElement>("#vault-pw-confirm");
const vaultPasswordErr = mustGet<HTMLDivElement>("#vault-pw-error");
const vaultPasswordSubmitBtn = mustGet<HTMLButtonElement>("#vault-pw-submit");
const vaultPasswordCancelBtn = mustGet<HTMLButtonElement>("#vault-pw-cancel");

const accountOverlay = mustGet<HTMLDivElement>("#account-overlay");
const accountNameEl = mustGet<HTMLInputElement>("#account-name");
const accountErr = mustGet<HTMLDivElement>("#account-error");
const accountSaveBtn = mustGet<HTMLButtonElement>("#account-save");
const accountCancelBtn = mustGet<HTMLButtonElement>("#account-cancel");

const vaultBack = mustGet<HTMLButtonElement>("#vault-back");
const vaultCount = mustGet<HTMLSpanElement>("#vault-count");
const vaultEntriesEl = mustGet<HTMLDivElement>("#vault-entries");
const newPasswordEl = mustGet<HTMLInputElement>("#new-password");
const confirmChgPasswordEl = mustGet<HTMLInputElement>("#confirm-password");
const confirmChgPasswordBtn = mustGet<HTMLButtonElement>("#confirm-change");
const cancelChangeBtn = mustGet<HTMLButtonElement>("#cancel-change");
const changeErr = mustGet<HTMLDivElement>("#change-error");
const copyBtnTpl = mustGet<HTMLTemplateElement>("#copy-btn-template");
const copyBtnTplTO = mustGet<HTMLTemplateElement>("#copy-btn-template-to");

// CONFIRM DIALOG
const confirmOverlay = mustGet<HTMLDivElement>("#confirm-overlay");
const confirmMessage = mustGet<HTMLSpanElement>("#confirm-message");
const confirmDelete = mustGet<HTMLButtonElement>("#confirm-delete");
const confirmCancel = mustGet<HTMLButtonElement>("#confirm-cancel");

function confirmDeleteDialog(name: string): Promise<boolean> {
  confirmMessage.textContent = `Delete "${name}"? This cannot be undone.`;

  confirmOverlay.classList.remove("hidden");

  return new Promise((resolve) => {
    const cleanup = () => {
      confirmOverlay.classList.add("hidden");

      confirmDelete.removeEventListener("click", onDelete);
      confirmCancel.removeEventListener("click", onCancel);
    };

    const onDelete = () => {
      cleanup();
      resolve(true);
    };

    const onCancel = () => {
      cleanup();
      resolve(false);
    };

    confirmDelete.addEventListener("click", onDelete, { once: true });
    confirmCancel.addEventListener("click", onCancel, { once: true });
  });
}
// Vault rendering

async function renderVault(): Promise<void> {
  vaultEntriesEl.innerHTML = "";
  vaultCount.textContent = String(accounts.size);

  for (const name of accounts.keys()) vaultEntriesEl.appendChild(createVaultEntry(name));

  await startTicker(vaultTicker, vaultStatus);
}

// Screen nav

type AppScreen = "main" | "vault" | "change-password";

async function showScreen(screen: AppScreen): Promise<void> {
  stopTicker();
  mainScreen.classList.remove("active");
  vaultScreen.classList.remove("active");
  changePasswordScreen.classList.remove("active");
  if (screen === "main") {
    mainScreen.classList.add("active");
    await startTicker(mainTicker, mainStatus);
  } else if (screen === "vault") {
    vaultScreen.classList.add("active");
    renderVault();
  } else if (screen === "change-password") {
    changePasswordScreen.classList.add("active");
    newPasswordEl.value = "";
    confirmChgPasswordEl.value = "";
    changeErr.textContent = "";
    newPasswordEl.focus();
  }
}

async function showMainScreen() {
  await showScreen("main");
}
async function showVaultScreen() {
  await showScreen("vault");
}
async function showPasswordChangeScreen() {
  await showScreen("change-password");
}

// Vault password overlay

type PasswordAction = "create" | "unlock";
let pwOnAuthenticated: (() => void) | null = null;

function showPasswordScreen(action: PasswordAction, onAuthenticated: () => void): void {
  pwOnAuthenticated = onAuthenticated;

  vaultPasswordInput.value = "";
  vaultPasswordConfirm.value = "";
  vaultPasswordErr.textContent = "";
  vaultPasswordOverlay.dataset.action = action;
  vaultPasswordOverlay.classList.add("active");

  if (action === "create") {
    vaultPasswordTitle.textContent = "Create vault password";
    vaultPasswordHint.textContent = "Your vault is new. Set a password to protect it.";
    vaultPasswordConfirm.style.display = "block";
    vaultPasswordSubmitBtn.textContent = "Create vault";
  } else {
    vaultPasswordTitle.textContent = "Unlock vault";
    vaultPasswordHint.textContent = "Enter your vault password to continue.";
    vaultPasswordConfirm.style.display = "none";
    vaultPasswordSubmitBtn.textContent = "Unlock";
  }
  vaultPasswordInput.focus();
}

function hideVaultPasswordOverlay(): void {
  vaultPasswordOverlay.classList.remove("active");
  pwOnAuthenticated = null;
}

// Vault

async function destroyVault() {
  await chrome.storage.local.remove("vault");
  sessionKey = null;
  sessionSalt = null;
  vaultExists = false;
  showScreen("main");
  isVaultEmpty();
}

async function openVault(): Promise<void> {
  const pw = vaultPasswordInput.value;
  vaultPasswordErr.textContent = "";

  if (!pw) {
    vaultPasswordErr.textContent = "Enter a password.";
    return;
  }

  if (vaultPasswordOverlay.dataset.action === "create") {
    const pw2 = vaultPasswordConfirm.value;
    if (pw !== pw2) {
      vaultPasswordErr.textContent = "Passwords do not match.";
      return;
    }
    const salt = randomBytes(16);
    sessionKey = await deriveKey(pw, salt);
    sessionSalt = toHex(salt);
    vaultExists = true;
  } else {
    try {
      const raw = await new Promise<string | null>(
        async (res) =>
          await chrome.storage.local.get("vault", (i) => res(typeof i["vault"] === "string" ? i["vault"] : null)),
      );
      if (!raw) {
        vaultPasswordErr.textContent = "Vault not found.";
        return;
      }
      const payload = JSON.parse(raw) as StoragePayload;
      sessionSalt = payload.salt;
      sessionKey = await deriveKey(pw, fromHex(payload.salt));
      accounts = await decryptAccounts(sessionKey, payload.iv, payload.ct);
    } catch {
      vaultPasswordErr.textContent = "Wrong password or corrupted vault.";
      return;
    }
  }

  const cb = pwOnAuthenticated;
  hideVaultPasswordOverlay();
  cb?.();
}

vaultPasswordSubmitBtn.addEventListener("click", () => openVault());
vaultPasswordInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    if (vaultPasswordOverlay.dataset.action === "create") vaultPasswordConfirm.focus();
    else openVault();
  }
});
vaultPasswordConfirm.addEventListener("keydown", (e) => {
  if (e.key === "Enter") openVault();
});
vaultPasswordCancelBtn.addEventListener("click", hideVaultPasswordOverlay);

accountCancelBtn.addEventListener("click", () => accountOverlay.classList.remove("active"));

// Main screen: live TOTP

mainSecretEl.addEventListener("input", () => {
  startTicker(mainTicker, mainStatus);
});

mainCopyBtn.addEventListener("click", () => {
  const raw = mainTotpEl.textContent ?? "";
  const code = raw.replace(/\s/g, "");
  if (!code || code.includes("—") || code === "Invalid") return;
  navigator.clipboard.writeText(code).then(() => {
    mainCopyBtn.classList.add("copied");
    mainCopyBtn.classList.add("icon");
    mainCopyBtn.innerHTML = "";
    mainCopyBtn.append(copyBtnTpl.content.cloneNode(true));
    setTimeout(() => {
      mainCopyBtn.classList.remove("copied");
      mainCopyBtn.classList.add("icon");
      mainCopyBtn.innerHTML = "";
      mainCopyBtn.append(copyBtnTplTO.content.cloneNode(true));
    }, 1500);
  });
});

// Account name overlay

async function showAccountOverlay(secret: string) {
  accountNameEl.value = "";
  accountErr.textContent = "";
  accountOverlay.classList.add("active");
  accountNameEl.focus();

  async function save() {
    const name = accountNameEl.value.trim();
    if (!name) {
      accountErr.textContent = "Enter an account name.";
      return;
    }
    if (accounts.has(name)) {
      accountErr.textContent = `"${name}" already exists in vault.`;
      return;
    }
    accountOverlay.classList.remove("active");
    accounts.set(name, secret);
    await writeVault(sessionKey!, sessionSalt!, accounts).then(() => {
      mainSecretEl.value = "";
      mainSecretEl.classList.remove("valid", "invalid");
      mainTotpEl.textContent = BLANK_TOTP;
      mainTotpEl.classList.add("empty");
      setStatus(mainStatus, `"${name}" saved to vault ✓`);
    });
    await showVaultScreen();
  }

  accountSaveBtn.onclick = save;
  accountNameEl.onkeydown = (e) => {
    if (e.key === "Enter") save();
  };
}

// Save to vault

saveToVaultBtn.addEventListener("click", () => {
  const secret = mainSecretEl.value.trim();
  if (!secret) {
    setStatus(mainStatus, "Enter a secret key first", true);
    return;
  }

  function showAccountScreen() {
    const secretConflict = [...accounts.entries()].find(([, s]) => s === secret);
    if (secretConflict) {
      setStatus(mainStatus, `Secret already saved as "${secretConflict[0]}"`, true);
      return;
    }
    showAccountOverlay(secret);
  }

  if (sessionKey && sessionSalt) {
    showAccountScreen();
  } else if (!vaultExists) {
    showPasswordScreen("create", showAccountScreen);
  } else {
    showPasswordScreen("unlock", showAccountScreen);
  }
});

// Open vault
function isVaultEmpty(): boolean {
  if (!vaultExists) {
    setStatus(mainStatus, "Vault is empty", true);
    return true;
  }
  return false;
}

openVaultBtn.addEventListener("click", async () => {
  if (isVaultEmpty()) return;

  if (sessionKey && sessionSalt) {
    await showVaultScreen();
    return;
  }
  await showPasswordScreen("unlock", showVaultScreen);
});

// Settings

settingsBtn.addEventListener("click", async () => {
  if (isVaultEmpty()) return;
  if (sessionKey && sessionSalt) {
    await showPasswordChangeScreen();
    return;
  }
  await showPasswordScreen("unlock", showPasswordChangeScreen);
});

// Status bar

function setStatus(statusBarEl: HTMLSpanElement, msg: string, isError = false, resetMsg: string = "Ready"): void {
  statusBarEl.textContent = msg;
  statusBarEl.style.color = isError ? "var(--danger)" : "var(--accent2)";
  setTimeout(() => {
    statusBarEl.textContent = resetMsg;
    statusBarEl.style.color = "";
  }, 3000);
}

function createVaultEntry(name: string): DocumentFragment {
  const tpl = document.getElementById("vault-entry-tpl") as HTMLTemplateElement;
  const frag = tpl.content.cloneNode(true) as DocumentFragment;

  const el = mustGet<HTMLDivElement>(".vault-entry", frag);
  const nameDiv = mustGet<HTMLDivElement>(".vault-entry-name", frag);
  const totpDiv = mustGet<HTMLDivElement>(".vault-entry-code", frag);
  const arc = mustGet<SVGCircleElement>(".ve-arc", frag);
  const copyBtn = mustGet<HTMLButtonElement>(".ve-btn.copy", frag);
  const editBtn = mustGet<HTMLButtonElement>(".ve-btn.edit", frag);
  const delBtn = mustGet<HTMLButtonElement>(".ve-btn.del", frag);

  el.dataset.name = name;
  nameDiv.textContent = name;
  arc.setAttribute("stroke-dasharray", String(CIRC));

  copyBtn.addEventListener("click", async () => {
    try {
      const raw = totpDiv.textContent ?? "";

      await navigator.clipboard.writeText(raw.replace(/\s/g, ""));

      copyBtn.classList.add("copied"); // Set checkmark
      copyBtn.classList.add("icon");
      copyBtn.innerHTML = "";
      copyBtn.append(copyBtnTpl.content.cloneNode(true));

      setTimeout(() => {
        copyBtn.classList.remove("copied"); // Remove checkmark after 1.5 sec
        copyBtn.classList.add("icon");
        copyBtn.innerHTML = "";
        copyBtn.append(copyBtnTplTO.content.cloneNode(true));
      }, 1500);
    } catch (err) {
      setStatus(vaultStatus, `Failed to copy text: ${err}`, true, "");
    }
  });

  delBtn.addEventListener("click", async () => {
    if (!sessionKey || !sessionSalt) return;
    if (!(await confirmDeleteDialog(name))) return;

    accounts.delete(name);

    if (accounts.size === 0) {
      destroyVault();
      return;
    }

    await writeVault(sessionKey, sessionSalt, accounts);
    el.remove();
  });

  editBtn.addEventListener("click", async () => {
    const editTpl = document.getElementById("vault-entry-edit-tpl") as HTMLTemplateElement;
    const fragEdit = editTpl.content.cloneNode(true) as DocumentFragment;
    const editForm = mustGet<HTMLDivElement>(".vault-edit-form", fragEdit);
    stopTicker();
    document.querySelectorAll<HTMLDivElement>(".vault-entry").forEach((e) => {
      if (el !== e) e.classList.add("hidden");
    });

    async function exitEdit() {
      // editForm.classList.add("hidden");
      editForm.remove();
      document.querySelectorAll<HTMLDivElement>(".vault-entry").forEach((e) => {
        e.classList.remove("hidden");
      });
      startTicker(vaultTicker, vaultStatus);
    }

    const editNameInput = mustGet<HTMLInputElement>(".edit-name-input", editForm);
    const editSecretInput = mustGet<HTMLInputElement>(".edit-secret-input", editForm);
    const editErr = mustGet<HTMLDivElement>(".vault-edit-error", editForm);
    const cancelEdit = mustGet<HTMLButtonElement>(".cancel-edit", editForm);
    const saveEdit = mustGet<HTMLButtonElement>(".save-edit", editForm);

    el.after(editForm);
    editForm.classList.remove("hidden");

    editNameInput.value = name;
    editSecretInput.value = accounts.get(name) ?? "";
    editErr.textContent = "";
    editNameInput.focus();

    cancelEdit.addEventListener("click", exitEdit);

    saveEdit.addEventListener("click", async () => {
      const secret = accounts.get(name) ?? "";
      const newName = editNameInput.value.trim();
      const newSecret = editSecretInput.value.trim();

      if (!newName) return (editErr.textContent = "Name is required.");
      if (!newSecret) return (editErr.textContent = "Secret is required.");
      if (newName === name && newSecret === secret) return (editErr.textContent = "No change.");
      if (newName !== name && accounts.has(newName))
        return (editErr.textContent = `"${newName}" already exists in vault.`);

      try {
        base32Decode(newSecret, true);
      } catch (e) {
        return (editErr.textContent = (e as Error).message);
      }

      if (newName !== name) {
        accounts.delete(name);
        el.dataset.name = newName;
        nameDiv.textContent = newName;
      }

      accounts.set(newName, newSecret);

      await writeVault(sessionKey!, sessionSalt!, accounts);

      await updateOnlyThatEntry(newName);

      await exitEdit();
    });
  });

  return frag;
}

async function updateOnlyThatEntry(name: string): Promise<void> {
  const el = vaultEntriesEl.querySelector<HTMLDivElement>(`.vault-entry[data-name="${CSS.escape(name)}"]`);

  if (!el) return;

  const secret = accounts.get(name);
  if (!secret) return;

  const totpEl = mustGet<HTMLDivElement>(".vault-entry-code", el);
  const arc = mustGet<SVGCircleElement>(".ve-arc", el);
  const copyBtn = mustGet<HTMLButtonElement>(".ve-btn.copy", el);
  await updateTOTP(secret, totpEl, arc, true, copyBtn);
}

vaultBack.addEventListener("click", () => {
  stopTicker();
  showScreen("main");
});

// Change password
cancelChangeBtn.addEventListener("click", showMainScreen);

confirmChgPasswordBtn.addEventListener("click", async () => {
  if (!sessionSalt) return;
  const np = newPasswordEl.value,
    cp = confirmChgPasswordEl.value;
  changeErr.textContent = "";
  if (!np) {
    changeErr.textContent = "New password is required.";
    return;
  }
  if (np !== cp) {
    changeErr.textContent = "Passwords do not match.";
    return;
  }
  try {
    const newSalt = randomBytes(16);
    sessionKey = await deriveKey(np, newSalt);
    sessionSalt = toHex(newSalt);
    await writeVault(sessionKey, sessionSalt, accounts);
    await showMainScreen();
  } catch {
    changeErr.textContent = "Failed to change password.";
  }
});

// State

let sessionKey: CryptoKey | null = null;
let sessionSalt: string | null = null;
let accounts: Accounts = new Map();
let vaultExists = false;
let intervalId: ReturnType<typeof setInterval> | null = null;

async function mainTicker(recalculate: boolean = false): Promise<void> {
  if (!mainScreen.classList.contains("active")) return;
  await updateTOTP(mainSecretEl, mainTotpEl, mainArcEl, recalculate, mainCopyBtn);
}

async function vaultTicker(recalculate: boolean = false): Promise<void> {
  if (!vaultScreen.classList.contains("active")) return;
  for (const [name, secret] of accounts) {
    const el = vaultEntriesEl.querySelector<HTMLDivElement>(`.vault-entry[data-name="${CSS.escape(name)}"]`);
    if (!el) continue;
    const arc = mustGet<SVGCircleElement>(".ve-arc", el);
    const totpEl = mustGet<HTMLDivElement>(".vault-entry-code", el);
    const copyBtn = mustGet<HTMLButtonElement>(".ve-btn.copy", el);
    await updateTOTP(secret, totpEl, arc, recalculate, copyBtn);
  }
}

function stopTicker() {
  if (intervalId !== null) {
    clearInterval(intervalId);
    intervalId = null;
  }
}

async function startTicker(ticker: (recalculate: boolean) => Promise<void>, statusEl: HTMLSpanElement) {
  stopTicker();

  const handleTickerError = (err: unknown) => {
    setStatus(statusEl, `${String(err)}`, true);
  };

  try {
    await ticker(true);
    intervalId = setInterval(async () => {
      await ticker(false).catch(handleTickerError);
    }, 1000);
  } catch (err) {
    handleTickerError(err);
  }
}

// Startup

chrome.storage.local.get("vault", (items) => {
  vaultExists = typeof items["vault"] === "string";
});

showMainScreen();
