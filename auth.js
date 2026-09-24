/* =========================================================
   PROJECT : College Student Information Portal
   COLLEGE : Uttaranchal University
   FILE    : auth.js  (Sign In / Create Account + JWT login)
   TECH    : Pure JavaScript — no libraries, no backend
   PURPOSE :
     - The navbar "Sign In" button opens a small popup.
     - The user can Sign In (existing account) or Create Account.
     - On success a signed JWT (HS256) is generated and saved.
     - The navbar then swaps "Sign In" for the logged-in user
       chip (avatar initial + name) with a Logout option.
     - If the JWT is expired or the signature is wrong, the
       user is treated as logged out (session check).
   NOTE    : In a real production site the JWT would be SIGNED
             and VERIFIED on a server. This demo does both in
             the browser so the whole flow runs offline, with
             no external libraries required.
   --------------------------------------------------------- */
(function () {
  "use strict";

  /* ======================================================
     1) JWT (HS256) implementation in pure JavaScript
        A JWT looks like:  header.payload.signature
        - header    : JSON saying which algorithm is used
        - payload   : JSON data (email, name, expiry time)
        - signature : HMAC-SHA256 of "header.payload" made
                      with a secret key (cannot be faked)
     ====================================================== */

  // Demo secret. Change it once; all tokens become invalid. */
  const JWT_SECRET = "uttaranchal-university-demo-secret-2026";

  // TextEncoder converts JS strings into UTF-8 bytes.
  const T_ENCODER = new TextEncoder();

  // ---- base64url helpers (JWT uses -_ instead of +/ and no padding) ----

  // bytes -> base64url string
  function bytesToB64url(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // JS string -> base64url string
  function strToB64url(str) {
    return bytesToB64url(T_ENCODER.encode(str));
  }

  // base64url string -> bytes
  function b64urlToBytes(str) {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";              // restore padding
    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  // base64url string -> JS string
  function b64urlToStr(str) {
    return new TextDecoder().decode(b64urlToBytes(str));
  }

  // hex string (2 chars per byte) -> "byte string" (1 char per byte)
  // used so sha256/hmac can work on pure byte strings
  function hexToBytesStr(hex) {
    let s = "";
    for (let i = 0; i < hex.length; i += 2) {
      s += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return s;
  }

  // ---- SHA-256: takes an ASCII "byte string", returns a hex digest ----
  // (compact implementation; only characters 0-255 are supported,
  //  which is exactly what HMAC/base64 inputs give us)
  function sha256(ascii) {
    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }
    const maxWord = Math.pow(2, 32);
    let result = "";
    const words = [];
    const asciiBitLength = ascii.length * 8;
    let hash = [];
    let k = [];
    let primeCounter = 0;
    const isComposite = {};

    // Generate the 64 constant words (from cube/square roots of primes)
    for (let candidate = 2; primeCounter < 64; candidate++) {
      if (!isComposite[candidate]) {
        for (let i = 0; i < 313; i += candidate) isComposite[i] = candidate;
        hash[primeCounter] = (Math.pow(candidate, 0.5) * maxWord) | 0;
        k[primeCounter++] = (Math.pow(candidate, 1 / 3) * maxWord) | 0;
      }
    }

    // Pad the message: append 1-bit + zeros, then the 64-bit bit length
    ascii += "\x80";
    while ((ascii.length % 64) - 56) ascii += "\x00";
    for (let i = 0; i < ascii.length; i++) {
      const j = ascii.charCodeAt(i);
      if (j >> 8) return;                          // only bytes 0-255 allowed
      words[i >> 2] |= j << (((3 - i) % 4) * 8);
    }
    words[words.length] = Math.floor(asciiBitLength / maxWord);
    words[words.length] = asciiBitLength;

    // Main compression loop (64 rounds over 16-word blocks)
    for (let j = 0; j < words.length; ) {
      const w = words.slice(j, (j += 16));
      const oldHash = hash.slice(0);
      hash = hash.slice(0, 8);
      for (let i = 0; i < 64; i++) {
        const w15 = w[i - 15];
        const w2 = w[i - 2];
        const a = hash[0];
        const e = hash[4];
        const temp1 =
          hash[7] +
          (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) +
          ((e & hash[5]) ^ (~e & hash[6])) +
          k[i] +
          (w[i] =
            i < 16
              ? w[i]
              : (w[i - 16] +
                  (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) +
                  w[i - 7] +
                  (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))) |
                0);
        const temp2 =
          (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) +
          ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
        hash = [(temp1 + temp2) | 0].concat(hash);
        hash[4] = (hash[4] + temp1) | 0;
      }
      for (let i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
    }

    // Convert the 8 working values into a 64-character hex string
    for (let i = 0; i < 8; i++) {
      for (let j = 3; j + 1; j--) {
        const b = (hash[i] >> (j * 8)) & 255;
        result += (b < 16 ? "0" : "") + b.toString(16);
      }
    }
    return result;
  }

  // ---- HMAC-SHA256 (key + message as byte strings, returns hex) ----
  function hmacSha256(key, message) {
    const blockSize = 64;
    if (key.length > blockSize) key = hexToBytesStr(sha256(key)); // shorten long keys
    while (key.length < blockSize) key += "\x00";                  // pad to 64 bytes

    let opad = "", ipad = "";
    for (let i = 0; i < blockSize; i++) {
      opad += String.fromCharCode(key.charCodeAt(i) ^ 0x5c);       // outer pad 0x5c
      ipad += String.fromCharCode(key.charCodeAt(i) ^ 0x36);       // inner pad 0x36
    }
    return sha256(opad + hexToBytesStr(sha256(ipad + message)));
  }

  // ---- Sign a JWT (returns "header.payload.signature") ----
  // payload: object like { sub, name, role } ; token lives 2 hours
  function signJwt(payload) {
    const header = { alg: "HS256", typ: "JWT" };
    const now = Math.floor(Date.now() / 1000);                     // current time (secs)
    const body = Object.assign({ iat: now, exp: now + 2 * 3600 }, payload);
    const input = strToB64url(JSON.stringify(header)) + "." + strToB64url(JSON.stringify(body));
    const sig = bytesToB64url(hexToBytesStr(hmacSha256(JWT_SECRET, input)));
    return input + "." + sig;
  }

  // ---- Verify a JWT: returns the payload if valid, otherwise null ----
  function verifyJwt(token) {
    if (!token) return null;
    const parts = token.split(".");
    if (parts.length !== 3) return null;                           // malformed

    // 1) Recompute the signature with the secret and compare it
    const expected = bytesToB64url(hexToBytesStr(hmacSha256(JWT_SECRET, parts[0] + "." + parts[1])));
    if (expected !== parts[2]) return null;                        // signature mismatch

    // 2) Check the expiry time ("exp")
    let payload = null;
    try { payload = JSON.parse(b64urlToStr(parts[1])); } catch (e) { return null; }
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  }

  /* ======================================================
     2) USER ACCOUNTS  (stored in the browser's localStorage)
        Passwords are NOT saved in plain text — only their
        SHA-256 hash is stored (salted with the email).
     ====================================================== */
  const USERS_KEY = "uu_users";     // key for the accounts list
  const TOKEN_KEY = "uu_token";     // key for the signed JWT

  // Hash a password (salted with the email) -> hex string
  function hashPassword(email, password) {
    return sha256(strToB64url(email) + ":" + strToB64url(password));
  }

  function getUsers() {
    try { return JSON.parse(localStorage.getItem(USERS_KEY)) || []; }
    catch (e) { return []; }
  }

  function saveUsers(list) {
    localStorage.setItem(USERS_KEY, JSON.stringify(list));
  }

  // Create a demo account the first time so the site is ready to try
  function seedDemoUser() {
    const users = getUsers();
    if (!users.some((u) => u.email === "admin@uttaranchal.edu")) {
      users.push({
        name: "Admin User",
        email: "admin@uttaranchal.edu",
        pass: hashPassword("admin@uttaranchal.edu", "admin123"),
      });
      saveUsers(users);
    }
  }

  /* ======================================================
     3) POPUP / FORM UI
     ====================================================== */
  const $ = (id) => document.getElementById(id);

  const overlay = $("authOverlay");
  const authBtn = $("authBtn");
  const chip = $("userChip");
  const userMenu = $("userMenu");

  // Tiny helper to read an error <p> by its data-err name
  function setError(which, msg) {
    document.querySelectorAll(".auth-error").forEach((p) => (p.textContent = ""));
    if (!which) return;
    const el = document.querySelector('[data-err="' + which + '"]');
    if (el) el.textContent = msg || "";
  }

  // Basic email format check
  function isEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
  }

  // Small toast notification at the bottom of the screen
  let toastTimer = null;
  function showToast(msg) {
    const toast = $("toast");
    toast.textContent = msg;
    toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("show"), 2600);
  }

  // ---- Open / close the popup ----
  function openAuth() {
    overlay.classList.add("open");
    document.body.style.overflow = "hidden";     // lock background scrolling
    setError(null);
    // Focus the first field for quick typing
    setTimeout(() => { ($("loginEmail") || $("signupName")).focus(); }, 150);
  }

  function closeAuth() {
    overlay.classList.remove("open");
    document.body.style.overflow = "";
  }

  // ---- Update the navbar depending on login state ----
  function updateAuthUI() {
    const payload = verifyJwt(localStorage.getItem(TOKEN_KEY));
    if (payload) {
      authBtn.hidden = true;                     // hide "Sign In"
      $("userAvatar").textContent = (payload.name || "U").charAt(0).toUpperCase();
      $("userName").textContent = payload.name || "User";
      chip.hidden = false;                       // show the user chip
      chip.classList.remove("open");             // close any open menu
    } else {
      localStorage.removeItem(TOKEN_KEY);        // clean up bad/session tokens
      authBtn.hidden = false;
      chip.hidden = true;
    }
  }

  /* ======================================================
     4) EVENT LISTENERS
     ====================================================== */

  // Sign In button in the navbar opens the popup
  authBtn.addEventListener("click", openAuth);

  // Close via the X button, clicking the dark backdrop, or Escape key
  $("authClose").addEventListener("click", closeAuth);
  overlay.addEventListener("click", (e) => { if (e.target === overlay) closeAuth(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeAuth(); });

  // Tabs: switch between "Sign In" and "Create Account"
  const tabs = document.querySelectorAll(".auth-tab");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const go = tab.dataset.tab;
      tabs.forEach((t) => t.classList.toggle("active", t === tab));
      $("loginForm").hidden = go !== "login";
      $("signupForm").hidden = go !== "signup";
      $("authTitle").textContent = go === "login" ? "Sign In" : "Create Account";
      setError(null);
    });
  });

  // Show / Hide password buttons (👁 would be nice but we keep it text-only)
  document.querySelectorAll(".pwd-toggle").forEach((btn) => {
    btn.addEventListener("click", () => {
      const input = $(btn.dataset.for);
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "Hide" : "Show";
    });
  });

  // ---- SIGN IN ----
  $("loginForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const email = $("loginEmail").value.trim().toLowerCase();
    const pass = $("loginPass").value;
    const err = (m) => setError("login", m);

    if (!email || !pass) return err("Please fill in both fields.");
    if (!isEmail(email)) return err("That email address looks invalid.");

    const users = getUsers();
    const user = users.find((u) => u.email === email);
    if (!user || user.pass !== hashPassword(email, pass)) {
      return err("Invalid email or password.");
    }

    // Success -> create the JWT and store it
    localStorage.setItem(TOKEN_KEY, signJwt({ sub: email, name: user.name, role: "student" }));
    $("loginForm").reset();
    closeAuth();
    updateAuthUI();
    showToast("Welcome back, " + user.name + "!");
  });

  // ---- CREATE ACCOUNT ----
  $("signupForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const name = $("signupName").value.trim();
    const email = $("signupEmail").value.trim().toLowerCase();
    const pass = $("signupPass").value;
    const err = (m) => setError("signup", m);

    if (!name) return err("Please enter your name.");
    if (!isEmail(email)) return err("Please enter a valid email address.");
    if (pass.length < 6) return err("Password must be at least 6 characters.");

    const users = getUsers();
    if (users.some((u) => u.email === email)) {
      return err("An account with this email already exists.");
    }

    // Store the new account (only the password hash, never plain text)
    users.push({ name: name, email: email, pass: hashPassword(email, pass) });
    saveUsers(users);

    // Auto-login after signup with a fresh JWT
    localStorage.setItem(TOKEN_KEY, signJwt({ sub: email, name: name, role: "student" }));
    $("signupForm").reset();
    closeAuth();
    updateAuthUI();
    showToast("Account created. Welcome, " + name + "!");
  });

  // ---- LOGOUT (from the user chip menu) ----
  $("logoutBtn").addEventListener("click", (e) => {
    e.preventDefault();
    localStorage.removeItem(TOKEN_KEY);
    chip.classList.remove("open");
    updateAuthUI();
    showToast("You have been logged out.");
  });

  // The user chip opens/closes its small menu
  chip.addEventListener("click", (e) => {
    if (userMenu.contains(e.target)) return;      // let the menu items work
    chip.classList.toggle("open");
    e.stopPropagation();
  });
  document.addEventListener("click", () => chip.classList.remove("open"));
  chip.addEventListener("mouseleave", () => chip.classList.remove("open"));

  /* ======================================================
     5) PAGE LOAD  (runs on every page)
     ====================================================== */
  function init() {
    seedDemoUser();       // make sure the demo account exists
    setError(null);       // clear placeholder error text
    updateAuthUI();       // show Sign In button OR the user chip
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();