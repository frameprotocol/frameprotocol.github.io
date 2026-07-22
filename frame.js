/* FRAME instance + identity model — stored in the browser (localStorage). */
window.FRAME = (function () {
  var LS_IDS = "frame.identities";
  var LS_ACTIVE = "frame.activeId";
  var SS_UNLOCKED = "frame.unlocked"; // sessionStorage: identity id unlocked this session
  var LS_OLD = "frame.instance";      // legacy single-identity key
  var LS_FRAME = "frame.shell";       // this FRAME instance (renamable id + stable uid)

  function readJSON(store, key) {
    try { return JSON.parse(store.getItem(key) || "null"); } catch (e) { return null; }
  }

  function getIdentities() {
    var arr = readJSON(localStorage, LS_IDS);
    if (Array.isArray(arr)) return arr;
    // Migrate a legacy single instance into the list.
    var old = readJSON(localStorage, LS_OLD);
    if (old && old.frameId) {
      arr = [old];
      try {
        localStorage.setItem(LS_IDS, JSON.stringify(arr));
        localStorage.setItem(LS_ACTIVE, old.frameId);
        localStorage.removeItem(LS_OLD);
      } catch (e) {}
      return arr;
    }
    return [];
  }

  function saveIdentities(arr) {
    try { localStorage.setItem(LS_IDS, JSON.stringify(arr)); } catch (e) {}
  }

  function getActiveId() { return localStorage.getItem(LS_ACTIVE); }

  function setActiveId(id) {
    try {
      if (id) localStorage.setItem(LS_ACTIVE, id);
      else localStorage.removeItem(LS_ACTIVE);
    } catch (e) {}
  }

  function getById(id) {
    var list = getIdentities();
    for (var i = 0; i < list.length; i++) if (list[i].frameId === id) return list[i];
    return null;
  }

  function getActive() { return getById(getActiveId()); }

  function updateIdentity(obj) {
    var arr = getIdentities();
    for (var i = 0; i < arr.length; i++) {
      if (arr[i].frameId === obj.frameId) { arr[i] = obj; break; }
    }
    saveIdentities(arr);
  }

  function addIdentity(obj) {
    var arr = getIdentities();
    arr.push(obj);
    saveIdentities(arr);
  }

  function removeIdentity(id) {
    var arr = getIdentities().filter(function (x) { return x.frameId !== id; });
    saveIdentities(arr);
    if (getActiveId() === id) setActiveId(arr.length ? arr[0].frameId : null);
    if (sessionStorage.getItem(SS_UNLOCKED) === id) lockSession();
  }

  function randomDigits(n) {
    var s = "";
    for (var i = 0; i < n; i++) s += Math.floor(Math.random() * 10);
    return s;
  }

  function randomAlnum(n) {
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    var out = "";
    var arr = (window.crypto && crypto.getRandomValues)
      ? crypto.getRandomValues(new Uint32Array(n)) : null;
    for (var i = 0; i < n; i++) {
      var r = arr ? arr[i] % chars.length : Math.floor(Math.random() * chars.length);
      out += chars.charAt(r);
    }
    return out;
  }

  /* --- This FRAME (instance): own renamable id + stable uid --- */
  function saveFrame(f) {
    try { localStorage.setItem(LS_FRAME, JSON.stringify(f)); } catch (e) {}
  }
  function getFrame() {
    var f = readJSON(localStorage, LS_FRAME);
    if (f && typeof f.uid === "string" && typeof f.id === "string" && f.uid && f.id) return f;
    // Migrate old "label on active identity" into a real FRAME record.
    var active = null;
    try { active = getActive(); } catch (e) {}
    var migratedId = (active && active.label) ? String(active.label) : "Frame:1";
    f = {
      uid: "frame_" + randomAlnum(20).toLowerCase(),
      id: migratedId,
      createdAt: new Date().toISOString()
    };
    saveFrame(f);
    // Clear identity labels — FRAME name is no longer stored on identities.
    try {
      getIdentities().forEach(function (ident) {
        if (ident && ident.label != null) {
          delete ident.label;
          updateIdentity(ident);
        }
      });
    } catch (e) {}
    return f;
  }
  function setFrameId(newId) {
    newId = String(newId || "").trim();
    if (!newId) throw new Error("FRAME id cannot be empty");
    if (newId.length > 48) newId = newId.slice(0, 48);
    var f = getFrame();
    f.id = newId;
    f.updatedAt = new Date().toISOString();
    saveFrame(f);
    return f;
  }

  /* --- Real cryptographic identity (mirrors frame ui/src/crypto.ts) --- */
  function bufToB64(buf) {
    var a = new Uint8Array(buf), s = "";
    for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s);
  }
  function bufToHex(buf) {
    var a = new Uint8Array(buf), s = "";
    for (var i = 0; i < a.length; i++) s += a[i].toString(16).padStart(2, "0");
    return s;
  }
  function packKeyMaterial(alg, b64) {
    var tag = alg === "Ed25519" ? "ed25519" : "p256";
    return "v1:" + tag + ":" + b64;
  }
  function hashHex(str) {
    return crypto.subtle.digest("SHA-256", new TextEncoder().encode(str)).then(bufToHex);
  }
  // Short stable id from packed public key material: fid_<first 32 hex of sha256>.
  function deriveIdentityId(publicKey) {
    return hashHex(publicKey).then(function (h) { return "fid_" + h.slice(0, 32); });
  }
  function supportsEd25519() {
    try {
      return crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])
        .then(function (k) { return !!k.publicKey; })
        .catch(function () { return false; });
    } catch (e) { return Promise.resolve(false); }
  }
  function generateKeypair() {
    return supportsEd25519().then(function (ok) {
      if (ok) {
        return crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]).then(function (pair) {
          return Promise.all([
            crypto.subtle.exportKey("raw", pair.publicKey),
            crypto.subtle.exportKey("pkcs8", pair.privateKey)
          ]).then(function (r) {
            return { publicKey: packKeyMaterial("Ed25519", bufToB64(r[0])), privateKey: packKeyMaterial("Ed25519", bufToB64(r[1])) };
          });
        });
      }
      return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]).then(function (pair) {
        return Promise.all([
          crypto.subtle.exportKey("spki", pair.publicKey),
          crypto.subtle.exportKey("pkcs8", pair.privateKey)
        ]).then(function (r) {
          return { publicKey: packKeyMaterial("ECDSA-P256", bufToB64(r[0])), privateKey: packKeyMaterial("ECDSA-P256", bufToB64(r[1])) };
        });
      });
    });
  }

  // Build (but do not store) a new identity object with a real keypair + fid_ id.
  function buildIdentity(passcode) {
    return generateKeypair().then(function (kp) {
      return deriveIdentityId(kp.publicKey).then(function (id) {
        var obj = {
          frameId: id,
          publicKey: kp.publicKey,
          privateKey: kp.privateKey,
          recoveryKey: randomAlnum(17),
          passcode: null,
          wallets: [],
          activeWalletId: null,
          settings: { maxAttempts: 5, onLimit: "lock" },
          failedAttempts: 0,
          locked: false,
          createdAt: new Date().toISOString()
        };
        if (!passcode) return obj;
        return hashPasscode(passcode).then(function (h) { obj.passcode = h; return obj; });
      });
    });
  }

  // Async: create + store a real identity. Returns a Promise<identity>.
  function createIdentity(passcode) {
    return buildIdentity(passcode).then(function (obj) { addIdentity(obj); return obj; });
  }

  /* --- Passcode hashing (FRAME_PASSCODE_V1) --- */
  function hashPasscode(pin) {
    return hashHex("frame.passcode.v1:" + String(pin || "")).then(function (h) {
      return "v1:sha256:" + h;
    });
  }
  function isHashedPasscode(p) {
    return typeof p === "string" && /^v1:sha256:[0-9a-f]{64}$/i.test(p);
  }
  function verifyPasscode(ident, pin) {
    if (!ident || !ident.passcode) return Promise.resolve(true);
    if (isHashedPasscode(ident.passcode)) {
      return hashPasscode(pin).then(function (h) { return h === ident.passcode; });
    }
    // Legacy plaintext: accept once, then migrate to hash.
    if (String(ident.passcode) === String(pin)) {
      return hashPasscode(pin).then(function (h) {
        ident.passcode = h;
        updateIdentity(ident);
        return true;
      });
    }
    return Promise.resolve(false);
  }
  function setPasscode(ident, pin) {
    if (!ident) return Promise.reject(new Error("no identity"));
    if (!pin) {
      ident.passcode = null;
      updateIdentity(ident);
      return Promise.resolve(ident);
    }
    return hashPasscode(pin).then(function (h) {
      ident.passcode = h;
      updateIdentity(ident);
      return ident;
    });
  }

  /* --- Export / import identity --- */
  function exportIdentity(id) {
    var ident = getById(id || getActiveId());
    if (!ident) return null;
    return {
      format: "frame.identity.v1",
      exportedAt: new Date().toISOString(),
      identity: {
        frameId: ident.frameId,
        publicKey: ident.publicKey || null,
        privateKey: ident.privateKey || null,
        recoveryKey: ident.recoveryKey || null,
        wallets: Array.isArray(ident.wallets) ? ident.wallets : [],
        activeWalletId: ident.activeWalletId || null,
        settings: ident.settings || { maxAttempts: 5, onLimit: "lock" },
        createdAt: ident.createdAt || new Date().toISOString()
      }
    };
  }
  function importIdentity(raw) {
    var data = raw;
    if (typeof raw === "string") {
      try { data = JSON.parse(raw); } catch (e) { return Promise.reject(new Error("invalid JSON")); }
    }
    if (!data || data.format !== "frame.identity.v1" || !data.identity) {
      return Promise.reject(new Error("unsupported identity package"));
    }
    var src = data.identity;
    if (!src.frameId || typeof src.frameId !== "string") {
      return Promise.reject(new Error("missing frameId"));
    }
    if (getById(src.frameId)) {
      return Promise.reject(new Error("identity already on this device"));
    }
    var obj = {
      frameId: src.frameId,
      publicKey: src.publicKey || null,
      privateKey: src.privateKey || null,
      recoveryKey: src.recoveryKey || randomAlnum(17),
      passcode: null,
      wallets: Array.isArray(src.wallets) ? src.wallets : [],
      activeWalletId: src.activeWalletId || null,
      settings: src.settings || { maxAttempts: 5, onLimit: "lock" },
      failedAttempts: 0,
      locked: false,
      createdAt: src.createdAt || new Date().toISOString()
    };
    addIdentity(obj);
    return Promise.resolve(obj);
  }

  /* FRAME instance package: the clonable shell (no identity secrets). */
  function exportFrame() {
    var shell = getFrame();
    var dapps = [];
    try {
      for (var i = 0; i < localStorage.length; i++) {
        var k = localStorage.key(i);
        if (!k || k.indexOf("frame.dapp.") !== 0) continue;
        var raw = localStorage.getItem(k);
        var parsed = null;
        try { parsed = JSON.parse(raw); } catch (e) { parsed = { raw: raw }; }
        if (parsed && typeof parsed === "object") {
          delete parsed.signature;
          delete parsed.signedBy;
          delete parsed.sigAlg;
          delete parsed.sigScheme;
        }
        dapps.push({ key: k, value: parsed });
      }
    } catch (e) {}
    return {
      format: "frame.instance.v1",
      exportedAt: new Date().toISOString(),
      frame: {
        uid: shell.uid,
        id: shell.id,
        createdAt: shell.createdAt || null,
        note: "A FRAME has its own renamable id. Cloning does not copy identities; identity ids (fid_…) are permanent and hold keys/wallets."
      },
      dapps: dapps
    };
  }
  function importFrame(raw) {
    var data = raw;
    if (typeof raw === "string") {
      try { data = JSON.parse(raw); } catch (e) { return Promise.reject(new Error("invalid JSON")); }
    }
    if (!data || data.format !== "frame.instance.v1") {
      return Promise.reject(new Error("unsupported FRAME package"));
    }
    try {
      var shell = getFrame();
      if (data.frame) {
        if (data.frame.id) shell.id = String(data.frame.id).trim() || shell.id;
        // Keep local uid unless missing; clone should get a new uid so it's a new instance.
        shell.uid = "frame_" + randomAlnum(20).toLowerCase();
        shell.updatedAt = new Date().toISOString();
        if (data.frame.createdAt) shell.clonedFrom = data.frame.uid || data.frame.id;
        saveFrame(shell);
      }
      (data.dapps || []).forEach(function (row) {
        if (!row || !row.key || row.key.indexOf("frame.dapp.") !== 0) return;
        localStorage.setItem(row.key, JSON.stringify(row.value || {}));
      });
    } catch (e) {
      return Promise.reject(new Error("could not import FRAME"));
    }
    return Promise.resolve(data);
  }

  /* --- Page gate: ensure an unlocked active identity, else redirect --- */
  function gate(opts) {
    opts = opts || {};
    var home = opts.home || "/dapps.html";
    var unlock = opts.unlock || "/unlock.html";
    try {
      var idents = getIdentities();
      if (idents.length === 0) {
        return createIdentity(null).then(function (created) {
          setActiveId(created.frameId);
          markUnlocked(created.frameId);
          ensureDefaultGrants(created.frameId);
          return created;
        });
      }
      var active = getActive();
      if (!active) {
        setActiveId(idents[0].frameId);
        active = getActive();
      }
      if (!active) { window.location.replace(home); return Promise.resolve(null); }
      if (!isUnlocked(active.frameId)) {
        window.location.replace(unlock);
        return Promise.resolve(null);
      }
      ensureDefaultGrants(active.frameId);
      return Promise.resolve(active);
    } catch (e) {
      return Promise.resolve(null);
    }
  }

  /* --- FRAME_SIGNATURE_V1 (mirrors frame ui/src/crypto.ts signDigest/verifyDigest) ---
     Ed25519 over the RAW SHA-256 digest bytes of the payload; base64 signature.
     ECDSA-P256 is a best-effort local fallback (hashes internally). */
  function b64ToBuf(b64) {
    var bin = atob(b64), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function unpackKeyMaterial(packed) {
    var m = /^v1:(ed25519|p256):(.+)$/i.exec((packed || "").trim());
    if (!m) return null;
    return { alg: m[1].toLowerCase() === "ed25519" ? "Ed25519" : "ECDSA-P256", b64: m[2] };
  }
  function sha256Bytes(str) {
    return crypto.subtle.digest("SHA-256", new TextEncoder().encode(str)).then(function (b) { return new Uint8Array(b); });
  }
  function importPriv(alg, b64) {
    var buf = b64ToBuf(b64);
    if (alg === "Ed25519") return crypto.subtle.importKey("pkcs8", buf, { name: "Ed25519" }, false, ["sign"]);
    return crypto.subtle.importKey("pkcs8", buf, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  }
  function importPub(alg, b64) {
    var buf = b64ToBuf(b64);
    if (alg === "Ed25519") return crypto.subtle.importKey("raw", buf, { name: "Ed25519" }, true, ["verify"]);
    return crypto.subtle.importKey("spki", buf, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  }
  function signDigest(privateKey, digest) {
    var u = unpackKeyMaterial(privateKey);
    if (!u) return Promise.reject(new Error("signDigest: invalid private key material"));
    return importPriv(u.alg, u.b64).then(function (k) {
      if (u.alg === "Ed25519") return crypto.subtle.sign("Ed25519", k, digest);
      return crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k, digest);
    }).then(bufToB64);
  }
  function verifyDigest(publicKey, digest, sigB64) {
    var u = unpackKeyMaterial(publicKey);
    if (!u) return Promise.resolve(false);
    return importPub(u.alg, u.b64).then(function (k) {
      var sig = b64ToBuf(sigB64);
      if (u.alg === "Ed25519") return crypto.subtle.verify("Ed25519", k, sig, digest);
      return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, k, sig, digest);
    }).catch(function () { return false; });
  }
  function signData(privateKey, data) { return sha256Bytes(data).then(function (d) { return signDigest(privateKey, d); }); }
  function verifyData(publicKey, data, sigB64) { return sha256Bytes(data).then(function (d) { return verifyDigest(publicKey, d, sigB64); }); }
  function keyAlgLabel(packed) { var u = unpackKeyMaterial(packed); return u ? u.alg : "unknown"; }

  function isUnlocked(id) {
    var ident = getById(id);
    if (!ident) return false;
    if (!ident.passcode) return true;
    return sessionStorage.getItem(SS_UNLOCKED) === id;
  }

  function markUnlocked(id) { try { sessionStorage.setItem(SS_UNLOCKED, id); } catch (e) {} }
  function lockSession() { try { sessionStorage.removeItem(SS_UNLOCKED); } catch (e) {} }

  function humanBytes(n) {
    if (n === null || n === undefined || isNaN(n)) return "unknown";
    var units = ["B", "KB", "MB", "GB", "TB", "PB"];
    var i = 0, v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    var dp = (v >= 100 || i === 0) ? 0 : (v >= 10 ? 1 : 2);
    return v.toFixed(dp) + " " + units[i];
  }

  function humanBytesLong(n) {
    if (n === null || n === undefined || isNaN(n)) return "unknown";
    var units = ["bytes", "kilobytes", "megabytes", "gigabytes", "terabytes", "petabytes"];
    var i = 0, v = Number(n);
    if (!isFinite(v) || v < 0) v = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    var val, unit = units[i];
    if (i === 0) {
      val = String(Math.round(Number(n) || 0));
      if (Number(val) === 1) unit = "byte";
    } else {
      // Always show two decimals for KB+ so tiny usage vs large quota stays precise.
      val = v.toFixed(2);
    }
    return val + " " + unit;
  }

  /** Parse any stored time as an absolute instant (UTC epoch / ISO). */
  function parseUtcInstant(input) {
    if (input == null || input === "") return null;
    if (input instanceof Date) {
      return isNaN(input.getTime()) ? null : input;
    }
    if (typeof input === "number" && isFinite(input)) {
      var fromNum = new Date(input);
      return isNaN(fromNum.getTime()) ? null : fromNum;
    }
    var s = String(input).trim();
    if (!s) return null;
    // Pure epoch millis string
    if (/^\d{10,13}$/.test(s)) {
      var n = Number(s);
      if (s.length === 10) n *= 1000;
      var fromEpoch = new Date(n);
      return isNaN(fromEpoch.getTime()) ? null : fromEpoch;
    }
    // ISO without timezone → treat as UTC (chain / storage convention)
    if (/^\d{4}-\d{2}-\d{2}T/.test(s) && !/[zZ]|[+-]\d{2}:?\d{2}$/.test(s)) {
      s = s + "Z";
    }
    var d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
  }

  /** Local display: 7-22-2026 8:06 PM (from UTC-backed instant). */
  function formatLocalDateTime(input) {
    var d = parseUtcInstant(input);
    if (!d) return "—";
    var month = d.getMonth() + 1;
    var day = d.getDate();
    var year = d.getFullYear();
    var h = d.getHours();
    var mins = d.getMinutes();
    var ampm = h >= 12 ? "PM" : "AM";
    var h12 = h % 12;
    if (h12 === 0) h12 = 12;
    var mm = mins < 10 ? "0" + mins : String(mins);
    return month + "-" + day + "-" + year + " " + h12 + ":" + mm + " " + ampm;
  }

  /** Canonical UTC ISO for storage / chain (always Zulu). */
  function utcNowIso() {
    return new Date().toISOString();
  }

  /* --- Hash-linked receipt chain (mirrors frame ui executionChain + MutationReceipt) ---
     Each entry: action + payload/result hashes, prev_hash → head, FRAME_SIGNATURE_V1. */
  var LS_CHAIN = "frame.receipts.chain.v1";
  var CHAIN_MAX = 512;

  function bytesToHex(buf) {
    var a = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    var s = "";
    for (var i = 0; i < a.length; i++) s += a[i].toString(16).padStart(2, "0");
    return s;
  }

  function stableStringify(value) {
    var seen = typeof WeakSet !== "undefined" ? new WeakSet() : null;
    function walk(v) {
      if (v === null || typeof v !== "object") return v;
      if (seen) {
        if (seen.has(v)) return null;
        seen.add(v);
      }
      if (Array.isArray(v)) return v.map(walk);
      var out = {};
      Object.keys(v).sort().forEach(function (k) { out[k] = walk(v[k]); });
      return out;
    }
    return JSON.stringify(walk(value) ?? null);
  }

  function sha256Hex(str) {
    return sha256Bytes(str).then(function (d) { return bytesToHex(d); });
  }

  function emptyChain() {
    return { version: 1, head_hash: null, next_sequence: 0, entries: [] };
  }

  function getReceiptChain() {
    var raw = readJSON(localStorage, LS_CHAIN);
    if (!raw || raw.version !== 1 || !Array.isArray(raw.entries)) return emptyChain();
    return {
      version: 1,
      head_hash: typeof raw.head_hash === "string" ? raw.head_hash : null,
      next_sequence: typeof raw.next_sequence === "number" ? raw.next_sequence : raw.entries.length,
      entries: raw.entries
    };
  }

  function saveReceiptChain(state) {
    try {
      var trimmed = {
        version: 1,
        head_hash: state.head_hash,
        next_sequence: state.next_sequence,
        entries: (state.entries || []).slice(-CHAIN_MAX)
      };
      localStorage.setItem(LS_CHAIN, JSON.stringify(trimmed));
    } catch (e) {}
  }

  function receiptSigningMaterial(entry) {
    return [
      String(entry.identity_id || "").trim(),
      String(entry.action || "").trim(),
      String(entry.payload_hash || ""),
      String(entry.result_hash || ""),
      entry.prev_hash == null ? "" : String(entry.prev_hash)
    ].join("|");
  }

  /** Append a signed, hash-linked receipt. Returns Promise<entry>. */
  function appendReceipt(args) {
    args = args || {};
    var active = getActive();
    if (!active || !active.privateKey || !active.publicKey) {
      return Promise.reject(new Error("appendReceipt: no signing identity"));
    }
    var action = String(args.action || "unknown").trim();
    var payload = args.payload != null ? args.payload : null;
    var result = args.result != null ? args.result : { ok: true };
    var dapp = args.dapp || null;
    var title = args.title || args.name || action;
    var state = getReceiptChain();
    var prev = state.head_hash;
    var seq = state.next_sequence || 0;
    var id = "r_" + Date.now().toString(36) + "_" + randomAlnum(8).toLowerCase();
    var payloadCanon = stableStringify(payload);
    var resultCanon = stableStringify(result);

    return Promise.all([sha256Hex(payloadCanon), sha256Hex(resultCanon)]).then(function (hashes) {
      var payload_hash = hashes[0];
      var result_hash = hashes[1];
      var draft = {
        identity_id: active.frameId,
        action: action,
        payload_hash: payload_hash,
        result_hash: result_hash,
        prev_hash: prev
      };
      var material = receiptSigningMaterial(draft);
      var alg = keyAlgLabel(active.publicKey);
      return signData(active.privateKey, material).then(function (sig) {
        return verifyData(active.publicKey, material, sig).then(function (ok) {
          if (!ok) throw new Error("appendReceipt: self-verify failed");
          var body = {
            id: id,
            identity_id: active.frameId,
            action: action,
            payload_hash: payload_hash,
            result_hash: result_hash,
            prev_hash: prev,
            timestamp: Date.now(), // UTC epoch ms (chain / signing)
            timestamp_utc: new Date().toISOString(), // explicit Zulu for readers
            signature: sig,
            provider_id: active.frameId,
            sig_alg: "FRAME_SIGNATURE_V1",
            signedBy: active.frameId,
            sigScheme: "FRAME_SIGNATURE_V1",
            sigAlg: alg,
            dapp: dapp,
            title: title,
            payload: payload,
            result: result,
            sequence: seq
          };
          return sha256Hex(stableStringify({
            id: body.id,
            identity_id: body.identity_id,
            action: body.action,
            payload_hash: body.payload_hash,
            result_hash: body.result_hash,
            prev_hash: body.prev_hash,
            timestamp: body.timestamp,
            signature: body.signature,
            provider_id: body.provider_id,
            sig_alg: body.sig_alg
          })).then(function (receipt_hash) {
            body.receipt_hash = receipt_hash;
            state.entries.push(body);
            state.head_hash = receipt_hash;
            state.next_sequence = seq + 1;
            saveReceiptChain(state);
            return body;
          });
        });
      });
    });
  }

  function verifyChainReceipt(entry) {
    if (!entry || !entry.signature || !entry.signedBy) return Promise.resolve(false);
    var signer = getById(entry.signedBy) || getById(entry.identity_id);
    if (!signer || !signer.publicKey) return Promise.resolve(false);
    var material = receiptSigningMaterial({
      identity_id: entry.identity_id || entry.signedBy,
      action: entry.action,
      payload_hash: entry.payload_hash,
      result_hash: entry.result_hash,
      prev_hash: entry.prev_hash
    });
    return verifyData(signer.publicKey, material, entry.signature);
  }

  /** Audit link integrity + signatures (Receipt Audit dApp idea). */
  function auditReceiptChain() {
    var state = getReceiptChain();
    var entries = state.entries || [];
    var report = {
      ok: true,
      count: entries.length,
      head_hash: state.head_hash,
      next_sequence: state.next_sequence,
      broken_links: [],
      bad_signatures: [],
      missing_signers: [],
      recomputed_head: null
    };
    if (entries.length === 0) {
      report.ok = state.head_hash == null;
      return Promise.resolve(report);
    }
    var prev = null;
    var i = 0;
    function step() {
      if (i >= entries.length) {
        report.recomputed_head = prev;
        if (state.head_hash && state.head_hash !== prev) {
          report.ok = false;
          report.broken_links.push({ at: "head", expected: prev, actual: state.head_hash });
        }
        return report;
      }
      var e = entries[i];
      if ((e.prev_hash || null) !== prev) {
        report.ok = false;
        report.broken_links.push({
          at: e.sequence != null ? e.sequence : i,
          id: e.id,
          expected_prev: prev,
          actual_prev: e.prev_hash || null
        });
      }
      var signer = getById(e.signedBy) || getById(e.identity_id);
      if (!signer || !signer.publicKey) {
        report.ok = false;
        report.missing_signers.push(e.id);
        prev = e.receipt_hash || prev;
        i++;
        return Promise.resolve().then(step);
      }
      return verifyChainReceipt(e).then(function (ok) {
        if (!ok) {
          report.ok = false;
          report.bad_signatures.push(e.id);
        }
        prev = e.receipt_hash || prev;
        i++;
        return step();
      });
    }
    return Promise.resolve().then(step);
  }

  /* --- Capability grants (explicit-only, mirrors frame capabilities.ts spirit) --- */
  var LS_GRANTS = "frame.grants.v1";
  var DEFAULT_CAPS = [
    "calc.write", "calc.read",
    "timer.write", "timer.read",
    "sound.play",
    "wallet.write", "wallet.export", "wallet.import",
    "frame.rename", "frame.clone", "frame.export",
    "identity.switch", "identity.create", "identity.export", "identity.import",
    "command.exec", "storage.read", "chain.verify", "grant.manage"
  ];

  function getGrantStore() {
    var raw = readJSON(localStorage, LS_GRANTS);
    if (!raw || typeof raw !== "object") return { version: 1, grants: {} };
    return { version: 1, grants: raw.grants && typeof raw.grants === "object" ? raw.grants : {} };
  }

  function saveGrantStore(store) {
    try { localStorage.setItem(LS_GRANTS, JSON.stringify({ version: 1, grants: store.grants || {} })); } catch (e) {}
  }

  function listGrants(identityId) {
    var id = identityId || getActiveId();
    if (!id) return [];
    var store = getGrantStore();
    var g = store.grants[id];
    return Array.isArray(g) ? g.slice().sort() : [];
  }

  function hasCapability(identityId, capability) {
    var caps = listGrants(identityId);
    if (caps.indexOf("*") >= 0) return true;
    return caps.indexOf(String(capability || "").trim()) >= 0;
  }

  function grantCapability(identityId, capability, opts) {
    opts = opts || {};
    var id = identityId || getActiveId();
    var cap = String(capability || "").trim();
    if (!id || !cap) return Promise.reject(new Error("grant: missing identity or capability"));
    var actor = getActiveId();
    if (opts.skipGate !== true && actor && !hasCapability(actor, "grant.manage") && listGrants(id).length > 0) {
      // Bootstrapping empty identities is allowed; otherwise need grant.manage.
      if (listGrants(actor).length > 0) {
        return Promise.reject(new Error("capability denied: grant.manage"));
      }
    }
    var store = getGrantStore();
    if (!Array.isArray(store.grants[id])) store.grants[id] = [];
    if (store.grants[id].indexOf(cap) < 0) store.grants[id].push(cap);
    saveGrantStore(store);
    if (opts.silent) return Promise.resolve({ identityId: id, capability: cap });
    return appendReceipt({
      action: "grant.add",
      dapp: "frame.system.grants",
      title: "grant " + cap + " → " + id.slice(0, 12) + "…",
      payload: { identityId: id, capability: cap },
      result: { grants: listGrants(id) }
    }).then(function () { return { identityId: id, capability: cap }; });
  }

  function revokeCapability(identityId, capability) {
    var id = identityId || getActiveId();
    var cap = String(capability || "").trim();
    var actor = getActiveId();
    if (actor && !hasCapability(actor, "grant.manage")) {
      return Promise.reject(new Error("capability denied: grant.manage"));
    }
    var store = getGrantStore();
    var list = Array.isArray(store.grants[id]) ? store.grants[id] : [];
    store.grants[id] = list.filter(function (c) { return c !== cap; });
    saveGrantStore(store);
    return appendReceipt({
      action: "grant.revoke",
      dapp: "frame.system.grants",
      title: "revoke " + cap + " from " + (id || "").slice(0, 12) + "…",
      payload: { identityId: id, capability: cap },
      result: { grants: listGrants(id) }
    }).then(function () { return { identityId: id, capability: cap }; });
  }

  function ensureDefaultGrants(identityId) {
    var id = identityId || getActiveId();
    if (!id) return;
    var store = getGrantStore();
    if (!Array.isArray(store.grants[id])) store.grants[id] = [];
    var list = store.grants[id];
    var changed = list.length === 0;
    DEFAULT_CAPS.forEach(function (c) {
      if (list.indexOf(c) < 0) { list.push(c); changed = true; }
    });
    if (changed) {
      store.grants[id] = list;
      saveGrantStore(store);
    }
  }

  function requireCapability(capability) {
    var id = getActiveId();
    if (!id) throw new Error("capability denied: no active identity");
    ensureDefaultGrants(id);
    if (!hasCapability(id, capability)) {
      throw new Error("capability denied: " + capability);
    }
    return true;
  }

  /**
   * Capability-gated mutation: check grant → append signed chain receipt → optional apply().
   * Mirrors frame's intent → receipt → projection funnel (browser-local).
   */
  function mutate(opts) {
    opts = opts || {};
    try {
      if (opts.capability) requireCapability(opts.capability);
    } catch (err) {
      return Promise.reject(err);
    }
    return appendReceipt({
      action: opts.action,
      dapp: opts.dapp,
      title: opts.title,
      payload: opts.payload,
      result: opts.result != null ? opts.result : { ok: true }
    }).then(function (entry) {
      if (typeof opts.apply === "function") {
        try { opts.apply(entry); } catch (e) {}
      }
      return entry;
    });
  }

  /** Project latest dApp display/state from chain receipts (chain as source of truth). */
  function projectFromChain(dappKey, actions) {
    var state = getReceiptChain();
    var latest = null;
    (state.entries || []).forEach(function (e) {
      if (dappKey && e.dapp !== dappKey) return;
      if (actions && actions.length && actions.indexOf(e.action) < 0) return;
      latest = e;
    });
    return latest;
  }

  function projectCalculatorState() {
    var state = getReceiptChain();
    var display = null;
    (state.entries || []).forEach(function (e) {
      if (e.dapp !== "frame.dapp.calculator") return;
      if (e.result && e.result.display != null) display = String(e.result.display);
      else if (e.result && e.result.value != null) display = String(e.result.value);
    });
    return display != null ? { display: display, fromChain: true } : null;
  }

  function projectWalletState() {
    var latest = projectFromChain("frame.dapp.wallet", [
      "wallet.persist", "wallet.add", "wallet.remove", "wallet.job", "wallet.task"
    ]);
    if (latest && latest.result && latest.result.state) {
      return { state: latest.result.state, fromChain: true, receipt: latest };
    }
    return null;
  }

  var LS_WALLET_DAPP = "frame.dapp.wallet";

  /**
   * Upsert a cross-dApp job into Wallet jobs list (Calculator/Timer → Jobs pane).
   * status: "running" | "queued" | "done" | "remove"
   */
  function syncDappJob(args) {
    args = args || {};
    var id = String(args.id || "").trim();
    if (!id) return null;
    var status = String(args.status || "running");
    var d = null;
    try { d = JSON.parse(localStorage.getItem(LS_WALLET_DAPP) || "null"); } catch (e) {}
    if (!d || typeof d !== "object") {
      d = { name: "Wallet", version: "1.0.0", installedAt: new Date().toISOString(), state: { jobs: [], tasks: [] } };
    }
    if (!d.state || typeof d.state !== "object") d.state = { jobs: [], tasks: [] };
    if (!Array.isArray(d.state.jobs)) d.state.jobs = [];
    if (!Array.isArray(d.state.tasks)) d.state.tasks = [];

    if (status === "remove") {
      d.state.jobs = d.state.jobs.filter(function (j) { return j.id !== id; });
    } else {
      var now = new Date().toISOString();
      var next = {
        id: id,
        title: String(args.title || id),
        status: status === "queued" || status === "done" || status === "running" ? status : "running",
        source: args.source || null,
        createdAt: now,
        updatedAt: now
      };
      var found = false;
      d.state.jobs = d.state.jobs.map(function (j) {
        if (j.id !== id) return j;
        found = true;
        return {
          id: id,
          title: next.title,
          status: next.status,
          source: next.source || j.source || null,
          createdAt: j.createdAt || now,
          updatedAt: now
        };
      });
      if (!found) d.state.jobs.unshift(next);
    }
    d.name = d.name || "Wallet";
    d.updatedAt = new Date().toISOString();
    try { localStorage.setItem(LS_WALLET_DAPP, JSON.stringify(d)); } catch (e) {}
    return d;
  }

  /* --- Sound capability (Web Audio; gated by sound.play) --- */
  var audioCtx = null;

  function getAudioContext() {
    try {
      var Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return null;
      if (!audioCtx) audioCtx = new Ctx();
      return audioCtx;
    } catch (e) {
      return null;
    }
  }

  /** Call from a user gesture so browsers allow later alarm playback. */
  function unlockAudio() {
    var ctx = getAudioContext();
    if (!ctx) return Promise.resolve(false);
    if (ctx.state === "suspended") {
      return ctx.resume().then(function () { return true; }).catch(function () { return false; });
    }
    return Promise.resolve(true);
  }

  function scheduleTone(ctx, freq, when, dur, opts) {
    opts = opts || {};
    var o = ctx.createOscillator();
    var g = ctx.createGain();
    var filter = ctx.createBiquadFilter();
    o.type = opts.type || "sine";
    o.frequency.setValueAtTime(freq, when);
    filter.type = "lowpass";
    filter.frequency.setValueAtTime(opts.filter || 4200, when);
    var peak = opts.gain != null ? opts.gain : 0.09;
    g.gain.setValueAtTime(0.0001, when);
    g.gain.exponentialRampToValueAtTime(peak, when + 0.018);
    g.gain.exponentialRampToValueAtTime(Math.max(peak * 0.35, 0.0002), when + dur * 0.45);
    g.gain.exponentialRampToValueAtTime(0.0001, when + dur);
    o.connect(filter);
    filter.connect(g);
    g.connect(ctx.destination);
    o.start(when);
    o.stop(when + dur + 0.03);
  }

  /**
   * Play a capability-gated system sound.
   * kind: "timer.done" | "timer.test" | "ui.tick"
   */
  function playSound(args) {
    args = args || {};
    var kind = String(args.kind || "timer.done");
    try {
      requireCapability("sound.play");
    } catch (err) {
      return Promise.reject(err);
    }
    var ctx = getAudioContext();
    if (!ctx) return Promise.reject(new Error("sound: Web Audio unavailable"));

    function run() {
      var t0 = ctx.currentTime + 0.04;
      if (kind === "ui.tick") {
        scheduleTone(ctx, 880, t0, 0.06, { gain: 0.04, type: "triangle" });
        return 0.12;
      }
      // Timer done: two rising chime phrases + sustained final note (alarm-like).
      // C5 E5 G5 · C5 E5 G5 · C6
      var phrase = [523.25, 659.25, 783.99];
      var cursor = t0;
      for (var p = 0; p < 2; p++) {
        for (var i = 0; i < phrase.length; i++) {
          scheduleTone(ctx, phrase[i], cursor, 0.22, {
            gain: 0.1,
            type: i === 2 ? "triangle" : "sine",
            filter: 5000
          });
          // Soft harmonic for body
          scheduleTone(ctx, phrase[i] * 2, cursor, 0.18, { gain: 0.025, type: "sine", filter: 6000 });
          cursor += 0.2;
        }
        cursor += 0.12;
      }
      scheduleTone(ctx, 1046.5, cursor, 0.55, { gain: 0.12, type: "triangle", filter: 5500 });
      scheduleTone(ctx, 1318.5, cursor + 0.02, 0.45, { gain: 0.04, type: "sine", filter: 7000 });
      cursor += 0.65;
      // Echo phrase quieter
      for (var j = 0; j < phrase.length; j++) {
        scheduleTone(ctx, phrase[j], cursor, 0.18, { gain: 0.05, type: "sine" });
        cursor += 0.16;
      }
      return cursor - t0 + 0.05;
    }

    return unlockAudio().then(function () {
      var dur = run();
      return appendReceipt({
        action: "sound.play",
        dapp: args.dapp || "frame.system.sound",
        title: "sound · " + kind,
        payload: { kind: kind },
        result: { ok: true, durationSec: Math.round(dur * 100) / 100 }
      }).then(function (entry) {
        return { ok: true, kind: kind, durationSec: dur, receipt: entry };
      }).catch(function () {
        return { ok: true, kind: kind, durationSec: dur };
      });
    });
  }

  function localStorageEntries() {
    var out = [];
    try {
      for (var i = 0; i < localStorage.length; i++) {
        var k = localStorage.key(i);
        var v = localStorage.getItem(k) || "";
        out.push({ name: k, bytes: (k.length + v.length) * 2 });
      }
    } catch (e) {}
    return out;
  }

  function localStorageBytes() {
    var total = 0;
    try {
      for (var i = 0; i < localStorage.length; i++) {
        var k = localStorage.key(i);
        var v = localStorage.getItem(k) || "";
        total += (k.length + v.length) * 2; // UTF-16 code units
      }
    } catch (e) {}
    return total;
  }

  function browserName() {
    // Prefer high-entropy client hints when available.
    try {
      var uaData = navigator.userAgentData;
      if (uaData && uaData.brands && uaData.brands.length) {
        var ignore = /not.a.brand|not_a_brand|not a brand/i;
        var pick = null, chromium = null;
        uaData.brands.forEach(function (b) {
          if (ignore.test(b.brand)) return;
          if (/chromium/i.test(b.brand)) { chromium = b.brand; return; }
          pick = b.brand;
        });
        if (pick) return pick.toLowerCase();
        if (chromium) return chromium.toLowerCase();
      }
    } catch (e) {}

    var ua = navigator.userAgent || "";
    try { if (navigator.brave) return "brave"; } catch (e) {}

    var tests = [
      [/Edg(A|iOS)?\//, "edge"],
      [/OPR\/|OPiOS\/|\bOpera\b/, "opera"],
      [/\bYaBrowser\//, "yandex"],
      [/\bVivaldi\//, "vivaldi"],
      [/\bBrave\//, "brave"],
      [/\bSamsungBrowser\//, "samsung internet"],
      [/\bUCBrowser\/|\bUCWEB\//, "uc browser"],
      [/\bDuckDuckGo\/|\bDDG\//, "duckduckgo"],
      [/\bQQBrowser\//, "qq browser"],
      [/\bMiuiBrowser\//, "miui browser"],
      [/\bSilk\//, "silk"],
      [/\bFxiOS\/|Firefox\/|Waterfox\//, "firefox"],
      [/\bCriOS\//, "chrome"],
      [/\bEdgiOS\//, "edge"],
      [/Chrome\//, "chrome"],
      [/Chromium\//, "chromium"],
      [/\bVersion\/.*\bSafari\/|iPhone|iPad|iPod|\bSafari\//, "safari"],
      [/\bMSIE |Trident\//, "internet explorer"]
    ];
    for (var i = 0; i < tests.length; i++) {
      if (tests[i][0].test(ua)) return tests[i][1];
    }
    // Last resort: use the trailing Name/Version token from the UA string.
    var m = ua.match(/([A-Za-z][A-Za-z ]+)\/[\d.]+\s*$/);
    if (m) return m[1].trim().toLowerCase();
    return "unknown browser";
  }

  return {
    getIdentities: getIdentities,
    saveIdentities: saveIdentities,
    getActiveId: getActiveId,
    setActiveId: setActiveId,
    getById: getById,
    getActive: getActive,
    updateIdentity: updateIdentity,
    addIdentity: addIdentity,
    removeIdentity: removeIdentity,
    createIdentity: createIdentity,
    buildIdentity: buildIdentity,
    generateKeypair: generateKeypair,
    deriveIdentityId: deriveIdentityId,
    packKeyMaterial: packKeyMaterial,
    hashPasscode: hashPasscode,
    isHashedPasscode: isHashedPasscode,
    verifyPasscode: verifyPasscode,
    setPasscode: setPasscode,
    getFrame: getFrame,
    setFrameId: setFrameId,
    exportIdentity: exportIdentity,
    importIdentity: importIdentity,
    exportFrame: exportFrame,
    importFrame: importFrame,
    gate: gate,
    sha256Bytes: sha256Bytes,
    signDigest: signDigest,
    verifyDigest: verifyDigest,
    signData: signData,
    verifyData: verifyData,
    keyAlgLabel: keyAlgLabel,
    isUnlocked: isUnlocked,
    markUnlocked: markUnlocked,
    lockSession: lockSession,
    randomDigits: randomDigits,
    randomAlnum: randomAlnum,
    humanBytes: humanBytes,
    humanBytesLong: humanBytesLong,
    formatLocalDateTime: formatLocalDateTime,
    parseUtcInstant: parseUtcInstant,
    utcNowIso: utcNowIso,
    localStorageBytes: localStorageBytes,
    localStorageEntries: localStorageEntries,
    browserName: browserName,
    stableStringify: stableStringify,
    sha256Hex: sha256Hex,
    getReceiptChain: getReceiptChain,
    appendReceipt: appendReceipt,
    verifyChainReceipt: verifyChainReceipt,
    auditReceiptChain: auditReceiptChain,
    listGrants: listGrants,
    hasCapability: hasCapability,
    grantCapability: grantCapability,
    revokeCapability: revokeCapability,
    ensureDefaultGrants: ensureDefaultGrants,
    requireCapability: requireCapability,
    mutate: mutate,
    projectFromChain: projectFromChain,
    projectCalculatorState: projectCalculatorState,
    projectWalletState: projectWalletState,
    syncDappJob: syncDappJob,
    unlockAudio: unlockAudio,
    playSound: playSound,
    DEFAULT_CAPS: DEFAULT_CAPS
  };
})();
