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
    var i = 0, v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    var dp = (v >= 100 || i === 0) ? 0 : (v >= 10 ? 1 : 2);
    var val = v.toFixed(dp);
    var unit = units[i];
    if (i === 0 && Number(val) === 1) unit = "byte";
    return val + " " + unit;
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
    localStorageBytes: localStorageBytes,
    localStorageEntries: localStorageEntries,
    browserName: browserName
  };
})();
