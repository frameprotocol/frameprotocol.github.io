/* FRAME identity model — stored in the browser (localStorage). */
window.FRAME = (function () {
  var LS_IDS = "frame.identities";
  var LS_ACTIVE = "frame.activeId";
  var SS_UNLOCKED = "frame.unlocked"; // sessionStorage: frameId unlocked this session
  var LS_OLD = "frame.instance";      // legacy single-instance key

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

  function createIdentity(passcode) {
    var obj = {
      frameId: "identity:" + randomDigits(6),
      recoveryKey: randomAlnum(17),
      passcode: passcode || null,
      settings: { maxAttempts: 5, onLimit: "lock" },
      failedAttempts: 0,
      locked: false,
      createdAt: new Date().toISOString()
    };
    addIdentity(obj);
    return obj;
  }

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
