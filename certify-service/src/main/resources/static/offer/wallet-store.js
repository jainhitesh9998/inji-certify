/*
 * The demo wallet's storage (P5-03a, plan section 4.2): IndexedDB database `certify-demo-wallet`, version 1.
 *
 *   credentials  keyPath `id`     {id, format, docType, issuerSigned, privateKey, publicJwk, credentialIssuer,
 *                                  credentialConfigurationId, storedAt, validFrom, validUntil, label}
 *   answered     keyPath `key`    {key, at}: a verifier request already answered, dropped after 24 hours
 *   log          autoIncrement    {at, ...}: the presentation log, the last 100 kept
 *
 * Nothing here leaves the browser, and a kept credential's private key is a non-extractable CryptoKey: the record holds
 * the only reference to it, so deleting the record deletes the key.
 */
var WalletStore = (function () {
  "use strict";

  var DB_NAME = "certify-demo-wallet";
  var VERSION = 1;
  var CREDENTIALS = "credentials";
  var ANSWERED = "answered";
  var LOG = "log";
  var MAX_LOG = 100;
  var ANSWERED_TTL = 24 * 60 * 60 * 1000;

  function available() {
    return typeof indexedDB !== "undefined" && indexedDB !== null;
  }

  function requestDone(request) {
    return new Promise(function (resolve, reject) {
      request.onsuccess = function () { resolve(request.result); };
      request.onerror = function () { reject(request.error || new Error("IndexedDB request failed")); };
    });
  }

  function transactionDone(transaction) {
    return new Promise(function (resolve, reject) {
      transaction.oncomplete = function () { resolve(); };
      transaction.onerror = function () { reject(transaction.error || new Error("IndexedDB transaction failed")); };
      transaction.onabort = function () { reject(transaction.error || new Error("IndexedDB transaction aborted")); };
    });
  }

  /** Opens (creating on first use) the database; answered requests older than 24 hours are dropped first. */
  function open() {
    return new Promise(function (resolve, reject) {
      var request;
      try {
        request = indexedDB.open(DB_NAME, VERSION);
      } catch (error) {
        reject(error);
        return;
      }
      request.onupgradeneeded = function () {
        var database = request.result;
        if (!database.objectStoreNames.contains(CREDENTIALS)) {
          database.createObjectStore(CREDENTIALS, { keyPath: "id" });
        }
        if (!database.objectStoreNames.contains(ANSWERED)) {
          database.createObjectStore(ANSWERED, { keyPath: "key" });
        }
        if (!database.objectStoreNames.contains(LOG)) {
          database.createObjectStore(LOG, { autoIncrement: true });
        }
      };
      request.onerror = function () { reject(request.error || new Error("IndexedDB could not be opened")); };
      request.onsuccess = function () {
        var database = request.result;
        pruneAnswered(database).then(function () { resolve(database); }, function () { resolve(database); });
      };
    });
  }

  function pruneAnswered(database) {
    var now = Date.now();
    return requestDone(database.transaction(ANSWERED, "readonly").objectStore(ANSWERED).getAll()).then(function (entries) {
      var stale = (entries || []).filter(function (entry) { return !entry || typeof entry.at !== "number" || now - entry.at > ANSWERED_TTL; });
      if (!stale.length) return undefined;
      var transaction = database.transaction(ANSWERED, "readwrite");
      var store = transaction.objectStore(ANSWERED);
      stale.forEach(function (entry) { if (entry && entry.key !== undefined) store.delete(entry.key); });
      return transactionDone(transaction);
    });
  }

  /** The kept credentials, newest first. */
  function list(database) {
    return requestDone(database.transaction(CREDENTIALS, "readonly").objectStore(CREDENTIALS).getAll())
      .then(function (records) {
        return (records || []).sort(function (left, right) {
          return (right && right.storedAt || 0) - (left && left.storedAt || 0);
        });
      });
  }

  function count(database) {
    return requestDone(database.transaction(CREDENTIALS, "readonly").objectStore(CREDENTIALS).count());
  }

  function put(database, record) {
    var transaction = database.transaction(CREDENTIALS, "readwrite");
    transaction.objectStore(CREDENTIALS).put(record);
    return transactionDone(transaction).then(function () { return record; });
  }

  function get(database, id) {
    return requestDone(database.transaction(CREDENTIALS, "readonly").objectStore(CREDENTIALS).get(id));
  }

  function remove(database, id) {
    var transaction = database.transaction(CREDENTIALS, "readwrite");
    transaction.objectStore(CREDENTIALS).delete(id);
    return transactionDone(transaction);
  }

  /** Deletes the whole database: "Delete everything". */
  function deleteEverything() {
    return new Promise(function (resolve, reject) {
      var request = indexedDB.deleteDatabase(DB_NAME);
      request.onsuccess = function () { resolve(); };
      request.onerror = function () { reject(request.error || new Error("IndexedDB could not be deleted")); };
      request.onblocked = function () { resolve(); };
    });
  }

  /** Adds one log entry, keeping the last 100. The log never leaves the browser. */
  function addLog(database, entry) {
    var transaction = database.transaction(LOG, "readwrite");
    transaction.objectStore(LOG).put(entry);
    return transactionDone(transaction).then(function () {
      return requestDone(database.transaction(LOG, "readonly").objectStore(LOG).getAll()).then(function (entries) {
        var excess = (entries || []).length - MAX_LOG;
        if (excess <= 0) return undefined;
        var trim = database.transaction(LOG, "readwrite");
        (entries || []).slice(0, excess).forEach(function (old) { trim.objectStore(LOG).delete(old && old.id); });
        return transactionDone(trim);
      });
    });
  }

  return {
    DB_NAME: DB_NAME,
    VERSION: VERSION,
    CREDENTIALS: CREDENTIALS,
    ANSWERED: ANSWERED,
    LOG: LOG,
    available: available,
    open: open,
    list: list,
    count: count,
    put: put,
    get: get,
    remove: remove,
    deleteEverything: deleteEverything,
    addLog: addLog,
  };
})();
