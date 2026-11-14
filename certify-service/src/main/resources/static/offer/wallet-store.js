/*
 * The demo wallet's storage (P5-03a, plan section 4.2): IndexedDB database `certify-demo-wallet`, version 1.
 *
 *   credentials  keyPath `id`     {id, format, docType, issuerSigned, privateKey, publicJwk, credentialIssuer,
 *                                  credentialConfigurationId, storedAt, validFrom, validUntil, label}
 *   answered     keyPath `key`    {key, at}: a verifier request already answered (P5-03c; created here so the version
 *                                  stays 1)
 *   log          autoIncrement    {at, ...}: the presentation log (P5-03b/e; created here for the same reason)
 *
 * Nothing here leaves the browser, and a kept credential's private key is a non-extractable CryptoKey: the record holds
 * the only reference to it, so deleting the record deletes the key.
 *
 * The two operations that can race another tab are the ones that have to be careful: keeping a credential counts and
 * writes in one transaction, and deleting the database says so when another tab still holds it open instead of waiting
 * for it forever.
 */
var WalletStore = (function () {
  "use strict";

  var DB_NAME = "certify-demo-wallet";
  var VERSION = 1;
  var CREDENTIALS = "credentials";
  var ANSWERED = "answered";
  var LOG = "log";

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

  /**
   * Opens (creating on first use) the database. The connection gives itself up when another tab asks for a version
   * change - "Delete everything" in another tab - because a connection that stays open is what blocks that delete.
   */
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
        // the browser fires this on every other connection when one tab upgrades or deletes the database: closing here
        // is what lets that request complete rather than stay blocked on this tab
        database.onversionchange = function () {
          try { database.close(); } catch (error) { /* already closed */ }
        };
        resolve(database);
      };
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

  function remove(database, id) {
    var transaction = database.transaction(CREDENTIALS, "readwrite");
    transaction.objectStore(CREDENTIALS).delete(id);
    return transactionDone(transaction);
  }

  /**
   * Stores one credential only while fewer than `limit` are kept, counted and written inside the same readwrite
   * transaction. Two tabs that keep their 50th and 51st credential at the same moment therefore cannot both succeed:
   * the count and the write are never apart, so no read can go stale between them. Resolves `true` when the record was
   * written, `false` when the limit refused it (nothing was written in that transaction).
   */
  function putWithinLimit(database, record, limit) {
    var stored = false;
    return new Promise(function (resolve, reject) {
      var transaction;
      try {
        transaction = database.transaction(CREDENTIALS, "readwrite");
      } catch (error) {
        reject(error);
        return;
      }
      transaction.oncomplete = function () { resolve(stored); };
      transaction.onerror = function () { reject(transaction.error || new Error("IndexedDB transaction failed")); };
      transaction.onabort = function () { reject(transaction.error || new Error("IndexedDB transaction aborted")); };
      var store = transaction.objectStore(CREDENTIALS);
      var counting = store.count();
      counting.onsuccess = function () {
        if (counting.result >= limit) return; // the transaction commits with nothing written
        stored = true;
        store.put(record);
      };
    });
  }

  /**
   * Deletes the whole database: "Delete everything". Resolves only once the browser reports the database gone. Another
   * tab that still holds a connection is asked to close it (see open); if it does not, the browser reports `blocked`,
   * which is refused here with what the visitor can do about it rather than left waiting forever.
   */
  function deleteEverything() {
    return new Promise(function (resolve, reject) {
      var request;
      try {
        request = indexedDB.deleteDatabase(DB_NAME);
      } catch (error) {
        reject(error);
        return;
      }
      request.onsuccess = function () { resolve(); };
      request.onerror = function () { reject(request.error || new Error("IndexedDB could not be deleted")); };
      request.onblocked = function () {
        reject(new Error("another tab of this wallet still has the credential store open; close every other wallet tab"
          + " and try again"));
      };
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
    putWithinLimit: putWithinLimit,
    remove: remove,
    deleteEverything: deleteEverything,
  };
})();
