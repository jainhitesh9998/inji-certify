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
 * writes in one transaction, and deleting the database reports `blocked` (another tab still holds it open) while it keeps
 * waiting, because a blocked delete is still queued and still finishes (IndexedDB 3.0, 5.3). Anything opened meanwhile
 * queues behind it (5.1), so nothing here opens the database while a delete is pending.
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
   *
   * `handlers` (optional) lets a page follow what happened to its connection: `onVersionChange(connection, event)` after
   * it closed itself for another tab (`event.newVersion` is null for a delete), and `onClose(connection, event)` when the
   * browser closed it (site data cleared, storage lost). Either way the connection is unusable from then on.
   */
  function open(handlers) {
    var on = handlers || {};
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
        database.onversionchange = function (event) {
          try { database.close(); } catch (error) { /* already closed */ }
          if (typeof on.onVersionChange === "function") on.onVersionChange(database, event);
        };
        database.onclose = function (event) {
          if (typeof on.onClose === "function") on.onClose(database, event);
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
   * Deletes the whole database: "Delete everything". Resolves once the browser reports the database gone, rejects only
   * when it reports an error: those are the delete's only outcomes.
   *
   * Every other connection is asked to close first (see open). One that does not close at once - another tab of an older
   * build, a frozen tab, a tab whose transaction is still running - makes the browser fire `blocked`. That is news, not
   * an outcome: the delete stays queued and finishes by itself once the last connection closes (IndexedDB 3.0, 5.3), so
   * `onBlocked` is called (synchronously, so a page can say so before it awaits anything) and the promise keeps waiting.
   * Rejecting there would report a failure for a delete that then succeeds, and an `open()` made after it would queue
   * behind the delete (5.1) instead of answering.
   */
  function deleteEverything(onBlocked) {
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
      request.onblocked = function (event) {
        if (typeof onBlocked === "function") onBlocked(event);
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
