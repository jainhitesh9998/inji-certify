/*
 * The demo wallet page's controller (P5-03a): DOM only. It lists the credentials kept in this browser (WalletStore),
 * shows one credential's IssuerSigned elements the way the offer page renders an issued mDL, and deletes one record or
 * the whole database. No protocol logic lives here; the naming and the modules are the plan's (section 4.1).
 *
 * The page holds one connection (`db`) and gives it up when another tab deletes or upgrades the store, or when the
 * browser closes it; the list then follows. While a start, a delete or a reconnect is under way (`busy`, a count of
 * them, so one finishing never re-enables the controls while another still waits) every control is disabled, so nothing
 * is attempted on a connection that is closing or a store that is being deleted. A list read on a connection the page
 * has since given up is dropped, never shown, and so is the closing message of an operation whose connection was given up
 * meanwhile: the handler that took the connection away has said what happened since, and its message is the newer one
 * (P5-03a review round 4).
 */
(function () {
  "use strict";

  var el = function (id) { return document.getElementById(id); };
  var db = null;
  var records = [];
  var selected = null;
  // how many operations (start, delete, delete everything, reconnect) are under way; the controls wait for all of them
  var busy = 0;
  // the blob URL of the portrait the details view last rendered, released when another one replaces it
  var portraitObjectUrls = [];

  function status(id, message, ok) {
    var node = el(id);
    if (node === null) return;
    node.textContent = message;
    node.className = "status " + (ok === undefined ? "" : ok ? "ok" : "bad");
  }

  function bytesOf(value) {
    if (value instanceof Uint8Array) return value;
    if (value && typeof value === "object" && value.buffer) return new Uint8Array(value);
    return null;
  }

  function imageMime(bytes) {
    if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "image/jpeg";
    if (bytes.length >= 8 && bytes[0] === 0 && bytes[1] === 0 && bytes[2] === 0 && bytes[3] === 0x0c
        && bytes[4] === 0x6a && bytes[5] === 0x50 && bytes[6] === 0x20 && bytes[7] === 0x20) return "image/jp2";
    return null;
  }

  function labelOf(record) {
    return record.label || record.docType || record.id;
  }

  /** The controls: off while anything is under way or no store is open; Delete also needs a credential selected. */
  function syncControls() {
    el("deleteAll").disabled = busy > 0 || db === null || records.length === 0;
    el("delete").disabled = busy > 0 || db === null || selected === null;
  }

  function renderList() {
    var list = el("records");
    list.textContent = ""; // clearing the page's own list only; every value below is set as text
    el("empty").hidden = records.length > 0;
    if (selected !== null && !records.some(function (record) { return record.id === selected.id; })) {
      selected = null;
      el("details").hidden = true;
    }
    syncControls();
    records.forEach(function (record) {
      var item = document.createElement("li");
      var open = document.createElement("button");
      open.className = "secondary";
      open.textContent = labelOf(record);
      open.disabled = busy > 0;
      open.addEventListener("click", function () { show(record); });
      var meta = document.createElement("span");
      meta.className = "hint";
      meta.textContent = (record.docType || record.format) + (record.storedAt ? " · kept " + new Date(record.storedAt).toISOString() : "");
      item.appendChild(open);
      item.appendChild(meta);
      list.appendChild(item);
    });
  }

  function row(name, value) {
    var tr = document.createElement("tr");
    var th = document.createElement("td");
    th.textContent = name;
    th.style.cssText = "padding:4px 6px;border-top:1px solid #eee;vertical-align:top;white-space:nowrap";
    var td = document.createElement("td");
    td.style.cssText = "padding:4px 6px;border-top:1px solid #eee;word-break:break-word";
    td.appendChild(document.createTextNode(String(value)));
    tr.appendChild(th);
    tr.appendChild(td);
    return tr;
  }

  /**
   * A decoded value as text. Maps arrive typed (`Map`, Mdoc.readIssuerSigned), so a text key prints quoted and an integer
   * key bare: `{"a":1}` reads as it did when maps were objects, and `{1:"x","1":"y"}` keeps its two keys apart. Bytes
   * print as their count, a BigInt as its exact digits.
   */
  function describe(value) {
    if (value instanceof Map) {
      var entries = [];
      value.forEach(function (member, key) {
        var name = typeof key === "string" ? JSON.stringify(key)
          : typeof key === "number" || typeof key === "bigint" ? String(key)
          : key instanceof Cbor.OtherKey ? describe(key.value) : String(key);
        entries.push(name + ":" + describe(member));
      });
      return "{" + entries.join(",") + "}";
    }
    if (Array.isArray(value)) return "[" + value.map(describe).join(",") + "]";
    if (value instanceof Uint8Array) return JSON.stringify("<" + value.length + " bytes>");
    if (typeof value === "bigint") return JSON.stringify(value.toString());
    if (value === undefined) return "undefined";
    return JSON.stringify(value);
  }

  /** The element value rendered as the offer page renders an issued mDL: a portrait as an image, bytes as a count. */
  function valueNode(elementIdentifier, value) {
    if (value instanceof Uint8Array) {
      if (elementIdentifier === "portrait") {
        var mime = imageMime(value);
        if (mime !== null) {
          var image = document.createElement("img");
          var url = URL.createObjectURL(new Blob([value], { type: mime }));
          portraitObjectUrls.push(url);
          image.src = url;
          image.alt = "portrait";
          image.style.cssText = "max-width:120px;border-radius:6px";
          var holder = document.createElement("span");
          holder.appendChild(image);
          return holder;
        }
      }
      return value.length + " bytes";
    }
    if (value !== null && typeof value === "object") return describe(value);
    return String(value);
  }

  function show(record) {
    selected = record;
    portraitObjectUrls.forEach(function (url) { URL.revokeObjectURL(url); });
    portraitObjectUrls = [];
    var table = el("detailsTable");
    table.textContent = "";
    el("detailsTitle").textContent = labelOf(record);
    table.appendChild(row("docType", record.docType || ""));
    table.appendChild(row("issuer", record.credentialIssuer || ""));
    table.appendChild(row("configuration", record.credentialConfigurationId || ""));
    table.appendChild(row("validFrom", record.validFrom || ""));
    table.appendChild(row("validUntil", record.validUntil || ""));
    var bytes = bytesOf(record.issuerSigned);
    if (bytes !== null) {
      try {
        var read = Mdoc.readIssuerSigned(bytes);
        [...read.nameSpaces.keys()].sort().forEach(function (namespace) {
          read.nameSpaces.get(namespace).forEach(function (item) {
            var name = namespace + " / " + item.elementIdentifier;
            var rendered = valueNode(item.elementIdentifier, item.elementValue);
            var tr = document.createElement("tr");
            var th = document.createElement("td");
            th.textContent = name;
            th.style.cssText = "padding:4px 6px;border-top:1px solid #eee;vertical-align:top;white-space:nowrap";
            var td = document.createElement("td");
            td.style.cssText = "padding:4px 6px;border-top:1px solid #eee;word-break:break-word";
            if (typeof rendered === "object" && rendered.nodeType === 1) td.appendChild(rendered);
            else td.appendChild(document.createTextNode(String(rendered)));
            tr.appendChild(th);
            tr.appendChild(td);
            table.appendChild(tr);
          });
        });
      } catch (e) {
        table.appendChild(row("IssuerSigned", "could not be read: " + e.message));
      }
    }
    el("details").hidden = false;
    status("detailsStatus", "");
    syncControls();
  }

  /**
   * Reads the list on the page's connection. The read can outlive the connection - another tab deletes everything
   * while it runs, and the connection is given up (versionchange) but still answers the read it had started - so the
   * answer is shown only while it is still the page's connection; otherwise it lists records that may be gone. Returns
   * whether the list was taken.
   */
  async function refresh() {
    var connection = db;
    if (connection === null) {
      records = [];
      renderList();
      return false;
    }
    var listed = await WalletStore.list(connection);
    if (connection !== db) return false; // given up meanwhile: whoever reconnects lists the store as it now is
    records = listed;
    renderList();
    return true;
  }

  /** One operation starts (true) or ends (false); the controls come back only when none is left. */
  function setBusy(value) {
    busy = Math.max(0, busy + (value ? 1 : -1));
    renderList();
  }

  /** Forgets what the page showed: the list, the selection and the details view. */
  function forget() {
    records = [];
    selected = null;
    el("details").hidden = true;
    renderList();
  }

  /**
   * This page's connection, which follows what happens to the store elsewhere. When another tab deletes everything,
   * this connection closes itself (WalletStore) and the page forgets its list, says why, and reconnects: that open
   * queues behind the other tab's delete (IndexedDB 3.0, 5.1), so it answers once the delete is done and the list is
   * then the store as it is. An upgrade by a newer page, or a connection the browser closed, asks for a reload instead.
   */
  function connect() {
    return WalletStore.open({
      onVersionChange: function (connection, event) {
        if (connection !== db) return; // a connection this page already gave up
        db = null;
        forget();
        if (event && event.newVersion !== null && event.newVersion !== undefined) {
          status("storageStatus", "Another tab upgraded the credential store; reload this page to see what is kept.", false);
          return;
        }
        status("storageStatus", "Another wallet tab is deleting everything kept in this browser; this list follows"
          + " once that delete is done.", false);
        reconnect("Another wallet tab deleted everything kept in this browser.");
      },
      onClose: function (connection) {
        if (connection !== db) return;
        db = null;
        forget();
        status("storageStatus", "The browser closed the credential store (its site data may have been cleared); reload"
          + " this page to see what is kept.", false);
      },
    });
  }

  async function reconnect(message) {
    setBusy(true);
    try {
      var connection = await connect();
      db = connection;
      // a newer change may have taken this connection away already; its own handler then says what happened
      if (await refresh() && db === connection) status("storageStatus", message, false);
    } catch (e) {
      status("storageStatus", "The credential store could not be reopened: " + e.message + ". Reload this page.", false);
    } finally {
      setBusy(false);
    }
  }

  el("delete").addEventListener("click", async function () {
    if (busy > 0 || selected === null || db === null) return;
    var record = selected;
    var connection = db;
    setBusy(true);
    try {
      await WalletStore.remove(connection, record.id);
      // another tab's delete may have taken the connection meanwhile: its own message, written since, is the news
      if (connection !== db) return;
      // the details section is hidden on success, so the confirmation goes where the visitor can still see it
      status("storageStatus", "Deleted " + labelOf(record) + ". Its key went with it.", true);
      status("detailsStatus", "");
      selected = null;
      el("details").hidden = true;
      await refresh();
    } catch (e) {
      if (connection === db) status("detailsStatus", "The credential could not be deleted: " + e.message, false);
    } finally {
      setBusy(false);
    }
  });

  el("deleteAll").addEventListener("click", async function () {
    if (busy > 0 || db === null) return;
    setBusy(true);
    status("storageStatus", "Deleting everything kept in this browser…");
    // this page's own connection goes first, or it would block its own delete
    var connection = db;
    db = null;
    try { connection.close(); } catch (e) { /* already closed */ }
    var failure = null;
    try {
      await WalletStore.deleteEverything(function () {
        // said before anything is awaited: the delete stays queued, and finishes by itself once the other tabs close
        status("storageStatus", "Waiting for other wallet tabs to close… Close every other tab of this wallet (or reload"
          + " it) and the delete finishes by itself.", false);
      });
    } catch (e) {
      failure = e;
    }
    // the delete has finished, one way or the other: only now can this page open the store without queueing behind it
    forget();
    try {
      var reopened = await connect();
      db = reopened;
      // only while the reopened connection is still the page's: another tab's delete may have taken it during the list
      // read, and that tab's handler has said so since - this older news must not overwrite it
      if (!(await refresh()) || db !== reopened) return;
      if (failure === null) status("storageStatus", "Everything kept in this browser was deleted.", true);
      else status("storageStatus", "The store could not be deleted: " + failure.message, false);
    } catch (e) {
      status("storageStatus", failure === null
        ? "Everything kept in this browser was deleted, but the store could not be reopened: " + e.message
        : "The store could not be deleted (" + failure.message + "), nor reopened: " + e.message, false);
    } finally {
      setBusy(false);
    }
  });

  /**
   * I4: the wallet's own switch decides whether this browser stores anything. The page is meant to be reached at
   * `offer/wallet`, which answers 404 with the switch off; asking `wallet/config` (the endpoint the offer page asks
   * too) before opening the store keeps that true whatever path served these bytes.
   */
  async function walletEnabled() {
    try {
      var answer = await fetch("wallet/config", { cache: "no-store", credentials: "same-origin", redirect: "error" });
      return answer.status === 200;
    } catch (e) {
      return false;
    }
  }

  (async function start() {
    renderList();
    if (typeof WalletStore === "undefined" || !WalletStore.available()) {
      status("storageStatus", "This browser cannot keep credentials: IndexedDB is unavailable.", false);
      el("empty").hidden = false;
      return;
    }
    if (!(await walletEnabled())) {
      status("storageStatus", "The demo wallet is switched off on this deployment, so nothing is kept in this browser.", false);
      el("empty").hidden = false;
      return;
    }
    setBusy(true);
    try {
      db = await connect();
    } catch (e) {
      status("storageStatus", "This browser could not open its credential store: " + e.message, false);
      setBusy(false);
      return;
    }
    try {
      await refresh();
    } catch (e) {
      status("storageStatus", "The kept credentials could not be read: " + e.message, false);
    } finally {
      setBusy(false);
    }
  })();
})();
