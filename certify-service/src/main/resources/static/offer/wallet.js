/*
 * The demo wallet page's controller (P5-03a): DOM only. It lists the credentials kept in this browser (WalletStore),
 * shows one credential's IssuerSigned elements the way the offer page renders an issued mDL, and deletes one record or
 * the whole database. No protocol logic lives here; the naming and the modules are the plan's (section 4.1).
 */
(function () {
  "use strict";

  var el = function (id) { return document.getElementById(id); };
  var db = null;
  var records = [];
  var selected = null;
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

  function renderList() {
    var list = el("records");
    list.textContent = ""; // clearing the page's own list only; every value below is set as text
    el("empty").hidden = records.length > 0;
    el("deleteAll").disabled = records.length === 0;
    if (selected !== null && !records.some(function (record) { return record.id === selected.id; })) {
      selected = null;
      el("details").hidden = true;
    }
    records.forEach(function (record) {
      var item = document.createElement("li");
      var open = document.createElement("button");
      open.className = "secondary";
      open.textContent = labelOf(record);
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
    if (value !== null && typeof value === "object") {
      return JSON.stringify(value, function (key, nested) {
        return typeof nested === "bigint" ? nested.toString() : nested instanceof Uint8Array ? "<" + nested.length + " bytes>" : nested;
      });
    }
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
        Object.keys(read.nameSpaces).sort().forEach(function (namespace) {
          read.nameSpaces[namespace].forEach(function (item) {
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
  }

  async function refresh() {
    records = await WalletStore.list(db);
    renderList();
  }

  el("delete").addEventListener("click", async function () {
    if (selected === null || db === null) return;
    try {
      await WalletStore.remove(db, selected.id);
      // the details section is hidden on success, so the confirmation goes where the visitor can still see it
      status("storageStatus", "Deleted " + labelOf(selected) + ". Its key went with it.", true);
      status("detailsStatus", "");
      selected = null;
      el("details").hidden = true;
      await refresh();
    } catch (e) {
      status("detailsStatus", "The credential could not be deleted: " + e.message, false);
    }
  });

  el("deleteAll").addEventListener("click", async function () {
    if (db === null) return;
    try {
      db.close();
      db = null;
      await WalletStore.deleteEverything();
    } catch (e) {
      // another tab still holds the store open (WalletStore reports `blocked` instead of waiting): reopen this page's
      // own connection so the list keeps working, and say what the visitor can do about it
      try {
        db = await WalletStore.open();
        await refresh();
      } catch (ignored) {
        // the status below is what the visitor reads; a store that cannot reopen says so on the next action
      }
      status("storageStatus", "The store could not be deleted: " + e.message, false);
      return;
    }
    try {
      db = await WalletStore.open();
      selected = null;
      el("details").hidden = true;
      await refresh();
      status("storageStatus", "Everything kept in this browser was deleted.", true);
    } catch (e) {
      status("storageStatus", "The store was deleted, but could not be reopened: " + e.message, false);
    }
  });

  (async function start() {
    if (typeof WalletStore === "undefined" || !WalletStore.available()) {
      status("storageStatus", "This browser cannot keep credentials: IndexedDB is unavailable.", false);
      el("empty").hidden = false;
      return;
    }
    try {
      db = await WalletStore.open();
    } catch (e) {
      status("storageStatus", "This browser could not open its credential store: " + e.message, false);
      return;
    }
    try {
      await refresh();
    } catch (e) {
      status("storageStatus", "The kept credentials could not be read: " + e.message, false);
    }
  })();
})();
