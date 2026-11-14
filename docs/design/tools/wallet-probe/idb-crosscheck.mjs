#!/usr/bin/env node
/*
 * P5-03a review round 2: the demo wallet's storage, held to an implementation of IndexedDB 3.0 that this repository did
 * not write. check-offer-wallet.mjs runs the wallet page on the harness's own fake IndexedDB; a fake that answered an
 * open at once while a delete was pending, and dropped a request on a finished transaction, let a real bug through
 * ("Delete everything" never told a visitor to close the other tabs, then reported a failure for a delete that had
 * succeeded). This runs the same scenarios - the connection queue, `blocked`, transaction lifetime, and the wallet
 * page's deletes against other tabs - on fake-indexeddb (pinned, test-only), so the fake and the page are both checked
 * against what a spec implementation does. Every scenario reads what the visitor sees and the store afterwards, never
 * a factory's internals.
 *
 *   (cd docs/design/tools/wallet-probe && npm ci && node idb-crosscheck.mjs)
 *
 * Node 24, like the other harnesses. Nothing here is a runtime dependency (plan invariant I6).
 */
import { IDBFactory } from "fake-indexeddb";

import { counts } from "../check-offer-page.mjs";
import { storageConformance, walletDeleteScenarios } from "../check-offer-wallet.mjs";

try {
    await storageConformance(() => new IDBFactory(), "fake-indexeddb 6.2.4");
    // fake-indexeddb 6.2.4 treats a close-pending connection as closed when it deletes (IndexedDB 3.0 2.6 and 5.3 say a
    // connection is closed once its transactions complete): the scenario's outcome checks still run, the two that
    // depend on that wait do not (see walletDeleteScenarios)
    await walletDeleteScenarios(() => new IDBFactory(), "fake-indexeddb 6.2.4", { closeWaitsForTransactions: false });
} finally {
    const { checks, failures } = counts();
    console.log();
    if (!checks) console.log("idb-crosscheck: no check ran");
    if (failures || !checks) {
        console.log(`idb-crosscheck: ${failures} of ${checks} checks FAILED`);
    } else {
        console.log(`idb-crosscheck: all ${checks} checks passed`);
    }
    process.exitCode = failures || !checks ? 1 : 0;
}
