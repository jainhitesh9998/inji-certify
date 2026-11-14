# wallet-probe: test-only Node tools for the demo wallet (P5-03)

Nothing here is on any runtime classpath (plan invariant I6). `npm ci` is the only install, and every version is exact
in `package.json` and `package-lock.json`.

| File | What |
| --- | --- |
| `probe.mjs` | the **independent verifier of every `DeviceResponse`** the wallet produces (P5-03b, plan 4.14) |
| `idb-crosscheck.mjs` | runs the wallet harness's IndexedDB scenarios on `fake-indexeddb` (P5-03a review round 2) |

## `probe.mjs`

```bash
node docs/design/tools/check-offer-wallet.mjs          # writes target/wallet-samples/
cd docs/design/tools/wallet-probe && npm ci && node probe.mjs ../../../../target/wallet-samples
```

The argument is optional (the default is `<repo>/target/wallet-samples`). Each sample directory the harness writes is

```
<name>/device-response.cbor   the response, byte for byte as the page built it
<name>/transcript.json        what the page signed over: {clientId, nonce, jwkThumbprint, responseUri}
<name>/expected.json          what a verifier must do: {expect, rejectedBy, verifier, docType, elements, alg, now, iacaSha256}
<name>/iaca.pem               the trust anchor the document signer chains to
```

and the probe checks it with `@owf/mdoc` 0.9.3, the library Credo's OpenID4VP verifier uses:

- **the transcript is the probe's own.** It builds the OpenID4VP 1.0 Appendix B.2.6.1 `SessionTranscript` with the
  library's `SessionTranscript.forOid4Vp` from `expected.verifier`, so a page that signed another transcript (another
  `client_id`, `nonce`, `response_uri` or JWK thumbprint) cannot agree with itself. The same call reproduces the
  appendix's own test vectors, which `check-offer-wallet.mjs` asserts byte for byte.
- **the response is verified end to end**: `Verifier.verifyDeviceResponse` with `trustedCertificates: [{issuance:
  [iaca]}]` and `now` from the sample's clock. That covers the IssuerAuth signature and the x5chain to the fixture
  IACA, every disclosed item's digest against the MSO's `valueDigests` (over the bytes as received, so a re-encoded
  item fails), the device signature over the transcript the probe computed, the docType, and the detached payload.
- **selective disclosure is checked in both directions.** The disclosed `(namespace, elementIdentifier)` set
  `@owf/mdoc` reads back must equal `expected.elements`: an element the user did not choose must not be there, and one
  they did choose must be.
- **a negative sample must fail at the check it names.** `expected.json`'s `rejectedBy` is `deviceSignature` (the
  transcript or the key is not the verifier's) or `digest` (an item was re-encoded). A sample that fails for another
  reason is a failure of the probe, not a pass.

Before the samples, the probe recomputes the OpenID4VP 1.0 Appendix B.2.6.1 worked example with
`SessionTranscript.forOid4Vp` and refuses to run if the library and the appendix disagree (the page is held to the same
vectors by `check-offer-wallet.mjs`).

A run prints one line per sample and `wallet-probe: all N samples passed`; anything else exits non-zero.

### The crypto context

`@owf/mdoc` leaves cryptography to its caller, the way Credo supplies its own. This probe's context uses Node's
WebCrypto for digests and certificate signatures, `@owf/x509` (the mdoc library's own ASN.1 module) to parse
certificates and check each link of the chain, and `@noble/curves` to verify the COSE signatures an mDL carries
(ES256 and ESP256, which is what the demo's IssuerAuth and device signature use). The plan's section 4.14 note names
`@peculiar/x509` for the reference context; `@owf/x509` is used instead because it is already a dependency of
`@owf/mdoc` and checks the same structure without pulling in a second ASN.1 stack (`@peculiar/x509` 3.x also needs a
`reflect-metadata` polyfill). The verification itself is still `@owf/mdoc`'s, which is what the gate is about.
