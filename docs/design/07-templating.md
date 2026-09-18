# Templating extensibility

> Part of the Inji Certify extensibility design. Baseline: `develop` at `a1cfd63` (1.0.0-beta.1-SNAPSHOT). Index: [README.md](./README.md).

One Velocity string template per configuration produces the whole credential document, the engine that renders it is also the only path to configuration, and the template author is responsible for format correctness. The design below splits envelope from claims, makes the engine a plugin, validates output, and stores templates as versioned rows instead of base64 blobs.

How templating works on develop, step by step:

1. The template is base64 text in `credential_config.vc_template`, one per configuration; QR settings are a JSONB list rendered as a second Velocity template (`formatQRData`, `VelocityTemplatingEngineImpl.java:265-284`).
2. The model is the data-provider JSON flattened to top-level keys, plus `_issuer`, `_holderId`, `validFrom`, `validUntil`, `credentialId` (only when `id-field-prefix-uri` is set), `_dateTool`, `_esc`, `_renderMethodSVGdigest`, a `rootContext` copy of the whole map, `envConfigs` from `mosip.certify.data-provider-plugin.velocity-template.env-configs.*`, and format extras `_doctype` or `vct`, `cnf`, `iss` (`CertifyIssuanceServiceImpl.java:256-305`). Quoting is decided by Java type in `CredentialUtils.toJsonMap` (`:115-143`).
3. The rendered string is parsed with `new JSONObject(...)`; then `id` is injected (`:243-245`), `credentialStatus` only when present and `templateName` contains the VC 2.0 context URL (`:246-248`), and `vct`, `cnf`, `iss` when all three are present (`:249-254`).
4. SD-JWT: `sd_claim` is a comma list of JSON paths, validated against the rendered document (`SDJWT.java:85-89`) and turned into disclosures by `SDJsonUtils`.
5. mDoc: the template must emit `validityInfo`, `docType` and `nameSpaces`; the sentinel strings `${_validFrom}`, `${_signed}`, `${_validUntil}` are replaced by CBOR-tagged dates (`MDocProcessor.java:61-120`), validity from `MDocConfig.validityPeriodYears`.
6. The SVG rendering template comes from `rendering_template` by the global property `mosip.certify.data-provider-plugin.rendering-template-id`; its digest is added for VC 2.0 only.
7. Selection is by the string key `types::contexts::format`, `format::vct` or `format::doctype` built in `CredentialUtils.getTemplateName` and parsed back in `getCachedCredentialConfig`.

Where it stops being extensible:

| Limit | Evidence | Consequence |
| --- | --- | --- |
| The template is the whole envelope | The shipped `farmer-local-config.json` template hard-codes `@context`, `type`, `issuer`, `issuanceDate`, `expirationDate` | Every spec change (VC 1.1 to 2.0, `credentialStatus`, `renderMethod`, `validFrom`) is a template edit for every issuer; VC 1.1 vs 2.0 is detected by string search |
| String templating into JSON | `_esc` is optional; a bad template throws `JSONException` per request; number vs string is a `toJsonMap` heuristic | Injection and escaping are the author's job; errors surface at issuance, not at configuration time |
| The engine is wired in | `VCFormatter` is Velocity plus 9 config getters; `Credential` takes it in the constructor; no engine id in configuration | A JSON mapping engine, a claims-only template, or a non-templated format cannot be chosen per configuration |
| No claims contract | Metadata `claims` (the column) is a hand-maintained list separate from the template; the data-provider output has no schema; the rendered document is not validated | Metadata and credential drift; SD paths are checked only after rendering |
| Global knobs | `envConfigs`, `rendering-template-id`, `vc-expiry-duration`, `id-field-prefix-uri` are properties | Cannot vary per credential type |
| No versioning or sharing | One base64 blob per configuration row; update is a full `PUT`; cache eviction needs a database lookup to compute the key | Templates cannot be reused across configurations or rolled back |
| Undocumented magic | `_`-prefixed names, mDoc sentinels, `rootContext` | Authors learn the contract from the source |
| QR is a second template pass | `formatQRData` renders JSONB settings through Velocity with `_esc` only | Same escaping class of bugs; QR-specific keys mixed into the credential model |

The target design:

```java
public interface TemplateEngine {
    String id();                                  // "velocity", "jsonmap", "passthrough"
    Set<TemplateMode> modes();                    // FULL_DOCUMENT, CLAIMS_ONLY
    RenderedDocument render(TemplateSource source, TemplateModel model);   // a JSON tree, never a String
}

public record TemplateModel(ClaimSet claims, IssuerInfo issuer, HolderBinding holder, Validity validity,
                            CredentialConfiguration config, Map<String, Object> params, Helpers helpers) {}
```

- Envelope split. The formatter owns `@context`, `type`, `issuer`, `validFrom`/`validUntil`, `credentialStatus`, `renderMethod`, `cnf`, `vct`, `iss`, mDoc `validityInfo` and `docType`; a `CLAIMS_ONLY` template produces only `credentialSubject` or the claim set. `FULL_DOCUMENT` stays for existing templates, and the post-injection of step 3 moves into the `ldp_vc` and `sd-jwt` formatters as an explicit "merge envelope over document" step.
- Output validation. A JSON Schema per format (VC 2.0 core, SD-JWT VC required claims, mDoc namespace shape) runs after render. `POST /v2/credential-configurations` dry-runs the template against sample claims at save time, so a broken template is rejected before the first wallet request.
- Storage. A `credential_template` table (`id`, `engine`, `mode`, `version`, `content` as text, `checksum`, `cr_dtimes`) referenced by `credential_config.template_id` and `template_version`; templates are shareable, versioned, cached by (id, version) with no eviction lookups. QR settings become a `claim169` listener template in the same table.
- Per-configuration knobs. Validity policy, id prefix, rendering template id and engine parameters move into `formatConfig` and `template.params`.
- A declarative engine. `jsonmap` (JSLT, JSONata or Jolt; JSLT is JVM-native and fast, JSONata has the widest tooling) produces typed JSON with no escaping class of bugs and lets SD-JWT disclosure paths be declared next to the claims they cover. Velocity stays for authors who need loops and conditionals.
- A documented model. `TemplateModel` is immutable and fully listed in the docs; `rootContext` and `envConfigs` become `params`; the `_` prefix goes.
- Tooling. `certify template render` in the CLI, golden tests per template in the configuration repository, and a preview endpoint for the admin UI.

Migration: Phase 1 turns `VCFormatter` into `TemplateEngine` (Velocity, `FULL_DOCUMENT`) and moves its nine getters to `CredentialRegistry`, with the post-injection moved into the formatters under golden tests; Phase 2 adds `credential_template` with a backfill that decodes `vc_template` from base64 into a text row and sets `template_id`, keeping `vc_template` readable until sunset; Phase 3 and later add the `jsonmap` engine, `CLAIMS_ONLY` mode, output schemas and the dry-run endpoint. `FULL_DOCUMENT` is deprecated only after every shipped sample configuration has a `CLAIMS_ONLY` equivalent.
