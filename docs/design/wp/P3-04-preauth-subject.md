# P3-04 A subject in the pre-authorized offer

Branch: `wp/p3-04-preauth-subject` off `design/extensibility`. Phase 3 (`certify-as`). Size: XS. Depends on: nothing new.

## Goal

The owner wants the CSV data provider (and every plugin that resolves a record by the access token's `sub`, as eSignet sets it) to work in the pre-authorized code flow without eSignet. Today Certify's own authorization server puts the offer's claims JSON in `sub`, which no such plugin can resolve.

## Scope

- `POST /pre-authorized-data` takes an optional `subject`: the identifier the data provider resolves (the CSV row id, the individual id). It is stored with the pre-authorized code and becomes the access token's `sub`; `claims` are then optional (bean validation still refuses an offer with neither). An offer with claims keeps today's behaviour (claims JSON in `sub`, `PreAuthDataProviderPlugin` reads them from the cache).
- Compose `rebuild` profile: the farmer profile's CSV plugin stays; VALIDATE.md step 5 shows the `subject` offer first; `docs/design/tools/smoke.py` takes the subject as its third argument and checks that every template field resolved.
- Tests: controller (subject-only offer accepted), service (no claim validation with a subject; the subject reaches `generateSignedJwt`), the compose smoke run with the CSV row `2154189532`.

## Acceptance criteria

- [x] `PreAuthorizedCodeControllerTest`, `PreAuthorizedCodeServiceTest`, `IssuanceGoldenTest`, `OAuthControllerTest` green; the v1 token golden unchanged.
- [x] Compose smoke run with the CSV plugin and a subject offer: both surfaces issue a credential with every template field resolved.
- [x] Full `certify-service` suite green (988 tests, 0 failures); CI pending.
