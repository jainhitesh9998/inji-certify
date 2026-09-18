# P2-08 Mixed-strategy deployment test

Branch: `wp/p2-08-mixed-strategy` off `design/extensibility`. Phase 2 exit criterion. Size: XS. Depends on: P2-02 (per-row `issuance_strategy`), P2-06 (v2 API writes it), P1-15 (`LegacyExternalIssuer`).

## Goal

docs/design/11-roadmap.md names "mixed-strategy deployment test passes" as a Phase 2 exit criterion: a single deployment where one configuration renders a template from the data provider and another delegates to the legacy `VCIssuancePlugin`, both through the same core and endpoint, decided per row rather than by the global plugin mode.

## Scope

- `MixedStrategyIssuanceTest`: DataProvider plugin mode (the local profile) with a mocked `DataProviderPlugin` and a mocked `VCIssuancePlugin`; a templated configuration written through the v1 API and an `EXTERNAL` configuration with `dataSourceId: vci-plugin` written through the v2 API; both listed in the `/oid4vci` metadata; `POST /oid4vci/credential` answers the templated credential for one and the plugin's own credential for the other (holder from the proof handed to the plugin, `notification_id` on both); the v2 read shows the strategy and data source.
- No production code change was needed: `JpaConfigurationRegistry.strategyOf` prefers the row's strategy, `LegacyExternalIssuer` and `DataProviderPluginDataSource` are always registered and resolve their plugin lazily.

## Acceptance criteria

- [x] `MixedStrategyIssuanceTest` green.
- [x] Full `certify-service` suite green (979 tests, 0 failures).
- [ ] CI green on the fork.
