# P0-06 ArchUnit module with the target dependency rules

Branch: `wp/p0-06-archunit-rules` off `develop`. Phase 0 (guardrails). Size: S. Depends on: none.

## Goal

Make the dependency direction of the target architecture executable from day one, with a shrinking allow-list for current violations.

## Scope

- New test-scoped module or package `io.mosip.certify.arch` with rules: no `org.springframework.web`, `jakarta.servlet`, `jakarta.persistence`, `org.apache.velocity`, `com.danubetech`, `foundation.identity` in `..core..` and `..signing..`; `io.mosip.kernel..` only from `..keyprovider.keymanager..`; `VCFormats` constants only from `..spi..` and `..format..`; no `switch` on format strings outside formatter packages (custom rule on string constants).
- A `known-violations.txt` frozen list (ArchUnit `FreezingArchRule`) so the build passes today and fails when a violation is added; every Phase 1 WP must shrink the list.

## Acceptance criteria

- [ ] `mvn test` runs the rules; the frozen list is committed and reviewed in every PR that changes it.

## Rules that apply

- Zero wire-byte change: goldens and signature vectors stay green.
- No edits outside the files this WP names without a note in the PR.
- Record any decision taken in `docs/design/12-risks-and-decisions.md`.
- Read `CLAUDE.md`, then `docs/design/05-target-architecture.md` and the section that owns this WP.
