# Inji Certify extensibility design

Baseline: `inji/inji-certify` `develop` at commit `a1cfd63` (1.0.0-beta.1-SNAPSHOT). This folder is the source of truth for the rebuild; `AGENTS.md` at the repository root describes the code as it is today and stays the reference for existing behaviour.

| # | Document | Read it when |
| --- | --- | --- |
| 01 | [Executive summary](./01-executive-summary.md) | First |
| 02 | [Architecture as built](./02-architecture-as-built.md) | You need to know which class does what today |
| 03 | [Coupling findings](./03-coupling-findings.md) | You are touching issuance, formats, signing, config or auth |
| 04 | [Capability gaps](./04-capability-gaps.md) | You are asked why a feature is hard |
| 05 | [Target architecture](./05-target-architecture.md) | Before any Phase 1 or later work package |
| 06 | [Signing](./06-signing.md) | Anything under `certify-signing`, key providers, JWKS, DID documents, the CLI |
| 06a | [X.509 PKI and mDoc/mDL](./06a-x509-pki-and-mdoc.md) | mDoc/mDL, SD-JWT `x5c`, issuers with their own PKI or without keymanager |
| 07 | [Templating](./07-templating.md) | Anything touching Velocity, `VCFormatter`, templates, QR settings |
| 08 | [Database](./08-database.md) | Any migration, entity, cache or tenancy change |
| 09 | [API compatibility](./09-api-compatibility.md) | Any endpoint, DTO, property or plugin-interface change |
| 10 | [Testing and conformance](./10-testing-and-conformance.md) | Adding tests, CI jobs, conformance runs |
| 11 | [Roadmap](./11-roadmap.md) | Planning or picking a phase |
| 12 | [Risks and decisions](./12-risks-and-decisions.md) | Before taking a decision; append to the log after |
| 13 | [Automated development](./13-automated-development.md) | Operating the agent-driven build-out |
| 14 | [Configuration revamp](./14-configuration.md) | Any new property, `@Value`, profile or URL list |
| wp/ | [Work packages](./wp/) | Picking up a task |

Live review with comments: https://claude.ai/code/artifact/5cf478f6-018c-4079-8825-e4a837db3323
- [15. Deployment](15-deployment.md): what ships, configuration, database and the upgrade road for a running deployment.
