# ACTIS Generated Documentation Framework — Current Repository State

This directory houses living, dynamically maintained documentation reflecting the **actual empirical state** of the ACTIS repository today.

---

## Core Distinctions

To avoid confusion among developers, reviewers, and AI coding agents, ACTIS maintains a strict separation between three documentation domains:

| Category | Location | Purpose | Authoritative For |
|---|---|---|---|
| **Architecture** | `docs/architecture/` | Approved system blueprint, component contracts, security boundaries. | What ACTIS is designed to be. |
| **Roadmap** | `docs/roadmap/` | Chronological 4-month / 16-week daily delivery schedule. | What ACTIS will build and when. |
| **Generated / Current State** | `docs/generated/` | Empirical state of source files, active tests, schemas, and models. | What ACTIS actually is right now. |

---

## Generated Documentation Index

- [`PROJECT_STATUS.md`](./PROJECT_STATUS.md): Current development milestone, version, test counts, and progress metrics.
- [`MODULE_STATUS.md`](./MODULE_STATUS.md): Fact-based status classification of all 11 core ACTIS subsystems.
- [`DATABASE_REFERENCE.md`](./DATABASE_REFERENCE.md): Active SQLite schema, tables, column definitions, and indices.
- [`ML_REFERENCE.md`](./ML_REFERENCE.md): Active machine learning models, feature definitions, and test performance.
- [`TEST_STATUS.md`](./TEST_STATUS.md): Automated test coverage, test files, and pass/fail telemetry.
- [`CHANGELOG.md`](./CHANGELOG.md): Mirrored chronological record of all verified commits and milestones.
