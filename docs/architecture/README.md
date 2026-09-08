# ACTIS Architecture Documentation — Source of Truth

Welcome to the official architectural documentation for **ACTIS — Automated Cyber Threat Intelligence System**.

This directory serves as the **permanent, authoritative source of truth** for the ACTIS technical design, component boundaries, threat detection pipelines, and security controls.

---

## Authority & Governance

1. **Approved Architecture**: All specifications in `docs/architecture/` describe the officially approved design for ACTIS. 
2. **Strict Architectural Integrity**: No module, interface, database schema, machine learning contract, or security boundary may be altered without explicit architectural review.
3. **Source of Truth vs. Roadmap vs. Current State**:
   - **`docs/architecture/` (Source of Truth)**: Defines the approved system blueprint and security constraints.
   - **`docs/roadmap/` (Development Plan)**: Defines the chronological 4-month / 16-week daily delivery sequence.
   - **`docs/generated/` (Actual Current State)**: Reflects the verified, empirical state of the repository today.
4. **Mandatory Review for AI Coding Agents**: All AI coding agents operating on the ACTIS codebase **must** consult these architectural documents prior to implementing features or proposing structural modifications.

---

## Architectural Index

| Document | Focus |
|---|---|
| [`system-architecture.md`](./system-architecture.md) | High-level system topology, scanner ingest, detection layers, and central threat-sharing architecture. |
| [`module-architecture.md`](./module-architecture.md) | Responsibilities, inputs, outputs, dependencies, and constraints for each module. |
| [`project-structure.md`](./project-structure.md) | Standard repository directory layout, component purposes, and implementation status. |
| [`detection-workflow.md`](./detection-workflow.md) | Multi-criteria evidence fusion pipeline (scanners, ML, heuristics, threat intelligence, risk engine). |
| [`data-flow.md`](./data-flow.md) | Data movement through the system and strict privacy boundaries. |
| [`threat-intelligence-workflow.md`](./threat-intelligence-workflow.md) | Local indicator storage, verification lifecycle (`CONFIRMED`, `SUSPICIOUS`, etc.), and backend sync. |
| [`ml-workflow.md`](./ml-workflow.md) | Feature extraction, model contracts, training pipelines, and inference schemas. |
| [`scanning-workflow.md`](./scanning-workflow.md) | Operational pipelines for URL, message, file, device, file watcher, and clipboard scanners. |
| [`security-boundaries.md`](./security-boundaries.md) | Non-negotiable security boundaries, read-only guarantees, and safety controls. |

---

## Rules for AI Coding Agents

Every AI assistant or autonomous agent working on ACTIS must strictly adhere to the following governance principles:

1. **Read Architecture First**: Review relevant architecture documents before changing or creating ACTIS components.
2. **Read the Roadmap**: Consult `docs/roadmap/` before starting work to confirm the authorized scope of the assigned day/week.
3. **Work Only on Assigned Scope**: Focus exclusively on the assigned development day. Do not work ahead or pull future-week items into the current turn.
4. **Do Not Implement Future Items**: Never implement future roadmap items simply because a file exists or an import is convenient.
5. **No Silent Architectural Alterations**: Do not change architectural decisions, data models, or core abstractions silently.
6. **Accurate Implementation Claims**: Never claim a component is implemented merely because its file exists or is planned. Distinguish `IMPLEMENTED`, `PARTIALLY IMPLEMENTED`, and `PLANNED`.
7. **Inspect Before Replacing**: Inspect existing codebase implementations before creating replacements or new scripts.
8. **Preserve Existing Functionality**: Ensure all changes maintain 100% regression fidelity for pre-existing tests.
9. **Zero Unnecessary Dependencies**: Avoid introducing third-party packages unless strictly required and authorized.
10. **Respect Security Boundaries**: Enforce strictly read-only inspection; never execute, delete, rename, encrypt, or upload user files.
11. **Atomic Conventional Commits**: Every commit must be atomic, reviewable, and follow Conventional Commits syntax (`feat:`, `chore:`, `test:`, `docs:`, `fix:`, `refactor:`).
12. **Continuous Documentation**: Keep `docs/CHANGELOG.md` and `docs/generated/` synchronized with actual commit history and verification state.
13. **Mandatory Test Verification**: Run the automated test suite (`pytest tests/`) after changes; never claim a test passed without running it.
14. **Transparent Warning Reporting**: Never suppress or conceal warnings from compilers, Linters, or Git; report them explicitly.
15. **Zero Force-Pushing**: Never use `git push --force`, `-f`, or `--force-with-lease`. Never overwrite remote GitHub history.
16. **Absolute Secret Isolation**: Never hardcode or commit API keys, tokens, certificates, or `.env` files.
17. **No Catch-All Commits**: Never use `git add .` or `git add -A`. Stage files explicitly by path (`git add <specific-file>`).
