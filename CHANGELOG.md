# Changelog

All notable changes to `prompt-evidence-collector` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Rebuilt the English and German READMEs as structurally parallel public documentation.
- Replaced private profile and repository names in public-facing descriptions with neutral authority roles.
- Added package discovery metadata, public operating boundaries, and portable installation and validation examples.

### Added
- Added `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `THIRD_PARTY_LICENSES.txt`, and a bilingual EU AI Act component note.
- Added regression checks for required public files, documentation neutrality, README structure/code parity, and private runtime ignore rules.

## [0.4.0] - 2026-08-16

### Added
- Standardized Shields.io badges in `README.md` and `README_de.md` (Version, Tests, Security, Python 3.11+, Ecosystem, Umbrella, LLM-Ready).
- Added comprehensive bilingual `SECURITY.md` defining local-first, zero-egress, Ed25519 authorization, and private vulnerability disclosure policies.
- Added cross-repository ecosystem tools discovery matrices in `README.md` and `README_de.md`.
- Added automated metadata, manifest, and documentation parity test suite in `tests/test_metadata.py` (6/6 tests passing).
- Synchronized `llms.txt` discovery index with timestamp `2026-08-16` and full test coverage specifications.

### Fixed
- Replaced machine-local file scheme documentation links with portable relative links.

### Added
- Added Doctor v3 inventory/readback for structurally valid receipts, exact
  Raw/pair verification, orphan/temp/reparse/unknown-object counts, and stable
  invalid-store exit code `3`.
- Added centralized fail-closed ID/hash/code validation and boundary tests for
  non-string Locator, filter, source-pair, and Receipt fields.
- Added the Ubuntu/Windows/macOS Python 3.11/3.12 CI matrix, passive Doctor
  smoke, and a single `_version.py` source checked against package/build/
  manifest metadata.
- Added a fail-closed, auditable `PromotionGate` lifecycle for all promotion
  changes; capture remains `not-reviewed` and no raw text leaves the local store.
- Added exact UTF-8 byte hashing/readback without newline normalization for
  Windows and POSIX line-ending stability.
- Added durable, no-overwrite Raw/Receipt pair publication, pending markers,
  pair manifests, and fail-closed doctor inventory for incomplete objects.
- Added fail-closed `trust-enroll plan`, `trust-enroll apply`, and pre-capture
  `trust-enroll rollback` commands with a fixed host-local bootstrap trust root.
- Added the explicit V2 capture trust-store schema with enforced provider,
  purpose, sensitivity, retention, one-shot, and maximum Grant-TTL constraints.
- Added atomic no-overwrite publication, restrictive ACL/mode readback, and
  public-key-only activation artifacts bound to the configured bootstrap decision reference.
- Added strictly read-only `authorization-preflight` and
  `authorization-validate` commands for the canonical private app store.
- Added a reusable pure authorization validator for trust, signatures, time
  bounds, authority scope, and signed grant-to-runtime binding.
- Added stable cloud-safe validation status codes and process exit codes.
- Bound read-only discovery to the canonical OS account store; added private
  trust-directory/file validation and bounded local-only input-file gates.
- Created root `llms.txt` discovery index and structured documentation.
- Added language switcher navigation bar and GFM callout box for `llms.txt` in `README.md` and `README_de.md`.
- Added Shields.io badges for Pytest suite status (44 passed), Python 3.11+, MIT License, Ecosystem (`ellmos-ai`), and Umbrella (`open-bricks`).
- Initialized `CHANGELOG.md` to track maintenance, version alignment, and technical hygiene updates.

### Verified
- Verified 79 Pytest tests passing and 3 platform-specific tests skipped after
  adding trust-enrollment, concurrency, rollback, and V2 constraint coverage.
- Added regression coverage for valid, tampered, expired, scope-mismatched,
  side-effect-free, and path/key-leakage scenarios.
- Verified 56 Pytest tests passing and 3 platform-specific tests skipped.
- Verified `ruff check` code style compliance (0 lint issues).
