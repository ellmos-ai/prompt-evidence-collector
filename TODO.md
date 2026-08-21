# Release Readiness TODO / Aufgaben zur Veröffentlichungsreife

This file records the active private-to-public review. It is a process document,
not a release certificate. Public visibility, tags, and releases remain disabled
until the owner closes the explicit decision gates below.

Diese Datei dokumentiert die laufende Prüfung vom privaten zum öffentlichen
Repository. Sie ist ein Prozessdokument und kein Release-Zertifikat. Öffentliche
Sichtbarkeit, Tags und Releases bleiben deaktiviert, bis der Eigentümer die unten
genannten Entscheidungsgates geschlossen hat.

## STATUS

| Category | Status | Evidence or required action |
|---|---|---|
| Current-tree privacy | PASS | No credentials, raw prompt data, local user paths, or private system names found in the tracked release surface. |
| Documentation | PASS | Structurally parallel English and German READMEs, contribution rules, security policy, component note, and dependency-license inventory are present. |
| Tests and package | PASS | 139 tests passed with 4 documented platform-specific skips; Ruff, compile, build, link checks, and wheel metadata validation passed on 2026-08-21. |
| Historical author metadata | OWNER DECISION | The Git history contains real maintainer email metadata. Do not rewrite history automatically; decide whether to retain it or create a deliberately sanitized public history. |
| Name clearance | MANUAL GATE | Exact-name checks found no package collision in the checked registries, but they are not a trademark clearance. Perform an official similarity search before commercial use or package registration. |
| Visibility and release | OWNER DECISION | Keep the repository private. A separate approval is required before changing visibility, creating a tag, publishing a package, or announcing a release. |
| Final module gate | OPEN | Rerun the binding `.MODULES` final gate after its documented broad `PRIVATE.KEY` scanner false positive is corrected under `T-20260821-895570554` or explicitly adjudicated. |

## Closed remediation items

- [x] Replace private profile and repository names in public documentation.
- [x] Remove hardcoded local paths from the public release surface.
- [x] Add portable installation, validation, and operating-boundary documentation.
- [x] Add contribution, conduct, dependency-license, and AI-component notes.
- [x] Expand runtime-data, credential, cache, build, and lock ignore rules.
- [x] Add regression tests for public files, language parity, neutral wording, and
      packaging metadata.

## Open owner gates

- [ ] Choose how to handle historical author email metadata before publication.
- [ ] Complete an official name-similarity check if commercialization or package
      registration is planned.
- [ ] Approve public visibility separately; then rerun the final gate, create the
      release certificate, tag deliberately, and verify the public repository.
