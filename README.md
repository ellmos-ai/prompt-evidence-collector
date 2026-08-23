<img src="assets/banner.png" width="100%" alt="prompt-evidence-collector banner">

# prompt-evidence-collector

[![English](https://img.shields.io/badge/Language-English-blue.svg)](README.md)
[![Deutsch](https://img.shields.io/badge/Sprache-Deutsch-de.svg)](README_de.md)
[![Version](https://img.shields.io/badge/Version-0.4.0-informational.svg)](pyproject.toml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-139%20Passed-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Local--First%20%2F%20Zero--Egress-success.svg)](SECURITY.md)
[![Ecosystem](https://img.shields.io/badge/Ecosystem-ellmos--ai-purple.svg)](https://github.com/ellmos-ai)
[![Umbrella](https://img.shields.io/badge/Umbrella-open--bricks-informational.svg)](https://github.com/open-bricks)
[![LLM-Ready](https://img.shields.io/badge/LLM--Ready-llms.txt-orange.svg)](llms.txt)

> [!NOTE]
> **LLM / AI context file available:** [`llms.txt`](llms.txt) contains the
> machine-readable architecture and boundary summary.

Standalone, cloud-safe prompt and workflow evidence module extracted from
`ellmos-core`. It stores raw text only in a hardened, application-owned local
data directory and exposes hash-only receipts. It never uploads raw text or
automatically promotes evidence into a library, policy, or user decision.

- Raw store: `<local-app-data>/prompt-evidence-collector/prompt-evidence/`
- Fail-closed on unsafe storage, ambiguous evidence, or integrity violations
- Passive by default: no daemon, scheduler, telemetry, or network access
- Fixed internal Clutch resolver registry; callers cannot inject a live resolver
- Authorized capture with a signed one-shot `CaptureGrant`, immutable runtime
  receipt, private trust store, and atomic SQLite replay protection

The extraction is based on `ellmos-core@03f6f58`. The original implementation
remains in place until a separate, explicitly authorized cutover is completed.

## Installation

Python 3.11 or newer is required. Installation alone does not provision trust,
start capture, or create background activity.

```bash
python -m pip install -e .
python -m prompt_evidence_collector.cli doctor
```

## Authorized one-shot capture

```python
result = collector.authorize_and_capture_from_locator(
    locator=clutch_locator,
    grant=signed_capture_grant,
    resolver_runtime_receipt=signed_runtime_receipt,
)
```

Before the resolver is called, this path validates:

- the Ed25519 signature against the private local trust store;
- the exact provider, locator, hash, purpose, sensitivity, and retention scope;
- a Grant lifetime of at most one hour, `one_shot=true`, and `max_captures=1`;
- the signed immutable resolver receipt, including module, export, callable,
  and adapter hashes; and
- atomic reservation in the private SQLite ledger. `prepared` is recoverable
  only idempotently; `consumed` and `failed` are terminal.

The consumption receipt contains only stable codes, opaque IDs, and hashes.
Capture always starts as `not-reviewed`. Valid authority sources are an
explicit user decision, an explicit capture policy, or an authorized delegated
decision avatar. A prediction or caller-supplied claim alone authorizes nothing.

Live activation, trust-key provisioning, and the core cutover are separate
gated operations. The low-level capture helpers are not public API.

## Explicit curated gate and storage integrity

Every capture API rejects caller-selected `rejected`, `candidate`, and
`curated` promotion states. Promotion is a separate local
`PromptEvidenceCollector.transition_promotion(...)` operation requiring a
self-bound `PromotionGate` with the opaque evidence ID, source and target
states, an explicit authority source, authorization reference, and UTC time.

Allowed transitions are `not-reviewed -> rejected|candidate` and
`candidate -> rejected|curated`. Missing, malformed, stale, or conflicting
gates fail closed with `PromotionGateError`. A successful transition preserves
the evidence ID, content hash, receipt schema, and raw object; only a hash- and
ID-only audit receipt is added.

Raw content has an exact byte contract: non-empty text is encoded strictly as
UTF-8, hashed, written, and read without newline normalization. LF, CRLF, mixed
line endings, trailing newlines, and Unicode round-trip byte-for-byte. Changed
bytes or invalid UTF-8 fail with `EvidenceIntegrityError`.

Raw content and evidence receipts use a durable pair protocol. Temporary files
are flushed and synced inside their bound directories, published without
replacement, and committed by a hash-only pair manifest. Pending, temporary,
or orphaned objects are never auto-deleted.

`prompt-evidence-collector doctor` emits the stable
`ellmos.prompt-evidence-collector-doctor.v3` schema. It validates complete
pairs and reports incomplete pairs, invalid receipts, hash mismatches, orphans,
pending or temporary files, unknown objects, and reparse objects. It never
returns raw content or provider URIs and never repairs an unsafe store
automatically. Invalid state returns exit code `3`.

## Read-only authorization preflight

The CLI can inspect the existing canonical private app store without creating
files or accepting a caller-selected trust root:

```bash
python -m prompt_evidence_collector.cli authorization-preflight
python -m prompt_evidence_collector.cli authorization-validate \
  --grant capture-grant.json \
  --runtime-receipt resolver-runtime-receipt.json
```

`authorization-preflight` validates store binding, ACL or mode, reparse and
symlink boundaries, trust schema, key fingerprints, roles, authority scopes,
and validity windows. Windows requires private ownership and ACLs for the store,
trust directory, and trust file; POSIX requires private modes. POSIX discovery
is bound to the native account home, so redirected `HOME` or `XDG_DATA_HOME`
values fail closed.

`authorization-validate` also checks both signed documents, their validity,
authority scope, and exact Grant-to-runtime hash binding. Neither command
imports or runs resolver code, resolves a locator, touches the replay ledger,
captures evidence, calls hooks, or uses the network. A valid result proves the
signed document binding, not the presence or health of a live resolver.

Inputs are limited to regular, single-link files of at most 1 MiB on a fixed
local drive. Symlink, reparse, UNC, remote, and known cloud/sync paths are
rejected before opening. Stable exit codes are `0` valid, `2` invalid input,
`3` unavailable or unsafe trust store, `4` invalid signature, `5` expired or
not current, and `6` scope or binding mismatch.

## Fail-closed trust enrollment

Version 0.4 provides a separate plan/apply path for enrolling capture-authority
and runtime-release **public keys**:

```bash
python -m prompt_evidence_collector.cli trust-enroll plan \
  --proposal trust-proposal.json
python -m prompt_evidence_collector.cli trust-enroll apply \
  --proposal trust-proposal.json \
  --activation signed-trust-activation.json \
  --expected-plan-sha256 <sha256>
```

`plan` is deterministic and read-only. Its output contains fingerprints and
bounded scope codes, never paths, public-key values, signatures, or private
material. `apply` accepts no caller-selected trust root. It requires an
Ed25519-signed activation bound to the configured bootstrap decision reference,
the exact host and system, proposal, plan hash, and validity window. The signer
must already be pinned in the fixed private bootstrap trust file.

The resulting V2 trust store enforces provider, purpose, sensitivity,
retention, one-shot cardinality, and maximum Grant TTL. Publication is atomic,
no-overwrite, and followed by ACL/mode and hash readback. It creates no capture
ledger, evidence, receipt, hook, scheduler, or network activity.

Before any capture state exists, `trust-enroll rollback
--expected-trust-sha256 <sha256>` removes only the exact unchanged enrollment.
After capture state exists, keys require a signed retirement revision; evidence
and ledgers are never deleted by rollback. The module does not generate, store,
or rotate private keys and cannot self-bootstrap its first issuer.

## Security and operating boundaries

| This component is | This component is not |
|---|---|
| A local evidence store with explicit cryptographic authorization | A surveillance, key-management, or background capture service |
| A hash-only receipt producer | A prompt library, policy registry, or decision authority |
| A passive component for deployment-owned workflows | Permission to monitor third parties or capture without consent |
| A building block with fail-closed validation | A complete AI system or authorization for a deployment context |

Do not use it to capture another person's content without authorization, as a
substitute for consent or retention policy, or as an automatic execution gate.
For the component-versus-system boundary and excluded high-risk contexts, see
the [EU AI Act note](docs/ai-act-note.md). Security issues must follow
[`SECURITY.md`](SECURITY.md); never place sensitive evidence in a public issue.

## Bundle and partners

The collector is the recommended `capture` component of the
`ellmos-prompt-workflow-bundle`. A deployment-owned bundle manifest remains
authoritative for membership and compatible versions. Direct integration
roles are:

- workflow and context gates;
- the curated prompt-library authority;
- an optional local locator or session producer such as Clutch;
- an optional authorized decision avatar or preference model;
- extraction and text-hygiene skills; and
- optional local prompt clients.

The collector remains independently installable. Bundle membership transfers
no prompt-library, policy, decision, user-model, or private-key authority.

### Related ecosystem tools

| Repository | Purpose | Primary focus |
|---|---|---|
| `ellmos-core` (deployment-provided) | Core runtime and prompt library | Agent runtime, prompt management, local workflows |
| [`clutch`](https://github.com/ellmos-ai/clutch) | Provider switching and multi-LLM engine | Model routing, streaming, structured output |
| [`workflowhooker`](https://github.com/ellmos-ai/workflowhooker) | Transparent workflow interception | Deterministic interception and lifecycle auditing |
| [`memoryhooker`](https://github.com/ellmos-ai/memoryhooker) | Context and memory interception | Memory lifecycle hooks and boundary protection |
| [`policy-registry`](https://github.com/ellmos-ai/policy-registry) | Policy registration and validation | Multi-agent governance and policy lifecycle |
| [`sqlite-transit-sync`](https://github.com/ellmos-ai/sqlite-transit-sync) | SQLite replication and synchronization | Bidirectional diffs and transit synchronization |
| [`system-gap-master`](https://github.com/ellmos-ai/system-gap-master) | Gap analysis and architecture audit | Architecture parity and invariant verification |

## Development

### CI and release parity

The CI matrix runs on Python 3.11 and 3.12 under Ubuntu, Windows, and macOS.
Every job installs the declared development dependencies, runs Ruff, executes
pytest with visible platform skips, and performs a passive Doctor smoke. No CI
job starts capture, network access, or cutover.

The single version source is
`src/prompt_evidence_collector/_version.py`. Build metadata, package import,
and `ellmos-module.v2.json` are checked by `tests/test_release_parity.py`.

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q -ra
python -m prompt_evidence_collector.cli doctor
```

## License and provenance

Project-owned code, documentation, and examples are available under the
[`MIT License`](LICENSE). Third-party packages retain their own licenses; the
verified dependency inventory is in
[`THIRD_PARTY_LICENSES.txt`](THIRD_PARTY_LICENSES.txt). AI-assisted changes are
reviewed and accepted by a human maintainer; no claim is made over third-party
material merely because an AI tool processed it.

## Contributing and community

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the test and pull-request workflow
and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) for community expectations.

## Architektur- und Sicherheitsgarantien

Standalone extraction from ellmos-core@03f6f58. Raw prompt/session text never leaves the local store; outbound artifacts are hashed receipts only. Default-passive: no scheduler, no network and no automatic promotion. Capture persists not-reviewed only; candidate/curated changes require an explicit, auditable PromotionGate with documented authority, allowed transitions not-reviewed->rejected|candidate and candidate->rejected|curated, and the PromotionGateError failure class; receipt schema/ID integrity is preserved. Raw content is hashed and round-tripped as exact UTF-8 bytes without newline normalization. Raw and receipt publication is a durable, no-overwrite pair protocol with a hash-/ID-only manifest; Doctor v3 verifies every receipt/raw/pair, reports invalid/orphaned/reparse/temp objects fail-closed, and never auto-deletes them. CI runs Ruff, pytest with Windows/POSIX/macOS matrix gates, and a passive Doctor smoke; package version derives from src/prompt_evidence_collector/_version.py and is checked against build metadata and this manifest. Trust enrollment is plan/apply, Ed25519-approved through a fixed private bootstrap trust file, atomic, no-overwrite and public-key-only. Live locator capture requires a signed one-shot CaptureGrant, a trusted authority key, an immutable signed resolver-runtime receipt and an atomic replay ledger. Explicit user decisions, capture policies and delegated decision-avatar grants are supported as typed authority sources, but the latter authorizes only after Policy-Registry trust provisioning; a preference-model prediction alone never suffices (V4-08 contract).
