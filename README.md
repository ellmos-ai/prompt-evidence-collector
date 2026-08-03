# prompt-evidence-collector

[![English](https://img.shields.io/badge/Language-English-blue.svg)](README.md)
[![Deutsch](https://img.shields.io/badge/Sprache-Deutsch-de.svg)](README_de.md)
[![Pytest](https://img.shields.io/badge/Pytest-44%20passed-success.svg)](https://docs.pytest.org/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ecosystem](https://img.shields.io/badge/Ecosystem-ellmos--ai-purple.svg)](https://github.com/ellmos-ai)
[![Umbrella](https://img.shields.io/badge/Umbrella-open--bricks-informational.svg)](https://github.com/open-bricks)

> [!NOTE]
> **LLM / AI Context File Available**: For an AI-optimized machine-readable architectural summary of this repository, inspect [`llms.txt`](file:///llms.txt).

Eigenständiges, cloud-sicheres Prompt-/Workflow-Evidenz-Modul (aus `ellmos-core` extrahiert).

Der Collector speichert Rohtext **ausschließlich lokal** (App-eigener
Local-Data-Root, gehärtete Verzeichnisrechte) und projiziert nach außen nur
gehashte Receipts — niemals Rohtext, niemals automatisch in eine Bibliothek
oder eine Nutzerentscheidung (Vertrag V4-08).

- Raw-Store: `<local-app-data>/prompt-evidence-collector/prompt-evidence/`
- Fail-closed bei unsicheren Stores, fehlender oder mehrdeutiger Evidenz und
  Integritätsbrüchen
- Standardmäßig deaktiviert gedacht: keine Hintergrundläufe, keine Scheduler,
  keine Netzwerkzugriffe
- Feste interne Clutch-Resolver-Registry: kein vom Aufrufer einschleusbarer
  Live-Resolver
- Autorisierter Live-Pfad: signierter one-shot CaptureGrant, privater
  Trust-Store, immutable Resolver-Receipt und atomarer SQLite-Replay-Schutz

Status: Extraktion aus `ellmos-core@03f6f58` (Service
`ellmos_core.services.prompt_evidence`), Code unverändert bis auf den
Store-Namespace (`APP_DIR = "prompt-evidence-collector"`). Die
ellmos-core-Fassung bleibt vorerst bestehen; ein Cutover ist ein eigener,
gegateter Schritt.

## Autorisierter one-shot Capture

```python
result = collector.authorize_and_capture_from_locator(
    locator=clutch_locator,
    grant=signed_capture_grant,
    resolver_runtime_receipt=signed_runtime_receipt,
)
```

Dieser Pfad prüft vor dem ersten Resolveraufruf:

- Ed25519-Signatur gegen den privaten lokalen Trust-Store
- exakten Provider-, Locator-, Hash-, Zweck- und Aufbewahrungsscope
- höchstens eine Stunde Grant-Laufzeit, `one_shot=true`, `max_captures=1`
- signiertes immutable Resolver-Receipt sowie Modul, Export, Callable- und
  Adapter-Hash des intern registrierten Resolvers
- atomare Reservierung im privaten SQLite-Ledger; `prepared` ist ausschließlich
  idempotent recoverbar, `consumed` und `failed` sind terminal

Das zusätzliche Consumption-Receipt ist cloud-sicher und enthält nur Codes,
opaque IDs und Hashes. Promotion bleibt zwingend `not-reviewed`.

Zulässige Autoritätsquellen sind eine explizite Nutzerentscheidung, eine
explizite Capture-Policy oder ein delegierter Decision Avatar. Ein
Decision-Avatar-Grant gilt jedoch nur, wenn Policy Registry dessen Signierschlüssel
und Scope im lokalen Trust-Store freigegeben hat. Eine TOM_lm-Prognose oder ein
caller-supplied Claim allein autorisiert nichts. Die früheren Low-Level-
Capture-Methoden sind nicht Teil der öffentlichen Collector-API.

Live-Aktivierung, Trust-Key-Provisionierung und der ellmos-core-Cutover bleiben
eigene gegatete Schritte; standardmäßig arbeitet das Modul passiv.

## Entwicklung

```bash
pip install -e .
python -m pytest -q
```
