# prompt-evidence-collector

Eigenständiges, cloud-sicheres Prompt-/Workflow-Evidenz-Modul (aus `ellmos-core` extrahiert).

Der Collector speichert Rohtext **ausschließlich lokal** und projiziert nach außen nur gehashte Receipts — niemals Rohtext, niemals automatisch in eine Bibliothek oder eine Nutzerentscheidung (Vertrag V4-08).

- Raw-Store: `<local-app-data>/prompt-evidence-collector/prompt-evidence/` (gehärtete Rechte)
- Fail-closed bei unsicheren Stores, fehlender/mehrdeutiger Evidenz, Integritätsbrüchen
- Kein Hintergrundlauf, kein Scheduler, kein Netzwerk
- Feste interne Clutch-Resolver-Registry; kein vom Aufrufer einschleusbarer Live-Resolver
- Autorisierter Live-Pfad mit signiertem one-shot CaptureGrant, privatem Trust-Store, immutable Resolver-Receipt und atomarem SQLite-Replay-Schutz

Status: Extraktion aus `ellmos-core@03f6f58`; Code unverändert bis auf den Store-Namespace. Die ellmos-core-Fassung bleibt vorerst; Cutover ist ein eigener gegateter Schritt.

## Autorisierter one-shot Capture

```python
result = collector.authorize_and_capture_from_locator(
    locator=clutch_locator,
    grant=signed_capture_grant,
    resolver_runtime_receipt=signed_runtime_receipt,
)
```

Vor dem ersten Resolveraufruf werden Ed25519-Signatur, exakter Locator-/Hash-/Zweckscope, maximal eine Stunde Grant-Laufzeit sowie Modul, Export, Callable- und Adapter-Hash des intern registrierten Resolvers geprüft. Ein privates SQLite-Ledger reserviert den Grant atomar; `prepared` ist ausschließlich idempotent recoverbar, `consumed` und `failed` sind terminal. Das zusätzliche Consumption-Receipt ist cloud-sicher, Promotion bleibt zwingend `not-reviewed`. Die früheren Low-Level-Capture-Methoden gehören nicht zur öffentlichen Collector-API.

Zulässige Autoritätsquellen sind eine explizite Nutzerentscheidung, eine explizite Capture-Policy oder ein delegierter Decision Avatar. Letzterer gilt nur nach Policy-Registry-Trust-Provisionierung; eine TOM_lm-Prognose oder ein caller-supplied Claim allein autorisiert nichts.

Live-Aktivierung, Trust-Key-Provisionierung und ellmos-core-Cutover bleiben eigene gegatete Schritte. Das Standardprofil bleibt passiv.

## Entwicklung

```bash
pip install -e .
python -m pytest -q
python -m prompt_evidence_collector.cli doctor
```
