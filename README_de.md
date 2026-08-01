# prompt-evidence-collector

Eigenständiges, cloud-sicheres Prompt-/Workflow-Evidenz-Modul (aus `ellmos-core` extrahiert).

Der Collector speichert Rohtext **ausschließlich lokal** und projiziert nach außen nur gehashte Receipts — niemals Rohtext, niemals automatisch in eine Bibliothek oder eine Nutzerentscheidung (Vertrag V4-08).

- Raw-Store: `<local-app-data>/prompt-evidence-collector/prompt-evidence/` (gehärtete Rechte)
- Fail-closed bei unsicheren Stores, fehlender/mehrdeutiger Evidenz, Integritätsbrüchen
- Kein Hintergrundlauf, kein Scheduler, kein Netzwerk
- Passiver Clutch-Consumer mit Schema-, URI- und Hashprüfung; der Aufrufer stellt den lokalen Resolver bereit

Status: Extraktion aus `ellmos-core@03f6f58`; Code unverändert bis auf den Store-Namespace. Die ellmos-core-Fassung bleibt vorerst; Cutover ist ein eigener gegateter Schritt.

## Passiver Locator-Consumer

```python
receipt = collector.capture_from_locator(
    locator=clutch_locator,
    resolve_content=local_clutch_resolver,
    captured_at="2026-08-01T09:00:00Z",
    sensitivity_code="private",
    retention_code="local-review",
)
```

Die API öffnet selbst keine Datenbank, kein Netzwerk und keinen Provider-Hook. Live-Capture und Cutover benötigen weiterhin ein eigenes Trust- und Aktivierungs-Gate.

## Entwicklung

```bash
pip install -e .
python -m pytest -q
python -m prompt_evidence_collector.cli doctor
```
