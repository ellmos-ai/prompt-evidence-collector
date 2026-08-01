# prompt-evidence-collector

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
- Passiver Clutch-Consumer: prüft Locator-Schema, opaque URI und Content-Hash;
  der Aufrufer stellt den rein lokalen Resolver bereit

Status: Extraktion aus `ellmos-core@03f6f58` (Service
`ellmos_core.services.prompt_evidence`), Code unverändert bis auf den
Store-Namespace (`APP_DIR = "prompt-evidence-collector"`). Die
ellmos-core-Fassung bleibt vorerst bestehen; ein Cutover ist ein eigener,
gegateter Schritt.

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

Diese API ist nur der Integrationsvertrag. Sie öffnet selbst keine Datenbank,
kein Netzwerk und keinen Provider-Hook. Live-Capture und Cutover benötigen
weiterhin ein eigenes Trust- und Aktivierungs-Gate.

## Entwicklung

```bash
pip install -e .
python -m pytest -q
```
