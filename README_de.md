# prompt-evidence-collector

Eigenständiges, cloud-sicheres Prompt-/Workflow-Evidenz-Modul (aus `ellmos-core` extrahiert).

Der Collector speichert Rohtext **ausschließlich lokal** und projiziert nach außen nur gehashte Receipts — niemals Rohtext, niemals automatisch in eine Bibliothek oder eine Nutzerentscheidung (Vertrag V4-08).

- Raw-Store: `<local-app-data>/prompt-evidence-collector/prompt-evidence/` (gehärtete Rechte)
- Fail-closed bei unsicheren Stores, fehlender/mehrdeutiger Evidenz, Integritätsbrüchen
- Kein Hintergrundlauf, kein Scheduler, kein Netzwerk

Status: Extraktion aus `ellmos-core@03f6f58`; Code unverändert bis auf den Store-Namespace. Die ellmos-core-Fassung bleibt vorerst; Cutover ist ein eigener gegateter Schritt.

## Entwicklung

```bash
pip install -e .
python -m pytest -q
python -m prompt_evidence_collector.cli doctor
```
