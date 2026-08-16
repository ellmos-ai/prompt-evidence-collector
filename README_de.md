<img src="assets/banner.png" width="100%" alt="prompt-evidence-collector Banner">

# prompt-evidence-collector

[![English](https://img.shields.io/badge/Language-English-blue.svg)](README.md)
[![Deutsch](https://img.shields.io/badge/Sprache-Deutsch-de.svg)](README_de.md)
[![Version](https://img.shields.io/badge/Version-0.4.0-informational.svg)](pyproject.toml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-136%20Passed-brightgreen.svg)](tests/)
[![Lizenz](https://img.shields.io/badge/Lizenz-MIT-green.svg)](LICENSE)
[![Sicherheit](https://img.shields.io/badge/Sicherheit-Local--First%20%2F%20Zero--Egress-success.svg)](SECURITY.md)
[![Ökosystem](https://img.shields.io/badge/Ökosystem-ellmos--ai-purple.svg)](https://github.com/ellmos-ai)
[![Dachorganisation](https://img.shields.io/badge/Dach-open--bricks-informational.svg)](https://github.com/open-bricks)
[![LLM-Ready](https://img.shields.io/badge/LLM--Ready-llms.txt-orange.svg)](llms.txt)

> [!NOTE]
> **LLM / KI-Kontextdatei verfügbar**: Eine maschinenlesbare Architektur-Zusammenfassung dieses Repositories befindet sich in [`llms.txt`](llms.txt).

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

## Explizites Curated-Gate und Integrität des Speichers

Jeder Capture-Aufruf weist die Promotionsstatus `rejected`, `candidate` und
`curated` zurück. Captures werden als `not-reviewed` gespeichert; eine Promotion
ist die getrennte lokale Operation
`PromptEvidenceCollector.transition_promotion(...)`. Sie erfordert ein
`PromotionGate` (`ellmos.prompt-evidence-promotion-gate.v1`) mit der opaken
Evidence-ID, Quell-/Zielstatus, einem expliziten Autoritätscode, einer
Autorisierungsreferenz, UTC-Zeitstempel und einer selbstgebundenen
`pg-<sha256>`-Gate-ID. Erlaubt sind `not-reviewed -> rejected|candidate` und
`candidate -> rejected|curated`; Endzustände können nicht erneut promotet
werden. Fehlende, fehlerhafte, veraltete oder widersprüchlich wiederholte Gates
scheitern fail-closed mit `PromotionGateError`. Eine erfolgreiche Transition
bewahrt Receipt-Schema, Evidence-ID, Content-Hash und Raw-Objekt; separat wird
nur ein Receipt mit IDs/Hashes und Status im privaten Store protokolliert. Es
gibt keinen Netzwerk- oder Provider-Hook und keine Rohtextprojektion.

Rohtext hat einen expliziten Bytevertrag: Der nichtleere Python-String wird
streng als UTF-8 kodiert, genau diese Bytes werden gehasht und ohne
Zeilenendennormalisierung geschrieben und gelesen. LF, CRLF, gemischte
Zeilenenden, abschließender Umbruch und Unicode bleiben unter Windows und POSIX
unverändert. Veränderte Bytes oder ungültiges UTF-8 lösen
`EvidenceIntegrityError` aus.

Raw- und Receipt-Veröffentlichung nutzt ein privates Paarprotokoll: Temporäre
Dateien werden in den gebundenen Verzeichnissen dauerhaft geschrieben,
geflush't und synchronisiert, danach nicht überschreibend verlinkt. Ein
ID-/Hash-only-Paarmanifest wird zuletzt festgeschrieben; Pending-, temporäre
oder verwaiste Objekte werden niemals automatisch gelöscht.
`prompt-evidence-collector doctor` inventarisiert sie und liefert Exitcode `3`
bei einem unvollständigen/ungültigen Paar. Ein halbfertiges Paar gilt damit nie
als gültige Evidence.

Doctor liefert das stabile Schema
`ellmos.prompt-evidence-collector-doctor.v3` mit `status`, `code`, `exit_code`,
der Anzahl vollständig paarvalidierter Receipts
(`structural_receipt_count` wird separat ausgegeben), vollständiger/
unvollständiger Paare sowie Zählern für ungültige Receipts, Hash-/Pair-Abweichungen, Verwaiste,
Pending-/Temp-, unbekannte und Reparse-Objekte. Rohinhalte und Provider-URIs
werden nie ausgegeben; Exitcode `3` markiert den unsicheren Store, der nicht
automatisch repariert wird.

## Schreibgeschützter Autorisierungs-Preflight

Die CLI prüft den bereits vorhandenen kanonischen privaten App-Store, ohne
Dateien anzulegen und ohne einen vom Aufrufer gewählten Trust-Root zu akzeptieren:

```bash
python -m prompt_evidence_collector.cli authorization-preflight
python -m prompt_evidence_collector.cli authorization-validate \
  --grant capture-grant.json \
  --runtime-receipt resolver-runtime-receipt.json
```

`authorization-preflight` prüft die kanonische Store-Bindung, ACL bzw. Modus,
Reparse-/Symlink-Grenzen, Trust-Store-Schema, Schlüsselfingerprints, Rollen,
Autoritätsscopes und Gültigkeitsfenster. Unter Windows müssen Store-Root,
Trust-Verzeichnis und Trust-Datei privaten Owner und ACL besitzen; unter POSIX
müssen ihre Modi privat sein. Die POSIX-Auflösung ist an das native Account-Home
aus der OS-Accountdatenbank gebunden; umgeleitete `HOME`- oder
`XDG_DATA_HOME`-Werte scheitern fail-closed. `authorization-validate` prüft darüber
hinaus die Strukturen von CaptureGrant und immutable Runtime-Receipt, beide
Ed25519-Signaturen, TTLs, den Autoritätsscope und die exakte signierte
Grant-zu-Runtime-Hashbindung.

Die Read-only-Kommandos geben ausschließlich stabile Codes, Hashes, Scope, TTL
und Status aus. Pfade, Public-Key-Werte, Signaturen und Rohinhalte werden nie
ausgegeben. Die Kommandos importieren oder starten keinen Resolver, lösen keinen
Locator auf, prüfen keine Live-Runtime, berühren weder Replay-Ledger noch
Evidenzspeicher, rufen keine Hooks auf und nutzen kein Netzwerk. Ein gültiges
Ergebnis belegt daher das signierte Runtime-Receipt und dessen Grant-Bindung,
nicht Anwesenheit oder Health der referenzierten Resolver-Runtime.

Grant- und Runtime-Receipt-Eingaben müssen begrenzte (maximal 1 MiB), reguläre
Single-Link-Dateien auf einem festen lokalen Laufwerk sein. Symlink-/Reparse-,
UNC-/Remote- und bekannte Cloud-/Sync-Pfade werden vor dem Öffnen abgelehnt;
dadurch entstehen weder Hydration noch Netzwerkzugriff.

Stabile Exitcodes: `0` gültig, `2` ungültige Eingabe, `3` privater Trust-Store
ungültig/nicht verfügbar, `4` Signatur ungültig, `5` abgelaufen/nicht aktuell
und `6` Scope- oder Binding-Abweichung. Die Aktualitätsprüfung verwendet immer
die aktuelle UTC-Uhr des Hosts; die CLI akzeptiert keinen vom Aufrufer gewählten
Prüfzeitpunkt.

## Fail-closed Trust-Enrollment

Version 0.4 ergänzt einen getrennten Plan/Apply-Pfad zur Aufnahme öffentlicher
Capture-Authority- und Runtime-Release-Schlüssel:

```bash
python -m prompt_evidence_collector.cli trust-enroll plan \
  --proposal trust-proposal.json
python -m prompt_evidence_collector.cli trust-enroll apply \
  --proposal trust-proposal.json \
  --activation signed-trust-activation.json \
  --expected-plan-sha256 <sha256>
```

`plan` ist deterministisch und vollständig read-only. Die Ausgabe enthält nur
Fingerprints und begrenzte Scope-Codes, aber keine Pfade, Public-Key-Werte,
Signaturen oder privaten Daten. `apply` akzeptiert keinen vom Aufrufer gewählten
Trust-Root. Erforderlich ist eine Ed25519-signierte Aktivierung, die an
`D-20260731-004`, den exakten Host und das System, Proposal, Plan-Hash und das
Gültigkeitsfenster gebunden ist. Der Signierer muss bereits in der festen
privaten Datei `bootstrap/trust-activation-authorities.v1.json` unter dem
kanonischen App-Store gepinnt sein.

Der erzeugte V2-Trust-Store erzwingt Provider, Zweck, Sensitivität, Retention,
One-shot-Kardinalität und maximale Grant-TTL. Die Veröffentlichung ist atomar,
überschreibt nie und liest ACL/Modus sowie Hash zurück. Sie aktiviert weder
Ledger noch Evidenz, Receipts, Hooks, Scheduler oder Netzwerk. Vor dem ersten
Capture-State kann `trust-enroll rollback --expected-trust-sha256 <sha256>` nur
die exakt unveränderte Aufnahme entfernen. Danach müssen Schlüssel über eine
signierte Revision stillgelegt werden; Evidenz und Ledger werden nie gelöscht.

Das Modul erzeugt, speichert oder rotiert keine privaten Schlüssel und kann
seinen ersten Issuer nicht selbst autorisieren. Die Provisionierung der festen
Bootstrap-Trust-Datei bleibt Aufgabe der externen Systemautorität und
Schlüsselverwahrung. Allein die Installation dieser Version aktiviert keinen
Live-Trust.

## Bundle und Partner

Dieses Modul ist die empfohlene private Evidenzkomponente des
`ellmos-prompt-workflow-bundle` im Profil `capture`. Für Mitgliedschaft und
kompatible Versionen ist das Bundlemanifest im Repository
`ellmos-development-system` autoritativ. Direkte Partner sind:

- erforderliche Workflow- und Kontextgates: `WORKFLOWHOOKER`, `memory-hooker`;
- Autorität der kuratierten Bibliothek: `ellmos-core`;
- optionaler lokaler Locator-/Session-Produzent: `clutch`;
- optionale personalisierte Methode: `build-your-users-mind`;
- empfohlene Extraktions-/Hygiene-Skills: `workflow-extract`,
  `skill-extractor`, `llm-text-hygiene`;
- optionale Clients: ProfiPrompt und PromptBoard.

Der Collector bleibt einzeln installierbar. Die Bundlemitgliedschaft überträgt
keine Promptbibliothek-, Policy-, Decision-, Nutzermodell- oder
Private-Key-Autorität auf dieses Modul.

### Verwandte Ökosystem-Werkzeuge

| Repository | Zweck | Hauptfokus |
|---|---|---|
| [`ellmos-core`](https://github.com/ellmos-ai/ellmos-core) | Kern-Laufzeit & Prompt-Bibliothek | Agenten-Laufzeit, Prompt-Verwaltung, lokale Workflows |
| [`clutch`](https://github.com/ellmos-ai/clutch) | Provider-Switching & Multi-LLM Engine | Modell-Routing, Streaming, strukturierte Ausgaben |
| [`workflowhooker`](https://github.com/ellmos-ai/workflowhooker) | Transparente Workflow-Interzeption | Deterministische Interzeption & Lebenszyklus-Auditing |
| [`memoryhooker`](https://github.com/ellmos-ai/memoryhooker) | Kontext- & Speicher-Interzeption | Speicher-Lebenszyklus-Hooks & Grenzenschutz |
| [`policy-registry`](https://github.com/ellmos-ai/policy-registry) | Richtlinien-Registrierung & Validierung | Multi-Agenten-Governance, Policy-Lifecycle |
| [`sqlite-transit-sync`](https://github.com/ellmos-ai/sqlite-transit-sync) | SQLite-Replikation & Synchronisation | Bidirektionale Diffs & Transit-Synchronisation |
| [`system-gap-master`](https://github.com/ellmos-ai/system-gap-master) | Gap-Analyse & Architektur-Auditor | Architektur-Parität & Invarianten-Verifikation |
| [`DevCenter`](https://github.com/dev-bricks/DevCenter) | Entwickler-Arbeitsplatz | Multi-Projekt-Orchestrierung & Entwickler-Werkzeuge |
| [`CodeBox`](https://github.com/dev-bricks/CodeBox) | Code-Snippet- & Scratchpad-Manager | Lokale Snippet-Organisation & Code-Scratchpads |
| [`safe-start-for-codex`](https://github.com/dev-bricks/safe-start-for-codex) | Sicherer Startup-Gatekeeper | Workspace-Integritätsprüfung & Preflight-Checks |
| [`automation-master`](https://github.com/dev-bricks/automation-master) | Workflow-Ausführungs-Orchestrator | Mehrstufige Aufgaben-Pipelines & Automation |

## Entwicklung

### CI- und Release-Parität

`.github/workflows/ci.yml` führt für Python 3.11 und 3.12 auf Ubuntu, Windows
und macOS denselben reproduzierbaren Ablauf aus: `pip install -e ".[dev]"`,
Ruff, Pytest mit sichtbaren Plattform-Skips (`-ra`) und einen passiven
`doctor`-Smoke. Der Windows-Lauf aktiviert Known-Folder- und ACL-Pfade;
POSIX-Läufe prüfen private Modi und Reparse-Grenzen. Kein Matrixlauf startet
Capture, Netzwerk oder Cutover.

Die einzige Versionsquelle ist
`src/prompt_evidence_collector/_version.py`. `pyproject.toml` leitet die
Build-Version daraus ab; Paketimport und `ellmos-module.v2.json` werden durch
`tests/test_release_parity.py` gegengeprüft.

```bash
pip install -e .
python -m pytest -q
python -m prompt_evidence_collector.cli doctor
```
