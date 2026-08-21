<img src="assets/banner.png" width="100%" alt="prompt-evidence-collector Banner">

# prompt-evidence-collector

[![English](https://img.shields.io/badge/Language-English-blue.svg)](README.md)
[![Deutsch](https://img.shields.io/badge/Sprache-Deutsch-de.svg)](README_de.md)
[![Version](https://img.shields.io/badge/Version-0.4.0-informational.svg)](pyproject.toml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-139%20Passed-brightgreen.svg)](tests/)
[![Lizenz](https://img.shields.io/badge/Lizenz-MIT-green.svg)](LICENSE)
[![Sicherheit](https://img.shields.io/badge/Sicherheit-Local--First%20%2F%20Zero--Egress-success.svg)](SECURITY.md)
[![Ökosystem](https://img.shields.io/badge/Ökosystem-ellmos--ai-purple.svg)](https://github.com/ellmos-ai)
[![Dachorganisation](https://img.shields.io/badge/Dach-open--bricks-informational.svg)](https://github.com/open-bricks)
[![LLM-Ready](https://img.shields.io/badge/LLM--Ready-llms.txt-orange.svg)](llms.txt)

> [!NOTE]
> **LLM-/KI-Kontextdatei vorhanden:** [`llms.txt`](llms.txt) enthält die
> maschinenlesbare Zusammenfassung von Architektur und Grenzen.

Eigenständiges, cloud-sicheres Prompt- und Workflow-Evidenzmodul, das aus
`ellmos-core` extrahiert wurde. Es speichert Rohtext ausschließlich in einem
gehärteten, anwendungseigenen lokalen Datenverzeichnis und gibt nur gehashte
Receipts aus. Rohtext wird weder hochgeladen noch automatisch in eine
Bibliothek, Policy oder Nutzerentscheidung übernommen.

- Rohdatenspeicher: `<local-app-data>/prompt-evidence-collector/prompt-evidence/`
- Fail-closed bei unsicherem Speicher, mehrdeutiger Evidenz oder Integritätsbruch
- Standardmäßig passiv: kein Dienst, Scheduler, keine Telemetrie und kein Netzwerkzugriff
- Feste interne Clutch-Resolver-Registry; Aufrufer können keinen Live-Resolver einschleusen
- Autorisierter Capture mit signiertem One-shot-`CaptureGrant`, unveränderlichem
  Runtime-Receipt, privatem Trust-Store und atomarem SQLite-Replay-Schutz

Die Extraktion basiert auf `ellmos-core@03f6f58`. Die ursprüngliche
Implementierung bleibt bestehen, bis ein eigener, ausdrücklich autorisierter
Cutover abgeschlossen ist.

## Installation

Erforderlich ist Python 3.11 oder neuer. Die Installation allein provisioniert
keinen Trust, startet keinen Capture und erzeugt keine Hintergrundaktivität.

```bash
python -m pip install -e .
python -m prompt_evidence_collector.cli doctor
```

## Autorisierter One-shot-Capture

```python
result = collector.authorize_and_capture_from_locator(
    locator=clutch_locator,
    grant=signed_capture_grant,
    resolver_runtime_receipt=signed_runtime_receipt,
)
```

Vor dem ersten Resolveraufruf prüft dieser Pfad:

- die Ed25519-Signatur gegen den privaten lokalen Trust-Store;
- den exakten Provider-, Locator-, Hash-, Zweck-, Sensitivitäts- und Aufbewahrungsscope;
- höchstens eine Stunde Grant-Laufzeit, `one_shot=true` und `max_captures=1`;
- das signierte unveränderliche Resolver-Receipt einschließlich Modul-, Export-,
  Callable- und Adapter-Hash; und
- die atomare Reservierung im privaten SQLite-Ledger. `prepared` ist nur
  idempotent wiederherstellbar; `consumed` und `failed` sind terminal.

Das Consumption-Receipt enthält ausschließlich stabile Codes, opake IDs und
Hashes. Captures beginnen immer als `not-reviewed`. Zulässige Autoritätsquellen
sind eine explizite Nutzerentscheidung, eine explizite Capture-Policy oder ein
autorisierter delegierter Decision Avatar. Eine Prognose oder ein vom Aufrufer
behaupteter Claim allein autorisiert nichts.

Live-Aktivierung, Trust-Key-Provisionierung und Core-Cutover sind getrennte,
gegatete Vorgänge. Die Low-Level-Capture-Helfer gehören nicht zur öffentlichen API.

## Explizites Curated-Gate und Speicherintegrität

Jede Capture-API weist die vom Aufrufer gesetzten Promotionszustände `rejected`,
`candidate` und `curated` zurück. Promotion ist die getrennte lokale Operation
`PromptEvidenceCollector.transition_promotion(...)` und erfordert ein
selbstgebundenes `PromotionGate` mit opaker Evidence-ID, Quell- und Zielzustand,
expliziter Autoritätsquelle, Autorisierungsreferenz und UTC-Zeitpunkt.

Erlaubt sind `not-reviewed -> rejected|candidate` und
`candidate -> rejected|curated`. Fehlende, fehlerhafte, veraltete oder
widersprüchliche Gates scheitern fail-closed mit `PromotionGateError`. Eine
erfolgreiche Transition bewahrt Evidence-ID, Content-Hash, Receipt-Schema und
Raw-Objekt; ergänzt wird nur ein Audit-Receipt mit IDs und Hashes.

Für Rohinhalte gilt ein exakter Bytevertrag: Nichtleerer Text wird streng als
UTF-8 kodiert, gehasht, geschrieben und ohne Zeilenendennormalisierung gelesen.
LF, CRLF, gemischte Zeilenenden, abschließende Umbrüche und Unicode bleiben
byteidentisch. Veränderte Bytes oder ungültiges UTF-8 lösen
`EvidenceIntegrityError` aus.

Rohinhalt und Evidence-Receipt verwenden ein dauerhaftes Paarprotokoll.
Temporäre Dateien werden in ihren gebundenen Verzeichnissen geflusht und
synchronisiert, ohne Überschreiben veröffentlicht und durch ein reines
Hash-Paarmanifest abgeschlossen. Pending-, temporäre und verwaiste Objekte
werden nie automatisch gelöscht.

`prompt-evidence-collector doctor` liefert das stabile Schema
`ellmos.prompt-evidence-collector-doctor.v3`. Es validiert vollständige Paare
und meldet unvollständige Paare, ungültige Receipts, Hashabweichungen, verwaiste,
Pending-, temporäre, unbekannte und Reparse-Objekte. Rohinhalte und Provider-URIs
werden nie ausgegeben; ein unsicherer Store wird nicht automatisch repariert
und liefert Exitcode `3`.

## Schreibgeschützter Autorisierungs-Preflight

Die CLI kann den vorhandenen kanonischen privaten App-Store prüfen, ohne Dateien
anzulegen oder einen vom Aufrufer gewählten Trust-Root zu akzeptieren:

```bash
python -m prompt_evidence_collector.cli authorization-preflight
python -m prompt_evidence_collector.cli authorization-validate \
  --grant capture-grant.json \
  --runtime-receipt resolver-runtime-receipt.json
```

`authorization-preflight` prüft Store-Bindung, ACL oder Modus, Reparse- und
Symlink-Grenzen, Trust-Schema, Schlüsselfingerprints, Rollen, Autoritätsscopes
und Gültigkeitsfenster. Unter Windows benötigen Store, Trust-Verzeichnis und
Trust-Datei private Eigentums- und ACL-Einstellungen; unter POSIX private Modi.
Die POSIX-Auflösung ist an das native Account-Home gebunden, weshalb umgeleitete
`HOME`- oder `XDG_DATA_HOME`-Werte fail-closed scheitern.

`authorization-validate` prüft zusätzlich beide signierten Dokumente, ihre
Gültigkeit, den Autoritätsscope und die exakte Grant-zu-Runtime-Hashbindung.
Beide Befehle importieren oder starten keinen Resolver, lösen keinen Locator
auf, berühren das Replay-Ledger nicht, erfassen keine Evidenz, rufen keine Hooks
auf und nutzen kein Netzwerk. Ein gültiges Ergebnis belegt die signierte
Dokumentbindung, nicht Anwesenheit oder Zustand eines Live-Resolvers.

Eingaben sind auf reguläre Single-Link-Dateien von höchstens 1 MiB auf einem
festen lokalen Laufwerk begrenzt. Symlink-, Reparse-, UNC-, Remote- und bekannte
Cloud-/Sync-Pfade werden vor dem Öffnen abgelehnt. Stabile Exitcodes sind `0`
gültig, `2` ungültige Eingabe, `3` nicht verfügbarer oder unsicherer Trust-Store,
`4` ungültige Signatur, `5` abgelaufen oder nicht aktuell und `6` Scope- oder
Binding-Abweichung.

## Fail-closed Trust-Enrollment

Version 0.4 stellt einen getrennten Plan-/Apply-Pfad zur Aufnahme öffentlicher
Capture-Authority- und Runtime-Release-Schlüssel bereit:

```bash
python -m prompt_evidence_collector.cli trust-enroll plan \
  --proposal trust-proposal.json
python -m prompt_evidence_collector.cli trust-enroll apply \
  --proposal trust-proposal.json \
  --activation signed-trust-activation.json \
  --expected-plan-sha256 <sha256>
```

`plan` ist deterministisch und vollständig read-only. Die Ausgabe enthält
Fingerprints und begrenzte Scope-Codes, jedoch keine Pfade, Public-Key-Werte,
Signaturen oder privaten Inhalte. `apply` akzeptiert keinen vom Aufrufer
gewählten Trust-Root. Erforderlich ist eine Ed25519-signierte Aktivierung, die
an die konfigurierte Bootstrap-Entscheidungsreferenz, den exakten Host und das
System, Proposal, Plan-Hash und Gültigkeitsfenster gebunden ist. Der Signierer
muss bereits in der festen privaten Bootstrap-Trust-Datei gepinnt sein.

Der erzeugte V2-Trust-Store erzwingt Provider, Zweck, Sensitivität, Retention,
One-shot-Kardinalität und maximale Grant-TTL. Die Veröffentlichung erfolgt
atomar, ohne Überschreiben und mit anschließendem ACL-/Modus- und Hash-Readback.
Sie erzeugt weder Capture-Ledger noch Evidenz, Receipts, Hooks, Scheduler oder
Netzwerkaktivität.

Vor dem ersten Capture-State entfernt `trust-enroll rollback
--expected-trust-sha256 <sha256>` nur die exakt unveränderte Aufnahme. Danach
erfordern Schlüssel eine signierte Stilllegungsrevision; Evidenz und Ledger
werden durch Rollback niemals gelöscht. Das Modul erzeugt, speichert oder
rotiert keine privaten Schlüssel und kann seinen ersten Issuer nicht selbst
autorisieren.

## Sicherheits- und Betriebsgrenzen

| Diese Komponente ist | Diese Komponente ist nicht |
|---|---|
| Ein lokaler Evidenzspeicher mit expliziter kryptografischer Autorisierung | Ein Überwachungs-, Schlüsselverwaltungs- oder Hintergrund-Capture-Dienst |
| Ein Produzent reiner Hash-Receipts | Eine Promptbibliothek, Policy-Registry oder Entscheidungsautorität |
| Eine passive Komponente für deployment-eigene Workflows | Eine Erlaubnis zur Überwachung Dritter oder Erfassung ohne Einwilligung |
| Ein Baustein mit Fail-closed-Prüfung | Ein vollständiges KI-System oder eine Autorisierung für einen Einsatzkontext |

Das Modul darf nicht zur Erfassung fremder Inhalte ohne Autorisierung, als
Ersatz für Einwilligungs- oder Aufbewahrungsregeln oder als automatisches
Ausführungsgate verwendet werden. Die Abgrenzung zwischen Komponente und System
sowie ausgeschlossene Hochrisikokontexte erläutert der
[EU-AI-Act-Hinweis](docs/ai-act-note.md). Sicherheitslücken müssen nach
[`SECURITY.md`](SECURITY.md) gemeldet werden; sensible Evidenz gehört nie in
ein öffentliches Issue.

## Bundle und Partner

Der Collector ist die empfohlene `capture`-Komponente des
`ellmos-prompt-workflow-bundle`. Ein deployment-eigenes Bundlemanifest bleibt
für Mitgliedschaft und kompatible Versionen autoritativ. Direkte
Integrationsrollen sind:

- Workflow- und Kontextgates;
- die Autorität der kuratierten Promptbibliothek;
- ein optionaler lokaler Locator- oder Session-Produzent wie Clutch;
- ein optionaler autorisierter Decision Avatar oder ein Präferenzmodell;
- Extraktions- und Texthygiene-Skills; und
- optionale lokale Prompt-Clients.

Der Collector bleibt einzeln installierbar. Bundlemitgliedschaft überträgt
keine Promptbibliothek-, Policy-, Decision-, Nutzermodell- oder
Private-Key-Autorität.

### Verwandte Ökosystem-Werkzeuge

| Repository | Zweck | Hauptfokus |
|---|---|---|
| `ellmos-core` (vom Deployment bereitgestellt) | Kernlaufzeit und Promptbibliothek | Agentenlaufzeit, Promptverwaltung, lokale Workflows |
| [`clutch`](https://github.com/ellmos-ai/clutch) | Providerwechsel und Multi-LLM-Engine | Modellrouting, Streaming, strukturierte Ausgaben |
| [`workflowhooker`](https://github.com/ellmos-ai/workflowhooker) | Transparente Workflow-Interzeption | Deterministische Interzeption und Lifecycle-Auditing |
| [`memoryhooker`](https://github.com/ellmos-ai/memoryhooker) | Kontext- und Speicherinterzeption | Speicher-Lifecycle-Hooks und Grenzschutz |
| [`policy-registry`](https://github.com/ellmos-ai/policy-registry) | Policy-Registrierung und Validierung | Multi-Agenten-Governance und Policy-Lifecycle |
| [`sqlite-transit-sync`](https://github.com/ellmos-ai/sqlite-transit-sync) | SQLite-Replikation und Synchronisation | Bidirektionale Diffs und Transit-Synchronisation |
| [`system-gap-master`](https://github.com/ellmos-ai/system-gap-master) | Gap-Analyse und Architekturaudit | Architekturparität und Invariantenprüfung |

## Entwicklung

### CI- und Release-Parität

Die CI-Matrix läuft mit Python 3.11 und 3.12 unter Ubuntu, Windows und macOS.
Jeder Job installiert die deklarierten Entwicklungsabhängigkeiten, führt Ruff
und pytest mit sichtbaren Plattform-Skips aus und startet einen passiven
Doctor-Smoke. Kein CI-Job startet Capture, Netzwerkzugriff oder Cutover.

Die einzige Versionsquelle ist
`src/prompt_evidence_collector/_version.py`. Buildmetadaten, Paketimport und
`ellmos-module.v2.json` werden durch `tests/test_release_parity.py` geprüft.

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q -ra
python -m prompt_evidence_collector.cli doctor
```

## Lizenz und Provenienz

Projekteigener Code, Dokumentation und Beispiele stehen unter der
[`MIT-Lizenz`](LICENSE). Drittanbieterpakete behalten ihre eigenen Lizenzen;
das geprüfte Abhängigkeitsinventar steht in
[`THIRD_PARTY_LICENSES.txt`](THIRD_PARTY_LICENSES.txt). KI-unterstützte
Änderungen werden von einem menschlichen Maintainer geprüft und übernommen;
allein durch KI-Verarbeitung entsteht kein Anspruch auf Drittmaterial.

## Beiträge und Community

[`CONTRIBUTING.md`](CONTRIBUTING.md) beschreibt Tests und Pull Requests,
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) die Regeln für die Community.
