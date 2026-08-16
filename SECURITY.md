# Security Policy / Sicherheitsrichtlinien

## English

### Local-First & Zero-Egress Security Invariants

`prompt-evidence-collector` is designed with strict security invariants for local-only prompt and workflow evidence collection:

1. **Local-First Storage**: Raw prompt and workflow text is saved strictly inside the host's private local application directory (`<local-app-data>/prompt-evidence-collector/prompt-evidence/`) with hardened OS file access control lists (Windows ACLs) or restrictive POSIX permissions (`0700` / `0600`).
2. **Zero-Egress Invariant**: The module does not execute background daemons, network sockets, or remote egress calls. Raw prompt text is never transmitted across the network or projected to external services.
3. **Hash-Only Projection**: External projections and receipts contain only opaque identifiers, status codes, and SHA-256 cryptographic hashes—never raw content.
4. **Cryptographic Authorization**: Captures require Ed25519-signed `CaptureGrant` verification against the local trust store with a maximum 1-hour TTL, strict purpose scoping, and atomic SQLite replay protection (`prepared`, `consumed`, `failed`).
5. **Fail-Closed Design**: Any integrity discrepancy (corrupted hash, missing pair manifest, untrusted signing key, invalid ACL/permissions) causes the module to immediately fail-closed without persisting or projecting invalid evidence.

### Reporting a Vulnerability

If you discover a potential security vulnerability in `prompt-evidence-collector`, please report it responsibly:

- **Private Reporting**: Do **NOT** file a public GitHub issue for security vulnerabilities.
- **Contact**: Submit details via [GitHub Security Advisories](https://github.com/ellmos-ai/prompt-evidence-collector/security/advisories) or privately to the project maintainers.
- **Response Timeline**: We acknowledge vulnerability reports within 48 hours and provide remediation status updates.

---

## Deutsch

### Local-First- und Zero-Egress-Sicherheitsinvariante

`prompt-evidence-collector` folgt strengen Sicherheitsrichtlinien für die rein lokale Erfassung von Prompt- und Workflow-Evidenzen:

1. **Lokaler Speicher**: Rohtext wird ausschließlich im privaten lokalen Anwendungsdatenverzeichnis (`<local-app-data>/prompt-evidence-collector/prompt-evidence/`) mit restriktiven Dateizugriffsrechten (Windows ACLs bzw. POSIX `0700` / `0600`) abgelegt.
2. **Zero-Egress-Invariante**: Das Modul betreibt keine Hintergrunddienste, öffnet keine Netzwerkverbindungen und sendet keine Telemetriedaten. Rohtexte verlassen das lokale System niemals über das Netzwerk.
3. **Hash-Projektion**: Nach außen projizierte Nachweise (Receipts) enthalten ausschließlich opake Kennungen, Statuscodes und kryptografische SHA-256-Hashes – niemals Rohtext.
4. **Kryptografische Autorisierung**: Capture-Vorgänge erfordern signierte Ed25519-`CaptureGrants`, die gegen den lokalen Trust-Store verifiziert werden (maximale TTL 1 Stunde, strikter Scope, atomarer Replay-Schutz im SQLite-Ledger).
5. **Fail-Closed-Prinzip**: Jede Integritätsverletzung (abweichender Hash, fehlendes Paar-Manifest, nicht vertrauenswürdiger Schlüssel, unzureichende Dateirechte) führt zum sofortigen kontrollierten Abbruch (Fail-Closed).

### Sicherheitslücken melden

Wenn Sie eine potenzielle Sicherheitslücke entdecken:

- **Vertrauliche Meldung**: Bitte eröffnen Sie **keine** öffentlichen GitHub-Issues für Sicherheitslücken.
- **Kontakt**: Nutzen Sie die [GitHub Security Advisories](https://github.com/ellmos-ai/prompt-evidence-collector/security/advisories) oder wenden Sie sich direkt vertraulich an die Maintainer.
- **Reaktionszeit**: Sicherheitsmeldungen werden innerhalb von 48 Stunden bestätigt.
