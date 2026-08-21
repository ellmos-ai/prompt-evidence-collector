# Beitragsrichtlinie / Contributing Guide

## Deutsch

Vielen Dank für Ihr Interesse an `prompt-evidence-collector`.

### Vor einem Beitrag

1. Lesen Sie [`README_de.md`](README_de.md) und [`SECURITY.md`](SECURITY.md).
2. Legen Sie niemals echten Prompt-Rohtext, Schlüssel, Signaturen, lokale
   Trust-Stores oder personenbezogene Daten in Issues, Fixtures oder Commits ab.
3. Melden Sie Sicherheitslücken vertraulich über GitHub Security Advisories,
   nicht als öffentliches Issue.

### Entwicklungsablauf

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q -ra
python -m prompt_evidence_collector.cli doctor
```

Pull Requests sollen klein und nachvollziehbar sein. Neue Capture-,
Trust- oder Promotionspfade benötigen negative Fail-closed-Tests und dürfen
keinen Netzwerk-, Scheduler- oder Hintergrundpfad einführen. Testschlüssel und
Testinhalte müssen synthetisch sein.

Beiträge werden unter der MIT-Lizenz dieses Projekts eingereicht, sofern keine
separate schriftliche Vereinbarung besteht.

---

## English

Thank you for your interest in `prompt-evidence-collector`.

### Before Contributing

1. Read [`README.md`](README.md) and [`SECURITY.md`](SECURITY.md).
2. Never place real raw prompts, keys, signatures, local trust stores, or
   personal data in issues, fixtures, or commits.
3. Report vulnerabilities privately through GitHub Security Advisories, not as
   a public issue.

### Development Workflow

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q -ra
python -m prompt_evidence_collector.cli doctor
```

Keep pull requests small and auditable. New capture, trust, or promotion paths
need negative fail-closed tests and must not introduce network, scheduler, or
background behavior. Test keys and test content must be synthetic.

Contributions are submitted under this project's MIT License unless a separate
written agreement applies.
