# TryHackMe SOC Simulations

A portfolio of my hands-on SOC investigations in TryHackMe training environments. I document alert triage, evidence, investigation queries, findings, and response decisions while distinguishing verified observations from hypotheses.

## Case index

| Category | Investigation | Status |
|---|---|---|
| Endpoint / process analysis | [Alert 1034 — Suspicious Parent–Child Relationship](simulations/endpoint-process-analysis/alert-1034-suspicious-parent-child/README.md) | Attempted DNS exfiltration identified; correlation pending |

## Organization

Each investigation lives under `simulations/<category>/<case>/`, with its report in `README.md` and captioned evidence in `screenshots/`. Categories are created as relevant cases are added, including phishing, network analysis, and identity investigations.

## Documentation standards

Reports include a summary, event details, evidence timeline where available, executed queries and results, analysis, disposition, response actions, and lessons learned. In-progress cases explicitly identify outstanding evidence. Prepared queries are labeled separately from executed searches.

All cases represent simulated activity. Screenshots are reviewed for personal information, credentials, tokens, and unrelated material before publication. Domain indicators in narrative text are defanged.

## Future updates

See [repository instructions](AGENTS.md) for the standing workflow for simulations and screenshots shared by the repository owner.
