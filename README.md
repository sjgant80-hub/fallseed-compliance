# FallSeed · Compliance

> **The level-1 seed.** A sovereign single-HTML PWA for managing multi-framework compliance posture. ISO/IEC 27001:2022 + Cyber Essentials + SOC 2 ship with full control catalogues; PCI-DSS / NIS2 / DORA ship as stubs the build engine can flesh out.

**Live:** https://sjgant80-hub.github.io/fallseed-compliance/

## What this is

`fallseed-compliance` is one HTML file. Save it, install it as a PWA, or fork it for a single framework or a single client. Inside:

- **Frameworks switcher** — toggle any combination of the six pre-loaded frameworks; cross-mapping shows you which controls overlap
- **Controls register** — 93 ISO 27001:2022 Annex A controls + 29 Cyber Essentials questions + 50 SOC 2 criteria, filterable by framework / theme / status / owner
- **Evidence library** — text and file capture, SHA-256 hashed and chained for non-repudiation
- **Scope wizard** — assets, processes, data flows, sub-processors, in-scope systems
- **Policy templates** — 10 cross-framework templates (ISP, AUP, ACC, IRP, BCP, CMP, VEN, CRY, CLD, PRV)
- **Audit cycle** — internal / external / management review planner
- **Gap analysis** — % complete per framework + list of remaining controls
- **Build engine** — cascade across 8 providers (WebLLM → ollama → Groq → OpenRouter → Google → Cerebras → Anthropic) to extend with new controls, policies, runbooks
- **Fork Seed packager** — serialise a mutated SEED into a new self-contained HTML file

## Why this is a "level-1" seed (and not a vertical)

Level-0 seeds (fallseed-ifa, fallseed-law, fallseed-clinic, etc.) package **one industry's tools**. Level-1 seeds package **a class of verticals** — every business with compliance obligations, regardless of industry. The fork mechanic and invariants (IDB, mesh, audit chain, cascade) are identical; the substrate that gets forked is a tier higher.

## Frameworks shipped

| Framework | Authority | Status | Controls |
|---|---|---|---|
| ISO/IEC 27001:2022 | ISO/IEC | full catalogue | 93 (A.5-A.8) |
| Cyber Essentials | NCSC / IASME | full catalogue | 29 (5 themes) |
| SOC 2 (Type II) | AICPA | full catalogue | 50 (CC1-CC9 + A/C/PI/P) |
| PCI-DSS v4.0 | PCI SSC | stub (12 themes) | generate via build |
| NIS2 (EU 2022/2555) | EU Commission | stub (10 measures) | generate via build |
| DORA (EU 2022/2554) | EU Commission · ESAs | stub (5 pillars) | generate via build |

## Architecture invariants

- **One HTML file** — no build step, no server, no install
- **IDB primary** — every record on your device (`fallseed-compliance-v1` IDB)
- **BroadcastChannel mesh** — `fall-compliance` for cross-tool sync, `fall-signal` for global hello
- **P3 audit chain** — `prevHash` + SHA-256 on every mutation across 5 stores
- **8-provider LLM cascade** — WebLLM (T1) → ollama / LM Studio (T2) → Groq / OpenRouter free / Google / Cerebras (T3-free) → Anthropic (T3-paid)
- **Streaming** — SSE token-by-token output
- **Fork Seed packager** — serialises a mutated SEED into a new HTML file

## Cosmology

Prime **1193**, spine-clean mod 127 = 50 = 2·5². Seed level **1** (first level above vertical seeds). Mesh channel `fall-compliance`. Bundle roles framework-switcher / controls-register / evidence-library / audit-cycle. Seal **◊·κ=1**.

Part of the FallSeed family — see [www.ai-nativesolutions.com](https://www.ai-nativesolutions.com).

## Disclaimer

This is **operational scaffolding, not certification**. Certification against ISO 27001, SOC 2, CE+, PCI-DSS or any other framework requires an accredited audit. This tool helps you organise the posture; the audit body decides.

## Licence

MIT © Simon Gant.
