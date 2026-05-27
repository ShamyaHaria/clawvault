# ClawVault

**The trusted skill registry for OpenClaw.**

ClawVault is a security verification platform for the OpenClaw ecosystem. Every skill submitted is audited through a multi-layer static analysis pipeline before a public trust verdict is issued. Users know exactly what a skill does, what permissions it requests, and whether it is safe to install.

---

## The Problem

In early 2026, a coordinated attack called **ClawHavoc** planted hundreds of malicious skills on ClawHub using typosquatted names — stealing SSH keys, API tokens, and browser session data from real users. A Snyk audit found 13.4% of ClawHub skills had critical vulnerabilities.

Every serious OpenClaw user is one bad install away from a compromised machine.

---

## What ClawVault Does

Every skill submitted to ClawVault is audited across multiple layers before a verdict is published:

- **Credential scan** — detects hardcoded API keys, tokens, and private keys across 15+ credential types including AWS, GitHub, OpenAI, Anthropic, Stripe, and more
- **Obfuscation detection** — catches eval chains, base64 payloads, dynamic imports, builtins evasion, marshal execution, pickle deserialization, and 20+ evasion techniques
- **Permission audit** — verifies actual code behavior matches declared SKILL.md permissions across network, filesystem, subprocess, and environment access
- **Typosquat check** — flags names engineered to impersonate known skills using Levenshtein distance, homoglyph normalization, number substitution, and version suffix detection
- **Dependency scan** — audits requirements.txt, package.json, setup.py, pyproject.toml, Pipfile, and conda environments for known malicious packages, typosquatted dependencies, unpinned versions, and runtime install calls

Results are published publicly. Users see exactly what was found, where, and why.

---

## License
[Apache 2.0](./LICENSE)