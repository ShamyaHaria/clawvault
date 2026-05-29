# ClawVault

**The Trusted Skill Registry for OpenClaw.**

ClawVault is a security verification platform for the OpenClaw ecosystem. Every skill submitted is audited through a 7-layer static analysis pipeline before a public trust verdict is issued. Users know exactly what a skill does, what permissions it requests and whether it is safe to install.

---

## The Problem

In early 2026 a coordinated attack called **ClawHavoc** planted hundreds of malicious skills on ClawHub using typosquatted names — stealing SSH keys, API tokens and browser session data from real users. A Snyk audit found 13.4% of ClawHub skills had critical vulnerabilities.

Every serious OpenClaw user is one bad install away from a compromised machine. ClawHub has no real security layer. Nobody credible has stepped in to fix it.

Until now.

---

## What ClawVault Does

Submitted skills are run through seven independent audit layers before a verdict is issued. Each layer targets a different class of threat — from credentials left exposed in source code to behavioral patterns that only become suspicious when viewed in sequence. No single layer sees the full picture. Together they do.

The pipeline runs in parallel. Results converge into a single structured report with a risk score weighted across four severity tiers. Every finding is traced back to an exact file and line number so there is no ambiguity about what was flagged or why.

ClawVault is intentionally strict. The pipeline surfaces anything suspicious and routes it for human review. A high score does not mean a skill is malicious — it means it warrants a closer look. The final verdict is always a human decision.

---

## What Gets Published

Every audited skill gets a public transparency report. It shows the verdict, the full findings breakdown and the declared repository so users can verify the source themselves. A ClawVault Verified badge means the skill cleared every layer and a human signed off on it.

Skills that fail are either rejected outright or flagged for review depending on severity. Rejected skills are disclosed publicly.

---

## How Scoring Works

Findings are weighted by severity and aggregated into a single risk score per submission. A score of zero means nothing was found. Anything above that enters a tiered risk classification from low through critical. The score is a signal not a verdict — context and human judgment determine the outcome.

---

## Repository Links

Every submission declares a source repository. It is displayed on the public audit report so anyone can trace the skill back to its origin. Future versions will cross-reference submitted code against the declared repository and trigger re-audits automatically on new commits.

---

## License

[Apache 2.0](./LICENSE)