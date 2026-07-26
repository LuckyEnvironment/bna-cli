# Security Policy

BNA builds verification and governance infrastructure. A missing or performative security policy would be a visible contradiction, so this one is meant to be used.

## Reporting a vulnerability

**Email:** security@bna.dev
**PGP:** published at https://bna.dev/.well-known/security.txt

Please do **not** open a public GitHub issue for a security vulnerability.

Include what you have: affected component and version, reproduction steps, impact as you see it, and whether it is already public. A rough report sent early is more useful than a polished one sent late.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 2 business days |
| Initial assessment and severity | 5 business days |
| Status update cadence while open | Every 7 days |
| Fix or documented mitigation — critical | 14 days |
| Fix or documented mitigation — high | 30 days |
| Fix or documented mitigation — medium/low | 90 days |

If we miss one of these, tell us. We would rather be held to it.

## Disclosure

We work to coordinated disclosure. Default embargo is 90 days from acknowledgement, or until a fix ships, whichever comes first. If you want to publish sooner, tell us and we will work to your timeline rather than argue about ours.

We will credit you by name in the advisory unless you ask us not to.

## Safe harbour

We will not pursue legal action against good-faith security research that:

- Does not access, modify, or exfiltrate data belonging to anyone other than yourself
- Does not degrade service for other users
- Does not use social engineering, physical intrusion, or attacks against our staff
- Gives us reasonable time to respond before public disclosure

If you are unsure whether something is in scope, ask first at security@bna.dev.

## Scope

**In scope**

- `@bna/cli` and `bna-validator-core`
- The hosted validator and public trust registry
- The sandbox API
- bna.dev and its subdomains
- The probe infrastructure

**Out of scope**

- Third-party agents and MCP servers we probe — report those to their operators. We are happy to help with contact if the operator is unresponsive.
- Findings from automated scanners without a demonstrated impact
- Missing security headers with no exploitable consequence
- Social engineering of BNA staff or customers

## Reporting a problem with a trust score

Not a vulnerability, but it belongs in the same place. If BNA has published a score or observation about your service that you believe is wrong, the appeals process is in [TRUST-METHODOLOGY.md](./TRUST-METHODOLOGY.md), section 6.

Short version: you can request the full underlying observation set for your entry at any time, free and without an account, and you can request removal from public scoring at any time without giving a reason. Removal is honoured within two business days.

## Our probes

If BNA's probe traffic is causing you a problem, email security@bna.dev and we will reduce frequency or stop entirely within two business days.

Our probes are read-only, never invoke tools with side effects, respect `Retry-After`, back off on 429, and identify themselves in the `User-Agent` with a link to the methodology. If you see traffic claiming to be a BNA probe that does not behave this way, please tell us — that is a report we want.
