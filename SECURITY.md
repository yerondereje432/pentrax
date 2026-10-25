# Security Policy

## Supported versions

PENTRAX is developed on a single rolling codebase. Security fixes are
applied to the latest commit on the `main` branch only — older commits
and forks do not receive backports. Always update to the newest `main`
before reporting an issue, in case it is already fixed.

| Version | Supported |
| :--- | :---: |
| Latest `main` | ✅ |
| Any older commit / release | ❌ |

## Reporting a vulnerability

**Please do not open a public GitHub issue, pull request, or discussion
for a security vulnerability in PENTRAX itself.** Public disclosure
before a fix exists puts every deployment at risk.

Instead, report it privately:

1. Go to the repository's **Security** tab on GitHub and choose
   **"Report a vulnerability"** (GitHub Private Vulnerability
   Reporting), **or**
2. If that option is unavailable, contact the repository owner
   (`@yerondereje432`) privately through GitHub and ask for a secure
   channel — do not include exploit details in a public post.

Please include, as far as you can:

- the commit hash or version you tested,
- a clear description of the vulnerability and its impact,
- step-by-step reproduction instructions or a proof of concept,
- any logs, screenshots, or suggested remediation.

### What to expect

- We aim to **acknowledge** your report within **3 business days**.
- We will confirm whether the issue is accepted, ask for any missing
  details, and keep you updated while a fix is developed.
- Once a fix is merged to `main`, we will agree on a public disclosure
  date with you (coordinated disclosure, normally within **90 days** of
  the report) and credit you in the release notes unless you prefer to
  remain anonymous.

Please give us a reasonable opportunity to fix the issue before
disclosing it publicly.

## Scope

**In scope** — vulnerabilities in this repository's own code, for
example:

- authentication, session, or role-based-access-control bypasses in the
  web console (`web/`),
- SQL injection, XSS, or other injection flaws in the web app or API,
- server-side request forgery (SSRF) weaknesses in the scanner's own
  protections (e.g. the cloud-metadata filter),
- unsafe handling of scan targets, templates, or uploaded data that
  leads to code execution on the host running PENTRAX.

**Out of scope:**

- findings that PENTRAX *reports about a scanned target* — those belong
  to the target's owner, not to this project,
- vulnerabilities in third-party dependencies that are already publicly
  disclosed (please still tell us if PENTRAX is affected),
- denial-of-service against a target caused by running aggressive scan
  settings the operator explicitly chose,
- issues that require already having local shell/admin access to the
  machine running PENTRAX.

## Safe harbour & authorized use

We support good-faith security research. If you make a genuine effort
to follow this policy — test only against your own PENTRAX instance,
avoid privacy violations and service disruption, and report privately —
we will treat your research as authorized and will not pursue legal
action over it.

PENTRAX itself must only be run against systems you own or have
explicit written authorization to test. Scanning third-party systems
without permission may be illegal in your jurisdiction and is never
endorsed by this project. See the "Ethical Rules of Engagement"
section of the [README](README.md#-ethical-rules-of-engagement--legal-disclaimer).
