---
title: "OWASP WSTG v4.2"
type: "reference"
status: "active"
---

# OWASP WSTG v4.2

Use the OWASP Web Security Testing Guide as the primary reference framework for web application pentest planning, evidence mapping, and reporting.

## Version Pin

- Stable reference: WSTG v4.2
- Versioned scenario ID style: `WSTG-v42-<CATEGORY>-<NUMBER>`
- Versioned documentation root: https://wstg.owasp.org/v4.2/
- Latest development docs: https://wstg.owasp.org/latest/

Versioned references are preferred for reports because WSTG identifiers and links can change between releases.

## TMS Rules

- WSTG mapping does not authorize testing.
- Confirm `SECURITY_AUTHORIZATION.md` before selecting checks for an engagement.
- Select only checks that match the approved target, environment, authentication level, and technique constraints.
- Mark blocked, not applicable, or out-of-scope checks explicitly.
- Link each completed check to local evidence and any finding note.
- Do not run tools from a WSTG checklist without a separate scope and technique gate.

## Coverage Status Values

- `planned`
- `done`
- `not_applicable`
- `blocked`
- `out_of_scope`

## Web Application Testing Categories

| Category | WSTG Prefix | Use in TMS |
| --- | --- | --- |
| Information Gathering | `WSTG-v42-INFO` | Discovery, mapping, fingerprinting, exposed content review |
| Configuration and Deployment Management | `WSTG-v42-CONF` | Headers, deployment posture, files, admin interfaces |
| Identity Management | `WSTG-v42-IDNT` | Account lifecycle, registration, identity assumptions |
| Authentication | `WSTG-v42-ATHN` | Login, MFA, password reset, credential handling |
| Authorization | `WSTG-v42-ATHZ` | Access control, privilege boundaries, IDOR-style review |
| Session Management | `WSTG-v42-SESS` | Cookies, tokens, logout, fixation, CSRF-adjacent flows |
| Input Validation | `WSTG-v42-INPV` | Injection, upload, encoding, deserialization-style checks |
| Error Handling | `WSTG-v42-ERRH` | Error leakage and exception handling |
| Cryptography | `WSTG-v42-CRYP` | TLS usage, transport, weak crypto implementation review |
| Business Logic | `WSTG-v42-BUSL` | Workflow abuse, process bypass, misuse cases |
| Client-side | `WSTG-v42-CLNT` | DOM, JavaScript, CORS, clickjacking, client storage |
| API Testing | `WSTG-v42-APIT` | API discovery, auth, methods, mass assignment, GraphQL |

## Agent Mapping

| Agent | WSTG Responsibility |
| --- | --- |
| Kermit | Selects in-scope WSTG checks and routes tasks |
| Rowlf | Turns selected checks into a daily work queue |
| Gonzo | Maps authorized recon output to `INFO`, `CONF`, and `APIT` coverage |
| Animal | Researches exploitability and drafts separately approved benign validation plans |
| Beaker | Drafts technical notes for completed checks and evidence |
| Miss Piggy | Verifies scope, evidence, status, and skipped-check rationale |
| Statler and Waldorf | Challenge weak WSTG mapping or unsupported claims |
| Fozzie | References WSTG IDs in approved report source material |
