---
title: "WSTG Coverage"
type: "template"
---

# WSTG Coverage - {{engagement}}

```yaml
type: wstg_coverage
framework: OWASP WSTG
version: v4.2
engagement:
target:
status: active
authorization_file: ../../SECURITY_AUTHORIZATION.md
```

## Scope Gate

- Exact target:
- Environment:
- Authentication level:
- Approved techniques:
- Exclusions:
- Stop conditions:

## Coverage

| WSTG ID | Title | Status | Evidence | Finding | Gating rationale |
| --- | --- | --- | --- | --- | --- |
| `WSTG-v42-INFO-01` | Conduct Search Engine Discovery Reconnaissance for Information Leakage | planned |  |  |  |
| `WSTG-v42-CONF-01` | Test Network Infrastructure Configuration | planned |  |  |  |
| `WSTG-v42-IDNT-01` | Test Role Definitions | planned |  |  |  |
| `WSTG-v42-ATHN-01` | Testing for Credentials Transported over an Encrypted Channel | planned |  |  |  |
| `WSTG-v42-ATHZ-01` | Testing Directory Traversal File Include | planned |  |  |  |
| `WSTG-v42-SESS-01` | Testing for Session Management Schema | planned |  |  |  |
| `WSTG-v42-INPV-01` | Testing for Reflected Cross Site Scripting | planned |  |  |  |
| `WSTG-v42-ERRH-01` | Testing for Improper Error Handling | planned |  |  |  |
| `WSTG-v42-CRYP-01` | Testing for Weak Transport Layer Security | planned |  |  |  |
| `WSTG-v42-BUSL-01` | Test Business Logic Data Validation | planned |  |  |  |
| `WSTG-v42-CLNT-01` | Testing for DOM-Based Cross Site Scripting | planned |  |  |  |
| `WSTG-v42-APIT-01` | Testing GraphQL | planned |  |  |  |

## Notes

Use `blocked`, `not_applicable`, or `out_of_scope` instead of forcing coverage where authorization or application behavior does not support a check.
