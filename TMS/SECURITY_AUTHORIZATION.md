# Security Authorization Template

Complete this file before using TMS for engagement work. Do not infer scope from related brands, domains, subsidiaries, vendors, redirects, DNS records, IP ownership, or search results.

## Engagement

- Operator: `<operator name>`
- Organization: `<organization name>`
- Engagement ID: `<ticket or contract identifier>`
- Authorization period: `<start UTC>` through `<end UTC>`
- Authorizing party: `<name, role, corporate contact>`
- Evidence of authorization: `<ticket, signed letter, or approved repository path>`

## Scope

| Target | Environment | Allowed Techniques | Notes |
| --- | --- | --- | --- |
| `<exact hostname or URL>` | `<prod/stage/test>` | `<passive recon, crawling, authenticated checks, etc.>` | `<constraints>` |

## Stop Conditions

- Stop immediately if a system owner, monitoring team, or authorizing party requests a stop.
- Stop if testing causes instability, material performance degradation, customer impact, or data exposure.
- Stop if a target, technique, date, or environment is absent or ambiguous.

## Data Handling

- Do not expose credentials, tokens, regulated data, customer data, or sensitive vulnerability evidence in unnecessary output.
- Store evidence only in the approved vault paths for the engagement.
- Redact secrets before sharing artifacts outside the approved operator group.

## Operator Checklist

- [ ] Exact target is listed in scope.
- [ ] Current UTC date is inside the authorization period.
- [ ] Requested technique is listed as allowed.
- [ ] Environment is confirmed.
- [ ] Stop conditions are understood.
