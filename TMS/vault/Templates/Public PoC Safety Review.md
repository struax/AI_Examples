---
title: "Public PoC Safety Review"
type: "template"
status: "active"
---

# Public PoC Safety Review

## Source

- PoC URL or reference:
- CVE/advisory:
- Reviewer: Animal
- Engagement:
- Target under consideration:
- Review date:

## Scope Check

- Explicitly in-scope host:
- Environment:
- Authorization source:
- Live execution requested: no

## Relevance

- Claimed affected product/version:
- Observed product/version evidence:
- Required configuration:
- Authentication or role prerequisite:
- Confidence: low / medium / high

## Safety Review

- Destructive behavior:
- Persistence:
- Credential, token, or customer-data access:
- Data modification:
- External callback or exfiltration:
- Request volume or DoS risk:
- Risky dependencies or install steps:
- Other red flags:

## Benign Alternative

Describe a safer observation, local mock, or non-destructive check that could support or reject the hypothesis.

## Recommendation

Choose one: `reject`, `research_only`, `local_mock_only`, `candidate_for_separate_approval`.

Rationale:

## Approval Needed Before Live Validation

Live validation requires a separate explicit approval note with exact host, hypothesis, benign method, maximum request count, rate limit, stop conditions, and cleanup plan.
