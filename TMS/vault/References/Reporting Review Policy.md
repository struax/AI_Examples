---
title: "Reporting Review Policy"
created: "2026-09-25T17:47:02Z"
type: "reference"
status: "active"
review_gpt: "Document Reviewer"
review_gpt_url: "<document-reviewer-gpt-url>"
---

# Reporting Review Policy

All TMS report drafts, finding writeups, report source notes, and final deliverable candidates must be reviewed with the Document Reviewer GPT before final human approval.

Reviewer GPT:

```text
<document-reviewer-gpt-url>
```

## Required Checks

- Grammar and spelling.
- Internal inconsistencies.
- Target and scope naming consistency.
- Severity wording consistency.
- Evidence reference consistency.
- Remediation clarity.
- Tone appropriate for client reporting.

## Recording Requirement

Record the reviewer GPT outcome in the report source note, finding note, or approval note. The note should state whether changes were made, whether issues remain, and where the reviewed draft is stored.

## Automation Boundary

TMS records and enforces the workflow requirement locally. Access to the GPT itself depends on ChatGPT workspace sharing and permissions.
