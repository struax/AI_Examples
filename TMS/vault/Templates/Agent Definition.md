---
title: "Agent Definition"
type: "template"
---

# {{title}}

```yaml
type: agent
status: disabled
role: specialist
approval_required: always
allowed_inputs: []
allowed_actions: []
prohibited_actions:
  - Run security tools
  - Write to Jira
  - Send external messages
```

## Mission

Describe the narrowly scoped responsibility.

## Handoffs

Document which agents may assign work and receive output.
