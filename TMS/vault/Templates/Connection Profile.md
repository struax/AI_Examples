---
title: "Connection Profile"
type: "template"
---

# {{service}} Connection

```yaml
type: connection_profile
service:
status: not_configured
mode:
secret_ref:
allowed_actions: []
```

## Purpose

Describe how Kermit and specialist agents may use this service.

## Safe Defaults

- Store tokens and passwords only in environment variables.
- Keep Asana and Jira import/read-only unless separately approved.
- Use Obsidian for Markdown note creation, not for secrets.
- Prefer Beaker for technical pentest notes.

## Configuration

```json
{}
```
