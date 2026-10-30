---
title: "Kermit Connector Policy"
type: "reference"
status: "active"
---

# Kermit Connector Policy

Kermit can use connection profiles to coordinate everyday pentest work across task systems and notes.

## Services

| Service | Mode | Default status | Default permission |
| --- | --- | --- | --- |
| Asana | plugin or API import | pending_plugin | Read/import task snapshots |
| Jira | plugin or API import | pending_plugin | Read/import issue snapshots |
| Obsidian | local vault | not_configured | Beaker creates technical Markdown notes |

## Rules

- Do not store service tokens, passwords, cookies, or API secrets in TMS notes or SQLite.
- Store only environment variable names such as `ASANA_ACCESS_TOKEN`, `JIRA_API_TOKEN`, or `TMS_OBSIDIAN_VAULT`.
- Keep Asana and Jira read-only until a separate written approval allows mutation.
- Obsidian writes are local Markdown note creation only.
- Kermit coordinates Obsidian usage; Beaker is the default author for technical notes.
- Every connector action should be recorded in `connection_events` and the audit log when it changes local notes.

## API Routes

| Route | Purpose |
| --- | --- |
| `GET /api/connections` | List connection profiles |
| `POST /api/connections` | Configure a profile without storing secrets |
| `POST /api/imports/asana` | Import a read-only Asana task snapshot |
| `POST /api/imports/jira` | Import a read-only Jira issue snapshot |
| `POST /api/beaker/obsidian-note` | Ask Beaker to create a technical Obsidian Markdown note |
| `POST /api/kermit/obsidian-note` | Backward-compatible route for Kermit-authored coordination notes |
| `POST /api/agents/obsidian-note` | Generic route; defaults to Beaker unless `agent` is supplied |
