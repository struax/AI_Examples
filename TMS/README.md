# TMS — The Muppet Show

TMS is a local-first, Markdown-first assistant workspace for authorised pentest coordination and work planning.

## Guardrails

- The dashboard binds to `127.0.0.1` only.
- Jira is import-only and read-only. TMS contains no Jira write operation.
- Tool exports are stored as notes; TMS does not execute imported commands.
- The Codex request box stores dashboard requests as local work-queue notes; it does not execute operating system commands.
- Animal may research exploitability and draft benign PoC plans, but live PoC validation requires a separate explicit approval note.
- A human approval note is required before a finding is marked ready for delivery.
- Report drafts must go through the Document Reviewer GPT for grammar, spelling, and consistency review before final human approval.
- Web pentest coverage is mapped to OWASP WSTG v4.2, but WSTG mapping does not authorize testing.

## Quick start

```bash
docker compose up --build
```

Open <http://127.0.0.1:8787>.

For a no-Docker Kali/Linux run:

```bash
python app/server.py
```

Run the test suite with:

```bash
python -m unittest discover -s tests
```

TMS uses only the Python standard library today. Python 3.12+ is recommended.

For a clean rebuild on another computer, see `docs/PORTABLE_REBUILD.md`.

## Storage

TMS stores operational records in a local SQLite database and writes companion Markdown notes for review.

- Default database: `vault/tms.sqlite3`
- Override path: `TMS_DB=/path/to/tms.sqlite3`
- Runtime database files are ignored by git because they may contain engagement metadata.

## Agent connections

Kermit has local connection profiles for Asana, Jira, and Obsidian. Kermit coordinates the connections; Beaker is the default author for technical Obsidian notes.

- Asana: read/import task snapshots.
- Jira: read/import issue snapshots.
- Obsidian: create Markdown notes in a configured local vault, usually authored by Beaker.

List profiles:

```bash
curl http://127.0.0.1:8787/api/connections
```

Configure Obsidian with a local vault path:

```bash
curl -X POST http://127.0.0.1:8787/api/connections \
  -H 'Content-Type: application/json' \
  -d '{"service":"obsidian","status":"connected","config":{"vault_path":"/home/kali/Obsidian","default_folder":"TMS"}}'
```

Create an Obsidian technical note through Beaker:

```bash
curl -X POST http://127.0.0.1:8787/api/beaker/obsidian-note \
  -H 'Content-Type: application/json' \
  -d '{"title":"Daily pentest notes","folder":"TMS/Daily","body":"Notes from today."}'
```

Do not put tokens or passwords in connection config. Use environment variables such as `ASANA_ACCESS_TOKEN`, `JIRA_API_TOKEN`, and `TMS_OBSIDIAN_VAULT`.

Import a read-only Asana task snapshot:

```bash
curl -X POST http://127.0.0.1:8787/api/imports/asana \
  -H 'Content-Type: application/json' \
  -d '{"gid":"1200123456789","name":"Review WSTG coverage","engagement":"TMS-LOCAL"}'
```

## Security authorization

Before using TMS for engagement work, fill out `SECURITY_AUTHORIZATION.md`. The health endpoint reports whether the file is present and whether obvious placeholders remain:

```bash
curl http://127.0.0.1:8787/api/health
```

## Markdown vault

All operational content lives in `vault/` as Markdown. Reports are an explicit exception: approved deliverables may be placed in `vault/Reports/Delivered/` as `.docx` and `.pdf`.

## Initial workflows

1. Copy a Jira issue's approved fields into `POST /api/imports/jira`, or use the dashboard form when configured.
2. Add safe, saved Burp or ProjectDiscovery exports through their import endpoints.
3. Let Kermit create a work-queue note and route it to a specialist.
4. Record human decisions in `vault/Approvals/`; only then mark deliverables ready.

## Project layout

- `app/` contains the local dashboard and API.
- `tests/` contains stdlib unit tests.
- `vault/tms.sqlite3` is the default local database path at runtime.
- `vault/Agents/` contains local role definitions.
- `vault/References/` contains local framework references such as OWASP WSTG v4.2.
- `vault/Templates/` contains Markdown schemas for daily work.
- `vault/Reports/Delivered/` is reserved for approved `.docx` and `.pdf` deliverables.

See [[Templates/Agent Definition]] and [[Agents/Kermit]].
