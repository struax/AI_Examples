"""Local-only TMS dashboard and Markdown vault API."""
from __future__ import annotations

import json
import os
import re
import sqlite3
import hashlib
import ipaddress
import socket
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(os.environ.get("TMS_VAULT", Path(__file__).parents[1] / "vault"))
PROJECT_ROOT = Path(__file__).parents[1]
AUTHORIZATION_FILE = PROJECT_ROOT / "SECURITY_AUTHORIZATION.md"
RECON_ROOT = Path(os.environ.get("TMS_RECON_ROOT", "/home/kali/Auto-PCI-Test/recon"))
MAX_JSON_PAYLOAD_BYTES = int(os.environ.get("TMS_MAX_JSON_PAYLOAD_BYTES", "25000000"))
SITE_CHECK_TIMEOUT_SECONDS = float(os.environ.get("TMS_SITE_CHECK_TIMEOUT_SECONDS", "6"))
SITE_CHECK_USER_AGENT = os.environ.get("TMS_SITE_CHECK_USER_AGENT", "TMS-Site-Monitor/1.0")
NOTE_FOLDERS = (
    "Agents",
    "Jira",
    "Work Queue",
    "Approvals",
    "Evidence",
    "Audit Log",
    "Engagements",
    "Findings",
    "Tasks",
    "References",
)
APPROVED_DECISIONS = {"approved", "approve", "accepted", "ready"}
AUTHORIZATION_PLACEHOLDERS = (
    "<ticket/contract identifier>",
    "<start UTC>",
    "<end UTC>",
    "<name, role, corporate contact>",
    "<internal ticket or signed-letter location>",
)
CONNECTION_STATUSES = {"not_configured", "pending_plugin", "connected", "disabled"}
DEFAULT_CONNECTIONS = {
    "asana": {
        "display_name": "Asana",
        "kind": "project_management",
        "mode": "plugin_or_api_import",
        "status": "pending_plugin",
        "secret_ref": "ASANA_ACCESS_TOKEN",
        "allowed_actions": ["read_tasks", "import_task_snapshots"],
        "config": {"workspace_gid": "", "project_gid": ""},
    },
    "jira": {
        "display_name": "Jira",
        "kind": "issue_tracker",
        "mode": "plugin_or_api_import",
        "status": "pending_plugin",
        "secret_ref": "JIRA_API_TOKEN",
        "allowed_actions": ["read_issues", "import_issue_snapshots"],
        "config": {"site_url": "", "project_key": ""},
    },
    "obsidian": {
        "display_name": "Obsidian",
        "kind": "notes",
        "mode": "local_vault",
        "status": "not_configured",
        "secret_ref": "",
        "allowed_actions": ["create_markdown_note"],
        "config": {"vault_path": "", "default_folder": "TMS"},
    },
}
SECRET_CONFIG_KEYS = {
    "api_token",
    "access_token",
    "refresh_token",
    "client_secret",
    "password",
    "cookie",
    "authorization",
    "secret",
    "credentials",
}
ENV_VAR_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
RECON_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9.-]+$")
OBSIDIAN_NOTE_AGENTS = {
    "Animal",
    "Beaker",
    "Fozzie",
    "Gonzo",
    "Kermit",
    "Miss Piggy",
    "Rowlf",
    "Statler and Waldorf",
}
SCANNER_JSON_TOOLS = {
    "crowdstrike": "CrowdStrike",
    "tenable": "Tenable",
}


def database_path() -> Path:
    return Path(os.environ.get("TMS_DB", ROOT / "tms.sqlite3"))


def server_host() -> str:
    return os.environ.get("TMS_HOST", "127.0.0.1")


def server_port() -> int:
    return int(os.environ.get("TMS_PORT", "8787"))


@contextmanager
def open_db() -> Iterator[sqlite3.Connection]:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    with open_db() as database:
        database.executescript(
            """
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                folder TEXT NOT NULL,
                title TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE,
                type TEXT,
                status TEXT,
                engagement TEXT,
                fields_json TEXT NOT NULL,
                body TEXT NOT NULL,
                created TEXT NOT NULL,
                updated TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_notes_folder_created
                ON notes(folder, created DESC);

            CREATE TABLE IF NOT EXISTS approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT NOT NULL,
                approver TEXT NOT NULL,
                decision TEXT NOT NULL,
                engagement TEXT NOT NULL,
                rationale TEXT NOT NULL,
                note_path TEXT NOT NULL,
                created TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_approvals_subject_decision
                ON approvals(subject, decision);

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                detail TEXT NOT NULL,
                note_path TEXT,
                created TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_events_created
                ON audit_events(created DESC);

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                engagement TEXT NOT NULL,
                summary TEXT NOT NULL,
                approval_verified INTEGER NOT NULL DEFAULT 0,
                note_path TEXT NOT NULL,
                created TEXT NOT NULL,
                updated TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS wstg_coverage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement TEXT NOT NULL,
                wstg_id TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'planned',
                evidence_path TEXT,
                finding_id TEXT,
                gating_rationale TEXT,
                created TEXT NOT NULL,
                updated TEXT NOT NULL,
                UNIQUE(engagement, wstg_id)
            );

            CREATE INDEX IF NOT EXISTS idx_wstg_coverage_engagement_status
                ON wstg_coverage(engagement, status);

            CREATE TABLE IF NOT EXISTS connections (
                service TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                kind TEXT NOT NULL,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                config_json TEXT NOT NULL,
                secret_ref TEXT NOT NULL,
                allowed_actions_json TEXT NOT NULL,
                last_sync TEXT,
                created TEXT NOT NULL,
                updated TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS connection_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT NOT NULL,
                created TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_connection_events_service_created
                ON connection_events(service, created DESC);
            """
        )
        for service, profile in DEFAULT_CONNECTIONS.items():
            created = now()
            database.execute(
                """
                INSERT OR IGNORE INTO connections (
                    service,
                    display_name,
                    kind,
                    mode,
                    status,
                    config_json,
                    secret_ref,
                    allowed_actions_json,
                    created,
                    updated
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    service,
                    profile["display_name"],
                    profile["kind"],
                    profile["mode"],
                    profile["status"],
                    json.dumps(profile["config"], sort_keys=True),
                    profile["secret_ref"],
                    json.dumps(profile["allowed_actions"], sort_keys=True),
                    created,
                    created,
                ),
            )


def now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._ -]", "-", value).strip(" .-")
    return cleaned[:100] or "untitled"


def yaml_value(value: object) -> str:
    return json.dumps(str(value))


def read_frontmatter(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        return {}
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if line == "---":
            break
        if ": " not in line:
            continue
        key, raw_value = line.split(": ", 1)
        try:
            value = json.loads(raw_value)
        except json.JSONDecodeError:
            value = raw_value.strip('"')
        fields[key] = str(value)
    return fields


def authorization_status() -> dict[str, object]:
    if not AUTHORIZATION_FILE.exists():
        return {"present": False, "complete": False, "path": str(AUTHORIZATION_FILE)}
    text = AUTHORIZATION_FILE.read_text(encoding="utf-8")
    has_placeholders = any(placeholder in text for placeholder in AUTHORIZATION_PLACEHOLDERS)
    return {
        "present": True,
        "complete": not has_placeholders,
        "path": str(AUTHORIZATION_FILE),
    }


def connection_event(service: str, action: str, status: str, detail: str) -> None:
    init_db()
    with open_db() as database:
        database.execute(
            """
            INSERT INTO connection_events (service, action, status, detail, created)
            VALUES (?, ?, ?, ?, ?)
            """,
            (service, action, status, detail, now()),
        )


def parse_json_field(value: str, fallback: object) -> object:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def list_connections() -> list[dict[str, object]]:
    init_db()
    with open_db() as database:
        rows = database.execute(
            """
            SELECT
                service,
                display_name,
                kind,
                mode,
                status,
                config_json,
                secret_ref,
                allowed_actions_json,
                last_sync,
                updated
            FROM connections
            ORDER BY service
            """
        ).fetchall()

    return [
        {
            "service": row["service"],
            "display_name": row["display_name"],
            "kind": row["kind"],
            "mode": row["mode"],
            "status": row["status"],
            "config": parse_json_field(row["config_json"], {}),
            "secret_ref": row["secret_ref"],
            "allowed_actions": parse_json_field(row["allowed_actions_json"], []),
            "last_sync": row["last_sync"],
            "updated": row["updated"],
        }
        for row in rows
    ]


def get_connection(service: str) -> dict[str, object]:
    service_key = service.strip().lower()
    for profile in list_connections():
        if profile["service"] == service_key:
            return profile
    raise ValueError("Unsupported connection service")


def sanitized_config(config: object) -> dict[str, str]:
    if config is None:
        return {}
    if not isinstance(config, dict):
        raise ValueError("Connection config must be a JSON object")
    clean: dict[str, str] = {}
    for key, value in config.items():
        key_text = str(key).strip()
        if not key_text:
            raise ValueError("Connection config keys cannot be blank")
        if key_text.lower() in SECRET_CONFIG_KEYS:
            raise ValueError("Store secrets in environment variables and reference them with secret_ref")
        clean[key_text] = str(value)
    return clean


def configure_connection(data: dict[str, object]) -> dict[str, object]:
    service = str(data.get("service", "")).strip().lower()
    if service not in DEFAULT_CONNECTIONS:
        raise ValueError("Unsupported connection service")
    current = get_connection(service)
    status = str(data.get("status", current["status"])).strip().lower()
    if status not in CONNECTION_STATUSES:
        raise ValueError("Unsupported connection status")

    config = current["config"]
    if data.get("config") is not None:
        if not isinstance(config, dict):
            config = {}
        config = {**config, **sanitized_config(data.get("config"))}

    secret_ref = str(data.get("secret_ref", current["secret_ref"])).strip()
    if secret_ref and not ENV_VAR_PATTERN.fullmatch(secret_ref):
        raise ValueError("secret_ref must be an environment variable name")

    allowed_actions = current["allowed_actions"]
    if data.get("allowed_actions") is not None:
        raw_actions = data["allowed_actions"]
        if not isinstance(raw_actions, list):
            raise ValueError("allowed_actions must be a list")
        allowed_actions = [str(action) for action in raw_actions]

    with open_db() as database:
        database.execute(
            """
            UPDATE connections
            SET status = ?,
                config_json = ?,
                secret_ref = ?,
                allowed_actions_json = ?,
                updated = ?
            WHERE service = ?
            """,
            (
                status,
                json.dumps(config, sort_keys=True),
                secret_ref,
                json.dumps(allowed_actions, sort_keys=True),
                now(),
                service,
            ),
        )
    connection_event(service, "configure", "ok", f"Configured {service} connection profile.")
    return get_connection(service)


def has_approved_human_decision(subject: str) -> bool:
    init_db()
    with open_db() as database:
        row = database.execute(
            """
            SELECT 1 FROM approvals
            WHERE subject = ?
              AND lower(decision) IN ('approved', 'approve', 'accepted', 'ready')
            LIMIT 1
            """,
            (subject,),
        ).fetchone()
    if row:
        return True

    directory = ROOT / "Approvals"
    if not directory.exists():
        return False
    for path in directory.glob("*.md"):
        fields = read_frontmatter(path)
        decision = fields.get("decision", "").strip().lower()
        if fields.get("title") == subject and decision in APPROVED_DECISIONS:
            return True
    return False


def relative_note_path(path: Path) -> str:
    return str(path.relative_to(ROOT)).replace("\\", "/")


def store_note_record(path: Path, folder: str, title: str, fields: dict[str, object], body: str, created: str) -> None:
    init_db()
    frontmatter = {"title": title, "created": created, **fields}
    note_path = relative_note_path(path)
    with open_db() as database:
        database.execute(
            """
            INSERT INTO notes (
                folder, title, path, type, status, engagement, fields_json, body, created, updated
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                folder = excluded.folder,
                title = excluded.title,
                type = excluded.type,
                status = excluded.status,
                engagement = excluded.engagement,
                fields_json = excluded.fields_json,
                body = excluded.body,
                updated = excluded.updated
            """,
            (
                folder,
                title,
                note_path,
                str(fields.get("type", "")),
                str(fields.get("status", "")),
                str(fields.get("engagement", "")),
                json.dumps(frontmatter, sort_keys=True),
                body,
                created,
                now(),
            ),
        )


def store_approval_record(
    subject: str,
    approver: str,
    decision: str,
    engagement: str,
    rationale: str,
    path: Path,
) -> None:
    init_db()
    created = read_frontmatter(path).get("created", now())
    with open_db() as database:
        database.execute(
            """
            INSERT INTO approvals (subject, approver, decision, engagement, rationale, note_path, created)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (subject, approver, decision, engagement, rationale, relative_note_path(path), created),
        )


def store_audit_event(action: str, detail: str, path: Path) -> None:
    init_db()
    created = read_frontmatter(path).get("created", now())
    with open_db() as database:
        database.execute(
            """
            INSERT INTO audit_events (action, detail, note_path, created)
            VALUES (?, ?, ?, ?)
            """,
            (action, detail, relative_note_path(path), created),
        )


def store_finding_ready_record(subject: str, engagement: str, summary: str, path: Path) -> None:
    init_db()
    created = read_frontmatter(path).get("created", now())
    with open_db() as database:
        database.execute(
            """
            INSERT INTO findings (
                subject, status, engagement, summary, approval_verified, note_path, created, updated
            )
            VALUES (?, ?, ?, ?, 1, ?, ?, ?)
            ON CONFLICT(subject) DO UPDATE SET
                status = excluded.status,
                engagement = excluded.engagement,
                summary = excluded.summary,
                approval_verified = excluded.approval_verified,
                note_path = excluded.note_path,
                updated = excluded.updated
            """,
            (
                subject,
                "ready_for_delivery",
                engagement,
                summary,
                relative_note_path(path),
                created,
                now(),
            ),
        )


def safe_folder(value: object) -> Path:
    parts = [safe_name(part) for part in str(value or "TMS").replace("\\", "/").split("/")]
    clean_parts = [part for part in parts if part and part != "."]
    return Path(*clean_parts) if clean_parts else Path("TMS")


def note(folder: str, title: str, fields: dict[str, object], body: str) -> Path:
    if folder not in NOTE_FOLDERS:
        raise ValueError("Unsupported note folder")
    directory = ROOT / folder
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{safe_name(title)}.md"
    created = now()
    frontmatter = {"title": title, "created": created, **fields}
    note_body = body.strip()
    lines = [
        "---",
        *(f"{key}: {yaml_value(value)}" for key, value in frontmatter.items()),
        "---",
        "",
        f"# {title}",
        "",
        note_body,
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    store_note_record(path, folder, title, fields, note_body, created)
    return path


def audit(action: str, detail: str) -> None:
    path = note("Audit Log", f"{now().replace(':', '-') } {action}", {"type": "audit", "action": action}, detail)
    store_audit_event(action, detail, path)


def record_approval(data: dict[str, object]) -> Path:
    subject = str(data.get("subject", ""))
    approver = str(data.get("approver", ""))
    decision = str(data.get("decision", ""))
    if not all((subject, approver, decision)):
        raise ValueError("Subject, approver, and decision are required")
    engagement = str(data.get("engagement", "unassigned"))
    rationale = str(data.get("rationale", "No rationale recorded."))
    path = note(
        "Approvals",
        subject,
        {
            "type": "approval",
            "approver": approver,
            "decision": decision,
            "engagement": engagement,
        },
        rationale,
    )
    store_approval_record(subject, approver, decision, engagement, rationale, path)
    audit("approval-recorded", f"{approver} recorded {decision} for [[Approvals/{path.stem}]].")
    return path


def import_asana_task_snapshot(data: dict[str, object]) -> Path:
    task_id = str(data.get("gid") or data.get("id") or data.get("task_gid") or "").strip()
    name = str(data.get("name") or data.get("summary") or "").strip()
    if not task_id or not name:
        raise ValueError("Asana task id and name are required")

    body = (
        f"## Task\n\n{name}\n\n## Imported fields\n\n```json\n"
        f"{json.dumps(data, indent=2)}\n```\n\n> [!info] Read-only import\n"
        "> This snapshot was imported into TMS. TMS does not mutate Asana tasks."
    )
    path = note(
        "Tasks",
        f"Asana {task_id} - {name}",
        {
            "type": "asana_task",
            "service": "asana",
            "asana_gid": task_id,
            "status": data.get("status", "unknown"),
            "source": "read_only_import",
            "engagement": data.get("engagement", "unassigned"),
        },
        body,
    )
    connection_event("asana", "import_task", "ok", f"Imported read-only Asana task snapshot {task_id}.")
    audit("asana-import", f"Imported read-only Asana task snapshot [[Tasks/{path.stem}]].")
    return path


def scanner_json_summary(payload: object) -> list[str]:
    lines: list[str] = []
    if isinstance(payload, dict):
        keys = sorted(str(key) for key in payload.keys())
        preview = ", ".join(keys[:20]) if keys else "none"
        suffix = " ..." if len(keys) > 20 else ""
        lines.append(f"- JSON root: object with {len(keys)} top-level keys")
        lines.append(f"- Top-level keys: {preview}{suffix}")
        for key in (
            "vulnerabilities",
            "findings",
            "assets",
            "hosts",
            "plugins",
            "detections",
            "incidents",
            "resources",
            "results",
            "data",
        ):
            value = payload.get(key)
            if isinstance(value, list):
                lines.append(f"- `{key}` items: {len(value)}")
            elif isinstance(value, dict):
                lines.append(f"- `{key}` keys: {len(value)}")
    elif isinstance(payload, list):
        lines.append(f"- JSON root: array with {len(payload)} items")
        first = payload[0] if payload else None
        if isinstance(first, dict):
            keys = sorted(str(key) for key in first.keys())
            preview = ", ".join(keys[:20]) if keys else "none"
            suffix = " ..." if len(keys) > 20 else ""
            lines.append(f"- First item keys: {preview}{suffix}")
    else:
        lines.append(f"- JSON root: {type(payload).__name__}")
    return lines


def import_scanner_json(data: dict[str, object]) -> Path:
    tool = str(data.get("tool", "")).strip().lower()
    if tool not in SCANNER_JSON_TOOLS:
        raise ValueError("Scanner tool must be tenable or crowdstrike")

    content = str(data.get("content", ""))
    if not content.strip():
        raise ValueError("Scanner JSON content is required")
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as error:
        raise ValueError(f"Uploaded file is not valid JSON: {error.msg}") from error

    filename = safe_name(str(data.get("filename", "") or f"{tool}-export.json"))
    if not filename.lower().endswith(".json"):
        raise ValueError("Scanner upload filename must end in .json")

    title = str(data.get("title", "")).strip() or f"{SCANNER_JSON_TOOLS[tool]} JSON {now()}"
    engagement = str(data.get("engagement", "unassigned")).strip() or "unassigned"
    operator_notes = str(data.get("notes", "")).strip() or "No operator notes provided."
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()

    upload_dir = ROOT / "Evidence" / "Uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    artifact_name = safe_name(f"{now().replace(':', '-')}-{filename}")
    artifact_path = upload_dir / artifact_name
    artifact_path.write_text(content, encoding="utf-8")
    artifact_relative = relative_note_path(artifact_path)

    summary = "\n".join(scanner_json_summary(payload))
    body = (
        "## Scanner JSON Intake\n\n"
        f"- Tool: {SCANNER_JSON_TOOLS[tool]}\n"
        f"- Uploaded file: `{filename}`\n"
        f"- Stored artifact: `{artifact_relative}`\n"
        f"- SHA-256: `{digest}`\n"
        f"- Size: {len(content.encode('utf-8'))} bytes\n"
        "- Assigned analyst: Beaker\n"
        "- Status: queued for analysis\n\n"
        "## Parsed JSON Shape\n\n"
        f"{summary}\n\n"
        "## Operator Notes\n\n"
        f"{operator_notes}\n\n"
        "## Beaker Analysis Request\n\n"
        "- Review the saved scanner JSON for credible vulnerabilities, detections, affected assets, severity, and remediation themes.\n"
        "- Deduplicate scanner rows into human-readable findings or follow-up questions.\n"
        "- Preserve scope boundaries and avoid copying secrets, tokens, customer data, or regulated data into findings.\n"
        "- Link conclusions back to the stored artifact path and only quote minimal evidence needed for review."
    )
    path = note(
        "Evidence",
        title,
        {
            "type": "scanner_json_analysis_request",
            "tool": tool,
            "assigned_agent": "Beaker",
            "status": "queued_for_analysis",
            "engagement": engagement,
            "artifact_path": artifact_relative,
            "sha256": digest,
            "sensitivity": "restricted",
            "execution": "not_run_by_tms",
        },
        body,
    )
    task_path = queue_scanner_json_analysis_task(path, title, tool, engagement, artifact_relative, digest)
    audit("scanner-json-import", f"Queued {SCANNER_JSON_TOOLS[tool]} JSON [[Evidence/{path.stem}]] for Beaker analysis.")
    audit("beaker-task", f"Routed scanner JSON analysis to [[Tasks/{task_path.stem}]].")
    return path


def queue_scanner_json_analysis_task(
    evidence_path: Path,
    title: str,
    tool: str,
    engagement: str,
    artifact_relative: str,
    digest: str,
) -> Path:
    task_title = f"Beaker {title} Analysis"
    body = (
        "## Scanner JSON Analysis Task\n\n"
        f"Source evidence: `Evidence/{evidence_path.stem}`\n\n"
        f"- Tool: {SCANNER_JSON_TOOLS[tool]}\n"
        f"- Stored artifact: `{artifact_relative}`\n"
        f"- SHA-256: `{digest}`\n"
        "- Assigned analyst: Beaker\n"
        "- Status: queued\n\n"
        "## Beaker Checklist\n\n"
        "- Parse the saved scanner JSON and summarize finding counts by severity/category.\n"
        "- Deduplicate scanner items into likely reportable issues and owner-review observations.\n"
        "- Map credible issues to affected target(s), evidence paths, and remediation themes.\n"
        "- Flag anything requiring scope confirmation, authenticated validation, or separate approval."
    )
    return note(
        "Tasks",
        task_title,
        {
            "type": "task",
            "status": "queued",
            "engagement": engagement,
            "assigned_agent": "Beaker",
            "source_note": f"Evidence/{evidence_path.stem}",
            "artifact_path": artifact_relative,
            "tool": tool,
            "sha256": digest,
            "approval_required": "before finding finalization or external delivery",
        },
        body,
    )


def create_codex_request(data: dict[str, object]) -> Path:
    command = str(data.get("command", "")).strip()
    if not command:
        raise ValueError("Codex request is required")
    title = str(data.get("title", "")).strip() or f"Codex Request {now()}"
    engagement = str(data.get("engagement", "unassigned")).strip() or "unassigned"
    priority = str(data.get("priority", "normal")).strip().lower() or "normal"
    context = str(data.get("context", "")).strip() or "No extra context provided."
    if priority not in {"low", "normal", "high"}:
        raise ValueError("Priority must be low, normal, or high")

    body = (
        "## Request\n\n"
        f"{command}\n\n"
        "## Context\n\n"
        f"{context}\n\n"
        "## Handling\n\n"
        "- This is a Codex work request queued from the local dashboard.\n"
        "- It does not execute an operating system command.\n"
        "- Codex should read this note, apply normal scope and authorization gates, then act through the usual chat/tool workflow."
    )
    path = note(
        "Work Queue",
        title,
        {
            "type": "codex_request",
            "status": "queued_for_codex",
            "assigned_agent": "Codex",
            "engagement": engagement,
            "priority": priority,
            "source": "dashboard",
        },
        body,
    )
    audit("codex-request", f"Queued dashboard Codex request [[Work Queue/{path.stem}]].")
    return path


def mark_finding_ready(data: dict[str, object]) -> Path:
    subject = str(data.get("subject", "")).strip()
    if not subject:
        raise ValueError("Finding subject is required")
    if not has_approved_human_decision(subject):
        raise PermissionError("Human approval note is required before marking a finding ready for delivery")
    body = str(data.get("summary", "Finding approved for delivery."))
    engagement = str(data.get("engagement", "unassigned"))
    path = note(
        "Findings",
        subject,
        {
            "type": "finding_status",
            "status": "ready_for_delivery",
            "approval": "verified",
            "engagement": engagement,
        },
        body,
    )
    store_finding_ready_record(subject, engagement, body, path)
    audit("finding-ready", f"Marked [[Findings/{path.stem}]] ready after matching human approval.")
    return path


def write_obsidian_note(data: dict[str, object], default_agent: str = "Beaker") -> Path:
    connection = get_connection("obsidian")
    if connection["status"] != "connected":
        raise PermissionError("Obsidian connection must be configured and connected before writing notes")

    config = connection["config"] if isinstance(connection["config"], dict) else {}
    vault_path = str(os.environ.get("TMS_OBSIDIAN_VAULT") or config.get("vault_path") or "").strip()
    if not vault_path:
        raise ValueError("Obsidian vault path is required")

    title = str(data.get("title", "")).strip()
    if not title:
        raise ValueError("Obsidian note title is required")

    agent = str(data.get("agent", default_agent)).strip() or default_agent
    if agent not in OBSIDIAN_NOTE_AGENTS:
        raise ValueError("Unsupported Obsidian note agent")

    folder = data.get("folder") or config.get("default_folder") or "TMS"
    body = str(data.get("body", "")).strip()
    note_type = str(data.get("type", "technical_note" if agent == "Beaker" else "agent_note"))
    fields = {
        "source": "tms",
        "agent": agent,
        "created": now(),
        "type": note_type,
    }

    target_directory = Path(vault_path).expanduser() / safe_folder(folder)
    target_directory.mkdir(parents=True, exist_ok=True)
    path = target_directory / f"{safe_name(title)}.md"
    lines = [
        "---",
        *(f"{key}: {yaml_value(value)}" for key, value in fields.items()),
        "---",
        "",
        f"# {title}",
        "",
        body,
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    connection_event("obsidian", "create_note", "ok", f"{agent} wrote Obsidian note {path}.")
    audit("obsidian-note", f"{agent} wrote an Obsidian note named {path.name}.")
    return path


def note_record(title: str, path: str, fields: dict[str, object] | None = None) -> dict[str, object]:
    record: dict[str, object] = {"title": title, "path": path}
    if fields:
        record.update(fields)
        record["title"] = str(fields.get("title", title))
        record["path"] = path
    return record


def list_notes(folder: str) -> list[dict[str, object]]:
    init_db()
    with open_db() as database:
        rows = database.execute(
            """
            SELECT title, path, fields_json FROM notes
            WHERE folder = ?
            ORDER BY created DESC, title DESC
            """,
            (folder,),
        ).fetchall()
    records: list[dict[str, object]] = []
    for row in rows:
        fields = parse_json_field(row["fields_json"], {})
        if not isinstance(fields, dict):
            fields = {}
        records.append(note_record(row["title"], row["path"], fields))
    known_paths = {record["path"] for record in records}

    directory = ROOT / folder
    if not directory.exists():
        return records
    for path in sorted(directory.glob("*.md"), reverse=True):
        note_path = relative_note_path(path)
        if note_path in known_paths:
            continue
        fields = read_frontmatter(path)
        records.append(note_record(fields.get("title", path.stem), note_path, fields))
    return records


def recon_results(target: str) -> dict[str, object]:
    clean_target = target.strip().lower()
    if not RECON_TARGET_PATTERN.fullmatch(clean_target):
        raise ValueError("Invalid recon target")

    directory = RECON_ROOT / clean_target
    if not directory.exists() or not directory.is_dir():
        return {"target": clean_target, "present": False, "sections": []}

    requested_files = (
        ("Scope Decision", "scope-decision.txt"),
        ("DNS", "dns.txt"),
        ("TLS", "tls.txt"),
        ("HTTP Headers", "http_headers.txt"),
    )
    sections = []
    for title, filename in requested_files:
        path = directory / filename
        if not path.exists() or not path.is_file():
            continue
        content = path.read_text(encoding="utf-8", errors="replace").strip()
        if len(content) > 6000:
            content = f"{content[:6000]}\n... truncated ..."
        sections.append(
            {
                "title": title,
                "path": str(path),
                "updated": datetime.fromtimestamp(path.stat().st_mtime, UTC)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                "content": content,
            }
        )
    return {"target": clean_target, "present": True, "sections": sections}


def public_http_url(value: object) -> str:
    raw_url = str(value or "").strip()
    if not raw_url:
        raise ValueError("URL is required")
    if "://" not in raw_url:
        raw_url = f"https://{raw_url}"
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("Credentials are not allowed in preview URLs")
    if not public_hostname(parsed.hostname):
        raise ValueError("Preview URL must resolve to a public address")
    return raw_url


def public_hostname(hostname: str) -> bool:
    if hostname.lower() in {"localhost", "localhost.localdomain"}:
        return False
    try:
        addresses = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ValueError(f"Could not resolve hostname: {hostname}") from error
    if not addresses:
        return False
    for _family, _type, _proto, _canonname, sockaddr in addresses:
        try:
            address = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return False
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            return False
    return True


def probe_site(data: dict[str, object]) -> dict[str, object]:
    url = public_http_url(data.get("url"))
    started = time.monotonic()
    method = "HEAD"
    try:
        response = site_request(url, method)
    except HTTPError as error:
        response = error
        if error.code in {405, 501}:
            method = "GET"
            response = site_request(url, method, range_header=True)
    except URLError as error:
        return {
            "url": url,
            "reachable": False,
            "status": "network_error",
            "error": str(error.reason),
            "checked_at": now(),
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }

    elapsed_ms = round((time.monotonic() - started) * 1000)
    status_code = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
    headers = response.headers
    frame_policy = frame_embedding_policy(headers)
    return {
        "url": url,
        "final_url": getattr(response, "url", url),
        "reachable": 200 <= status_code < 500,
        "status": status_code,
        "reason": getattr(response, "reason", ""),
        "method": method,
        "elapsed_ms": elapsed_ms,
        "checked_at": now(),
        "server": headers.get("server", ""),
        "content_type": headers.get("content-type", ""),
        "cache_control": headers.get("cache-control", ""),
        "x_frame_options": headers.get("x-frame-options", ""),
        "content_security_policy": headers.get("content-security-policy", ""),
        "frame_allowed": frame_policy["allowed"],
        "frame_block_reason": frame_policy["reason"],
    }


def frame_embedding_policy(headers) -> dict[str, object]:
    x_frame_options = headers.get("x-frame-options", "")
    content_security_policy = headers.get("content-security-policy", "")
    lower_xfo = x_frame_options.lower()
    lower_csp = content_security_policy.lower()
    reasons = []
    if "deny" in lower_xfo:
        reasons.append("X-Frame-Options is DENY")
    elif "sameorigin" in lower_xfo:
        reasons.append("X-Frame-Options is SAMEORIGIN")
    if "frame-ancestors" in lower_csp:
        frame_ancestors = lower_csp.split("frame-ancestors", 1)[1].split(";", 1)[0].strip()
        if "*" not in frame_ancestors and "127.0.0.1" not in frame_ancestors and "localhost" not in frame_ancestors:
            reasons.append(f"CSP frame-ancestors is {frame_ancestors}")
    return {"allowed": not reasons, "reason": "; ".join(reasons)}


def site_request(url: str, method: str, range_header: bool = False):
    headers = {"User-Agent": SITE_CHECK_USER_AGENT, "Accept": "text/html,*/*;q=0.8"}
    if range_header:
        headers["Range"] = "bytes=0-0"
    request = Request(url, headers=headers, method=method)
    response = urlopen(request, timeout=SITE_CHECK_TIMEOUT_SECONDS)
    if method == "GET":
        response.read(512)
    return response


class TMSHandler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return

    def send_json(self, data: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_head_response(self, route: str) -> bool:
        if route == "/":
            page = (Path(__file__).parent / "index.html").read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            return True
        if route in ("/api/health", "/api/overview", "/api/connections"):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            return True
        return False

    def read_json(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_JSON_PAYLOAD_BYTES:
            raise ValueError(f"Payload exceeds {MAX_JSON_PAYLOAD_BYTES} bytes")
        content = self.rfile.read(length)
        data = json.loads(content or b"{}")
        if not isinstance(data, dict):
            raise ValueError("JSON object required")
        return data

    def do_HEAD(self) -> None:
        route = urlparse(self.path).path
        if self.send_head_response(route):
            return
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()

    def do_GET(self) -> None:
        route = urlparse(self.path).path
        if route == "/":
            page = (Path(__file__).parent / "index.html").read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
            return
        if route == "/api/health":
            init_db()
            self.send_json(
                {
                    "status": "ok",
                    "vault": str(ROOT),
                    "database": str(database_path()),
                    "host": server_host(),
                    "port": server_port(),
                    "local_only": True,
                    "jira_mode": "read_only",
                    "authorization": authorization_status(),
                }
            )
            return
        if route == "/api/overview":
            self.send_json({folder: list_notes(folder) for folder in NOTE_FOLDERS})
            return
        if route == "/api/connections":
            self.send_json({"connections": list_connections()})
            return
        if route.startswith("/api/recon/"):
            target = unquote(route.removeprefix("/api/recon/"))
            self.send_json(recon_results(target))
            return
        self.send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        route = urlparse(self.path).path
        try:
            data = self.read_json()
            if route == "/api/imports/jira":
                key = str(data.get("key", "")).upper()
                summary = str(data.get("summary", ""))
                if not key or not summary:
                    raise ValueError("Jira key and summary are required")
                body = (
                    f"## Summary\n\n{summary}\n\n## Imported fields\n\n```json\n"
                    f"{json.dumps(data, indent=2)}\n```\n\n> [!info] Read-only import\n"
                    "> This snapshot was imported into TMS. TMS never writes to Jira."
                )
                path = note(
                    "Jira",
                    key,
                    {
                        "type": "jira_issue",
                        "jira_key": key,
                        "status": data.get("status", "unknown"),
                        "priority": data.get("priority", "unknown"),
                        "source": "read_only_import",
                    },
                    body,
                )
                audit("jira-import", f"Imported read-only Jira snapshot [[Jira/{path.stem}]].")
                connection_event("jira", "import_issue", "ok", f"Imported read-only Jira issue snapshot {key}.")
            elif route == "/api/imports/asana":
                path = import_asana_task_snapshot(data)
            elif route == "/api/imports/scanner-json":
                path = import_scanner_json(data)
            elif route in ("/api/imports/burp", "/api/imports/projectdiscovery"):
                tool = "burp" if route.endswith("burp") else "projectdiscovery"
                title = str(data.get("title", f"{tool} export {now()}"))
                content = str(data.get("content", ""))
                if not content:
                    raise ValueError("Export content is required")
                path = note(
                    "Evidence",
                    title,
                    {
                        "type": "tool_export",
                        "tool": tool,
                        "engagement": data.get("engagement", "unassigned"),
                        "sensitivity": "restricted",
                        "execution": "not_run_by_tms",
                    },
                    f"## Imported export\n\n```text\n{content}\n```",
                )
                audit("evidence-import", f"Stored {tool} export as [[Evidence/{path.stem}]]. No tool was executed.")
            elif route == "/api/approvals":
                path = record_approval(data)
            elif route == "/api/findings/ready":
                path = mark_finding_ready(data)
            elif route == "/api/connections":
                profile = configure_connection(data)
                self.send_json({"ok": True, "connection": profile}, HTTPStatus.OK)
                return
            elif route == "/api/codex/requests":
                path = create_codex_request(data)
                self.send_json({"ok": True, "note": relative_note_path(path)}, HTTPStatus.CREATED)
                return
            elif route == "/api/site/check":
                self.send_json({"ok": True, **probe_site(data)}, HTTPStatus.OK)
                return
            elif route in ("/api/beaker/obsidian-note", "/api/kermit/obsidian-note", "/api/agents/obsidian-note"):
                default_agent = "Kermit" if route == "/api/kermit/obsidian-note" else "Beaker"
                path = write_obsidian_note(data, default_agent)
                self.send_json({"ok": True, "note": str(path)}, HTTPStatus.CREATED)
                return
            else:
                self.send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
                return
            self.send_json({"ok": True, "note": str(path.relative_to(ROOT)).replace("\\", "/")}, HTTPStatus.CREATED)
        except PermissionError as error:
            self.send_json({"error": str(error)}, HTTPStatus.CONFLICT)
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json({"error": str(error)}, HTTPStatus.BAD_REQUEST)


if __name__ == "__main__":
    ROOT.mkdir(parents=True, exist_ok=True)
    init_db()
    ThreadingHTTPServer((server_host(), server_port()), TMSHandler).serve_forever()
