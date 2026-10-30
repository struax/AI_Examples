import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from app import server


@contextmanager
def isolated_storage():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        with (
            patch.object(server, "ROOT", root),
            patch.dict(os.environ, {"TMS_DB": str(root / "tms.sqlite3"), "TMS_OBSIDIAN_VAULT": ""}),
        ):
            yield root


class MarkdownVaultTests(unittest.TestCase):
    def test_note_is_markdown_with_frontmatter(self):
        with isolated_storage():
            result = server.note("Jira", "ABC-123", {"source": "read_only_import"}, "A read-only snapshot.")
            content = result.read_text(encoding="utf-8")
        self.assertEqual(result.suffix, ".md")
        self.assertIn('source: "read_only_import"', content)
        self.assertIn("# ABC-123", content)

    def test_unsupported_folder_is_rejected(self):
        with self.assertRaises(ValueError):
            server.note("Reports", "nope", {}, "")

    def test_note_title_cannot_escape_vault(self):
        with isolated_storage() as temporary:
            result = server.note("Evidence", "../../etc/passwd", {}, "Captured text only.")
            evidence_dir = (temporary / "Evidence").resolve()

        self.assertTrue(result.resolve().is_relative_to(evidence_dir))
        self.assertNotIn("/", result.name)

    def test_note_metadata_is_stored_in_sqlite(self):
        with isolated_storage():
            server.note("Jira", "ABC-123", {"type": "jira_issue"}, "A read-only snapshot.")
            with server.open_db() as database:
                row = database.execute(
                    "SELECT folder, title, path, type FROM notes WHERE path = ?",
                    ("Jira/ABC-123.md",),
                ).fetchone()
                record = dict(row)

        self.assertEqual(
            record,
            {
                "folder": "Jira",
                "title": "ABC-123",
                "path": "Jira/ABC-123.md",
                "type": "jira_issue",
            },
        )

    def test_list_notes_includes_frontmatter_fields(self):
        with isolated_storage() as temporary:
            tasks = temporary / "Tasks"
            tasks.mkdir()
            (tasks / "Plan.md").write_text(
                "\n".join(
                    [
                        "---",
                        'title: "Plan"',
                        'type: "task"',
                        'status: "queued"',
                        'assigned_agent: "Rowlf"',
                        "---",
                        "",
                        "# Plan",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            notes = server.list_notes("Tasks")

        self.assertEqual(notes[0]["title"], "Plan")
        self.assertEqual(notes[0]["status"], "queued")
        self.assertEqual(notes[0]["assigned_agent"], "Rowlf")

    def test_recon_results_reads_allowed_target_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            recon_root = Path(temporary)
            target = recon_root / "www.example.test"
            target.mkdir(parents=True)
            (target / "dns.txt").write_text("www.example.test [A] [192.0.2.1]", encoding="utf-8")
            with patch.object(server, "RECON_ROOT", recon_root):
                results = server.recon_results("www.example.test")

        self.assertTrue(results["present"])
        self.assertEqual(results["target"], "www.example.test")
        self.assertEqual(results["sections"][0]["title"], "DNS")
        self.assertIn("192.0.2.1", results["sections"][0]["content"])

    def test_recon_results_rejects_unsafe_target(self):
        with self.assertRaises(ValueError):
            server.recon_results("../etc/passwd")

    def test_site_probe_returns_status(self):
        class FakeResponse:
            status = 200
            code = 200
            reason = "OK"
            url = "https://www.example.test/"
            headers = {"content-type": "text/html", "server": "example"}

            def read(self, _size):
                return b""

        with (
            patch.object(server.socket, "getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 0))]),
            patch.object(server, "urlopen", return_value=FakeResponse()),
        ):
            result = server.probe_site({"url": "https://www.example.test/"})

        self.assertTrue(result["reachable"])
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["content_type"], "text/html")

    def test_site_probe_rejects_localhost(self):
        with self.assertRaises(ValueError):
            server.probe_site({"url": "http://127.0.0.1:8787"})

    def test_frame_policy_detects_sameorigin_block(self):
        result = server.frame_embedding_policy(
            {
                "x-frame-options": "SAMEORIGIN",
                "content-security-policy": "frame-ancestors 'self'",
            }
        )

        self.assertFalse(result["allowed"])
        self.assertIn("SAMEORIGIN", result["reason"])

    def test_finding_ready_requires_human_approval(self):
        with isolated_storage():
            with self.assertRaises(PermissionError):
                server.mark_finding_ready({"subject": "Reflected XSS in search"})

    def test_finding_ready_accepts_matching_approved_decision(self):
        with isolated_storage():
            server.note(
                "Approvals",
                "Reflected XSS in search",
                {"type": "approval", "approver": "Steven Truax", "decision": "approved"},
                "Approved for delivery.",
            )
            result = server.mark_finding_ready(
                {
                    "subject": "Reflected XSS in search",
                    "engagement": "TMS-LOCAL",
                    "summary": "Ready after human approval.",
                }
            )
            content = result.read_text(encoding="utf-8")

        self.assertIn('status: "ready_for_delivery"', content)
        self.assertIn('approval: "verified"', content)

    def test_record_approval_stores_sqlite_row(self):
        with isolated_storage():
            server.record_approval(
                {
                    "subject": "Reflected XSS in search",
                    "approver": "Steven Truax",
                    "decision": "approved",
                    "engagement": "TMS-LOCAL",
                    "rationale": "Evidence reviewed.",
                }
            )
            with server.open_db() as database:
                approval = database.execute(
                    """
                    SELECT subject, approver, decision, engagement, rationale
                    FROM approvals
                    WHERE subject = ?
                    """,
                    ("Reflected XSS in search",),
                ).fetchone()
                record = dict(approval)

        self.assertEqual(record["decision"], "approved")
        self.assertEqual(record["engagement"], "TMS-LOCAL")
        self.assertEqual(record["rationale"], "Evidence reviewed.")

    def test_finding_ready_stores_sqlite_row(self):
        with isolated_storage():
            server.record_approval(
                {
                    "subject": "Reflected XSS in search",
                    "approver": "Steven Truax",
                    "decision": "approved",
                }
            )
            server.mark_finding_ready(
                {
                    "subject": "Reflected XSS in search",
                    "engagement": "TMS-LOCAL",
                    "summary": "Ready after approval.",
                }
            )
            with server.open_db() as database:
                finding = database.execute(
                    """
                    SELECT subject, status, engagement, summary, approval_verified
                    FROM findings
                    WHERE subject = ?
                    """,
                    ("Reflected XSS in search",),
                ).fetchone()
                record = dict(finding)

        self.assertEqual(record["status"], "ready_for_delivery")
        self.assertEqual(record["engagement"], "TMS-LOCAL")
        self.assertEqual(record["summary"], "Ready after approval.")
        self.assertEqual(record["approval_verified"], 1)

    def test_wstg_coverage_table_is_created(self):
        with isolated_storage():
            server.init_db()
            with server.open_db() as database:
                database.execute(
                    """
                    INSERT INTO wstg_coverage (
                        engagement, wstg_id, title, category, status, created, updated
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "TMS-LOCAL",
                        "WSTG-v42-INFO-01",
                        "Conduct Search Engine Discovery Reconnaissance for Information Leakage",
                        "Information Gathering",
                        "planned",
                        server.now(),
                        server.now(),
                    ),
                )
                row = database.execute(
                    "SELECT status FROM wstg_coverage WHERE engagement = ? AND wstg_id = ?",
                    ("TMS-LOCAL", "WSTG-v42-INFO-01"),
                ).fetchone()

        self.assertEqual(row["status"], "planned")

    def test_default_connections_are_seeded(self):
        with isolated_storage():
            services = {profile["service"]: profile for profile in server.list_connections()}

        self.assertEqual(services["asana"]["status"], "pending_plugin")
        self.assertEqual(services["jira"]["status"], "pending_plugin")
        self.assertEqual(services["obsidian"]["mode"], "local_vault")

    def test_connection_config_rejects_secrets(self):
        with isolated_storage():
            with self.assertRaises(ValueError):
                server.configure_connection(
                    {
                        "service": "asana",
                        "config": {"access_token": "do-not-store-this"},
                    }
                )

    def test_configure_obsidian_and_write_note(self):
        with isolated_storage() as temporary:
            obsidian_vault = temporary / "Obsidian"
            profile = server.configure_connection(
                {
                    "service": "obsidian",
                    "status": "connected",
                    "config": {"vault_path": str(obsidian_vault), "default_folder": "TMS/Daily"},
                }
            )
            result = server.write_obsidian_note(
                {
                    "title": "Daily pentest notes",
                    "body": "Notes from today.",
                }
            )
            content = result.read_text(encoding="utf-8")

        self.assertEqual(profile["status"], "connected")
        self.assertEqual(result.name, "Daily pentest notes.md")
        self.assertIn("agent: \"Beaker\"", content)
        self.assertIn("type: \"technical_note\"", content)
        self.assertIn("Notes from today.", content)

    def test_obsidian_note_requires_connected_profile(self):
        with isolated_storage():
            with self.assertRaises(PermissionError):
                server.write_obsidian_note({"title": "Daily pentest notes"})

    def test_asana_task_snapshot_import_writes_task_note(self):
        with isolated_storage():
            result = server.import_asana_task_snapshot(
                {
                    "gid": "1200123456789",
                    "name": "Review WSTG coverage",
                    "engagement": "TMS-LOCAL",
                }
            )
            content = result.read_text(encoding="utf-8")
            with server.open_db() as database:
                event = database.execute(
                    "SELECT action FROM connection_events WHERE service = ?",
                    ("asana",),
                ).fetchone()

        self.assertIn('type: "asana_task"', content)
        self.assertIn("Review WSTG coverage", content)
        self.assertEqual(event["action"], "import_task")

    def test_scanner_json_import_writes_artifact_and_beaker_note(self):
        with isolated_storage() as root:
            result = server.import_scanner_json(
                {
                    "tool": "tenable",
                    "filename": "tenable-export.json",
                    "title": "Tenable export review",
                    "engagement": "SECTEST-1",
                    "notes": "Review criticals first.",
                    "content": '{"vulnerabilities":[{"plugin_id":123}],"assets":[{"host":"www.example.test"}]}',
                }
            )
            content = result.read_text(encoding="utf-8")
            artifacts = list((root / "Evidence" / "Uploads").glob("*.json"))
            task = root / "Tasks" / "Beaker Tenable export review Analysis.md"
            task_exists = task.exists()
            with server.open_db() as database:
                event = database.execute(
                    "SELECT action FROM audit_events WHERE action = ?",
                    ("scanner-json-import",),
                ).fetchone()

        self.assertEqual(len(artifacts), 1)
        self.assertTrue(task_exists)
        self.assertIn('type: "scanner_json_analysis_request"', content)
        self.assertIn('assigned_agent: "Beaker"', content)
        self.assertIn('tool: "tenable"', content)
        self.assertIn("Review criticals first.", content)
        self.assertIn("`vulnerabilities` items: 1", content)
        self.assertEqual(event["action"], "scanner-json-import")

    def test_scanner_json_import_rejects_invalid_json(self):
        with isolated_storage():
            with self.assertRaises(ValueError):
                server.import_scanner_json(
                    {
                        "tool": "crowdstrike",
                        "filename": "crowdstrike.json",
                        "content": "{not-json",
                    }
                )

    def test_codex_request_writes_work_queue_note(self):
        with isolated_storage():
            result = server.create_codex_request(
                {
                    "title": "Start baseline review",
                    "command": "Review the latest scanner JSON and summarize findings.",
                    "engagement": "SECTEST-1",
                    "priority": "high",
                    "context": "Use the uploaded Tenable export.",
                }
            )
            content = result.read_text(encoding="utf-8")

        self.assertIn('type: "codex_request"', content)
        self.assertIn('assigned_agent: "Codex"', content)
        self.assertIn('priority: "high"', content)
        self.assertIn("Review the latest scanner JSON", content)

    def test_codex_request_requires_body(self):
        with isolated_storage():
            with self.assertRaises(ValueError):
                server.create_codex_request({"command": ""})

    def test_authorization_status_reports_template_placeholders(self):
        with tempfile.TemporaryDirectory() as temporary:
            authorization = Path(temporary, "SECURITY_AUTHORIZATION.md")
            authorization.write_text("Engagement ID: <ticket/contract identifier>", encoding="utf-8")
            with patch.object(server, "AUTHORIZATION_FILE", authorization):
                status = server.authorization_status()

        self.assertTrue(status["present"])
        self.assertFalse(status["complete"])

    def test_authorization_status_reports_completed_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            authorization = Path(temporary, "SECURITY_AUTHORIZATION.md")
            authorization.write_text("Engagement ID: ENG-1234", encoding="utf-8")
            with patch.object(server, "AUTHORIZATION_FILE", authorization):
                status = server.authorization_status()

        self.assertTrue(status["present"])
        self.assertTrue(status["complete"])


if __name__ == "__main__":
    unittest.main()
