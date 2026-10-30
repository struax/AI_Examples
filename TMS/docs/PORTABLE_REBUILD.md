# Portable Rebuild Guide

This package contains the reusable TMS dashboard source, tests, vault templates, agent definitions, references, and Codex build notes.

It intentionally excludes runtime and engagement-specific material such as SQLite databases, logs, uploaded scanner JSON, live evidence notes, Jira notes, work-queue notes, task notes, and delivered report artifacts.

## Rebuild Steps

1. Unzip the package on the new computer.
2. Change into the project directory:

   ```bash
   cd TMS
   ```

3. Review and fill out the authorization template:

   ```bash
   cp SECURITY_AUTHORIZATION.example.md SECURITY_AUTHORIZATION.md
   ```

4. Run the test suite:

   ```bash
   python -m unittest discover -s tests
   ```

5. Start the dashboard:

   ```bash
   python app/server.py
   ```

6. Open the dashboard:

   ```text
   http://127.0.0.1:8787
   ```

## Docker Option

If Docker Compose is available, start the dashboard with:

```bash
docker compose up --build
```

## Runtime Notes

- Python 3.12+ is recommended.
- The app currently uses only the Python standard library.
- The dashboard binds to `127.0.0.1`.
- The default runtime database is created at `vault/tms.sqlite3`.
- Scanner uploads are stored under `vault/Evidence/Uploads/`.
- New engagement data should be kept in its own vault folders.

## Included Build Memory

- `docs/CODEX_BUILD_PROMPTS.md` records the dashboard-building prompts and implementation notes.
- `README.md` contains the normal quick-start and operating notes.
- `SECURITY_AUTHORIZATION.example.md` is a sanitized template for new authorized engagements.
