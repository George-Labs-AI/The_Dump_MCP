# Cursor Bugbot Review Rules

## What to Flag

### Security (all languages)

- Hardcoded secrets, API keys, tokens, or credentials
- Sensitive data (PII, passwords, tokens) logged or printed
- SQL injection vectors — raw string interpolation in queries
- Missing authentication or authorization checks on endpoints
- Insecure use of `eval()`, `exec()`, or equivalent

### Python (Backend, Frontend, File Processing)

- Bare `except:` or `except Exception:` without re-raise or logging
- Missing timeouts on `requests.get/post/put/delete` calls
- Mutable default arguments in function definitions (e.g., `def f(x=[])`)
- Use of `os.system()` or `subprocess.call()` with `shell=True` and unsanitized input
- Synchronous blocking calls inside `async` functions without `asyncio.to_thread()`

### TypeScript (Dashboard, MCP)

- Use of `any` type — should use `unknown` and narrow
- Unhandled promise rejections — missing `.catch()` or try/catch on awaits
- Missing error boundaries around components that fetch data
- Non-null assertions (`!`) on values that could realistically be null

### Swift (iOS)

- Force unwraps (`!`) on optionals that could be nil at runtime
- Missing `[weak self]` in closures that capture self in view models or services
- Hardcoded API URLs or base URLs (should come from configuration)
- Retain cycles in delegate patterns or closure captures

### Known traps in The Dump (each has caused a real production bug)

These four apply across repos, so flag them wherever they appear.

- **A single database row passed to `normalize_rows`.** In production the web app uses the pg8000 database driver, which returns rows as plain lists rather than dictionaries. Passing the result of `fetchone()` to `normalize_rows()` (in `The_Dump_Front_End/helpers/data_connect_helpers.py`) therefore breaks only in production. Flag it, and ask for `fetchall()` with `force_list=True`. Also flag unit tests that fake database rows as dictionaries, because they pass locally while hiding this bug; fakes should be lists with a cursor `description`.
- **A new web route added to `main.py`.** New routes in the web app belong in a Flask blueprint under `routes/`, registered from `main.py`. `main.py` already holds thousands of lines of older routes and must not grow.
- **Reading or writing the old sorting columns.** The backend migration `migrations/2026-09-24_drop_dead_columns_and_tables.sql` lists columns and tables that are unused and waiting to be dropped. Flag any new code that reads or writes them, in any repo. They include the tables `note_field_embeddings` and `embedding_validation_log`; on `organized_notes` the columns `embedding`, `predicted_category`, `winner_field`, `winner_gap`, `sub_category_id`, `sub_cat_name`, `llm_call_made`, `llm_response_valid`, `local_ner_anchors`, `project`, `goal`, `organizing_status`, `chunked`, `vector_store_status`, `formatted`, `user_vote_weight`, `last_reclustered` and `retired_at`; `categories_by_user.embedding` and `embedded_date`; and `users.category_decision_guide`. The migration file is the full list.
- **The note-type list changed in only one place.** The list of note types (`NOTE_TYPES`) is written by hand twice: in the backend's `app/openai_interactions.py` and in the web app's `helpers/normalization_helpers.py`. A pull request that changes one must change the other identically, or the web app will reject types the backend produces (or the reverse).

## What to Ignore

### Directories and files

- Everything in `old/` directories (legacy/archived code)
- Everything in `docs/archive/` (dated history, not current instructions)
- Generated files (`*.generated.*`, `*.pb.swift`, build output)
- Lock files (`pnpm-lock.yaml`, `package-lock.json`, `Podfile.lock`)
- `node_modules/`, `__pycache__/`, `.build/`, `dist/`
- `.env.example` files (these intentionally contain placeholder values)

### Style and formatting

- Style issues already enforced by ruff, ESLint, Prettier, or SwiftLint
- Import ordering (handled by linters)
- Whitespace, indentation, line length (handled by formatters)

### Test code

- Test fixtures, mock data, and factory functions
- Hardcoded values in test assertions (expected behavior)
- Simplified error handling in test helpers
