# Stack: Python

## Detect
`*.py`; `pyproject.toml`, `requirements*.txt`, `Pipfile`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pdm.lock`. Frameworks reported: fastapi, flask, django. Missing lockfile is reported in `lockfiles_missing` (feeds SUP-PINNING).

## Pinned tools that apply
- semgrep: `python/lang/security`, plus `python/django/security`, `python/flask/security`, `python/fastapi/security` when the framework is present.
- bandit (`bandit -r {project} -x tests,venv`): Python only; semgrep has no equivalent for every bandit rule.
- pip-audit (against `requirements.txt` or a pinned export) and osv-scanner on the lockfile.
- gitleaks, syft; hadolint/trivy config if a Dockerfile exists.
- Not pinned: safety, pip-licenses. `NOT-TESTED: tool unavailable: <name>` unless the project ships it.

## Gotchas to read for
- `pickle`, `yaml.load` without `SafeLoader`, `marshal`, `shelve` on data a user can influence.
- `subprocess(..., shell=True)`, `os.system`, `eval`/`exec`, f-string SQL, Jinja `Template(user_input)` (SSTI), `render_template_string`.
- Flask: `debug=True` or the Werkzeug debugger reachable from outside loopback; hard-coded `SECRET_KEY`; `app.run(host="0.0.0.0")` in the shipped entry point.
- Django: `DEBUG = True`, `ALLOWED_HOSTS = ["*"]`, `csrf_exempt`, raw `.extra()` / `RawSQL`, `mark_safe` on user data, `SECRET_KEY` in the repo.
- FastAPI: routes without a dependency-injected auth check; Pydantic models used for output that include internal fields; permissive `CORSMiddleware(allow_origins=["*"], allow_credentials=True)`.
- `requests(..., verify=False)`, `tarfile.extractall` / `zipfile.extractall` without path checks, `tempfile.mktemp`, `random` used for tokens (use `secrets`), `assert` used for access checks (stripped under `-O`).
- Unpinned or URL/VCS dependencies, `pip install` in entrypoints, install-time code in `setup.py`.

## Check ids
SEC-SAST (semgrep + bandit), SEC-SCA (pip-audit + osv-scanner), SUP-PINNING (lockfile), SEC-INJECTION-DYNAMIC and SEC-SSRF-DYNAMIC for the sinks above once they are reachable in a local instance.
