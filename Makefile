.PHONY: install lock-check lint format-check typecheck docs-check audit-python test quality sandbox-image docker-integration serve

install:
	python -m pip install -r tools/requirements-bootstrap.txt
	uv sync --frozen --extra dev --python python

lock-check:
	uv lock --check

lint:
	uv run --frozen --extra dev ruff check .

format-check:
	uv run --frozen --extra dev python scripts/check_python_format.py --worktree

typecheck:
	uv run --frozen --extra dev python scripts/check_python_typing.py --worktree

docs-check:
	uv run --frozen --extra dev python scripts/check_markdown_links.py
	uv run --frozen --extra dev python scripts/check_evidence_governance.py --as-of 2026-07-18T20:00:00Z --fail-within-days 0
	uv run --frozen --extra dev pytest -q tests/test_documentation_governance.py

audit-python:
	uv run --frozen --extra dev python scripts/audit_python_dependencies.py

test:
	uv run --frozen --extra dev pytest -q

quality: lock-check lint format-check typecheck docs-check audit-python test

sandbox-image:
	docker build --pull -f Dockerfile.sandbox -t systeme-local-sandbox:dev .

docker-integration: sandbox-image
	SYSTEME_LOCAL_RUN_DOCKER_TESTS=1 \
	SYSTEME_LOCAL_SANDBOX_IMAGE=systeme-local-sandbox:dev \
	uv run --frozen --extra dev pytest -m integration -q

serve:
	uv run --frozen --extra dev uvicorn systeme_local_gateway.main:app --host 127.0.0.1 --port 8765
