.PHONY: install test lint sandbox-image serve

install:
	python -m pip install -e '.[dev]'

test:
	pytest -q

lint:
	ruff check .

sandbox-image:
	docker build -f Dockerfile.sandbox -t systeme-local-sandbox:dev .

serve:
	uvicorn systeme_local_gateway.main:app --host 127.0.0.1 --port 8765
