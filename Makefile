.PHONY: install test lint sandbox-image docker-integration serve

install:
	python -m pip install -e '.[dev]'

test:
	python -m pytest -q

lint:
	python -m ruff check .

sandbox-image:
	docker build --pull -f Dockerfile.sandbox -t systeme-local-sandbox:dev .

docker-integration: sandbox-image
	SYSTEME_LOCAL_RUN_DOCKER_TESTS=1 \
	SYSTEME_LOCAL_SANDBOX_IMAGE=systeme-local-sandbox:dev \
	python -m pytest -m integration -q

serve:
	uvicorn systeme_local_gateway.main:app --host 127.0.0.1 --port 8765
