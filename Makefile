# Project Manager API - developer workflow
PYTHON ?= python

.PHONY: clean install test coverage verify-migration import-check routes-check run docker-up docker-down

## Remove test/build artifacts. Run this (or `git clean -fdx --dry-run`)
## before delivering a snapshot so no .coverage/.pytest_cache/__pycache__ ship.
clean:
	find . -name '__pycache__' -exec rm -rf {} + 2>/dev/null; \
	rm -rf .pytest_cache .coverage htmlcov

## Install pinned runtime + test dependencies.
install:
	$(PYTHON) -m pip install -r requirements.txt

## Run the test suite.
test:
	$(PYTHON) -m pytest -v

## Run tests with coverage.
coverage:
	$(PYTHON) -m pytest --cov=app --cov-report=term-missing

## Run alembic upgrade head on a throwaway DB and confirm the schema
## matches Base.metadata (alembic check).
verify-migration:
	$(PYTHON) scripts/verify_migration.py

## Verify the application imports and print the title.
import-check:
	ENVIRONMENT=test SECRET_KEY=test-secret-key-local-verification $(PYTHON) -c "from app.main import app; print(app.title)"

## Print all API routes.
routes-check:
	ENVIRONMENT=test SECRET_KEY=test-secret-key-local-verification $(PYTHON) -c "from fastapi.routing import APIRoute; from app.main import app; [print(r.path) for r in app.routes if isinstance(r, APIRoute)]"

## Run the dev server (requires you to export SECRET_KEY first).
run:
	@if [ -z "$(SECRET_KEY)" ]; then echo "ERROR: export SECRET_KEY first, e.g.  export SECRET_KEY=$$(openssl rand -hex 32)"; exit 1; fi
	ENVIRONMENT=development SECRET_KEY="$(SECRET_KEY)" $(PYTHON) -m uvicorn app.main:app --reload

## Build and start the full Postgres-backed stack (requires .env with real secrets).
docker-up:
	docker compose up --build -d

docker-down:
	docker compose down
