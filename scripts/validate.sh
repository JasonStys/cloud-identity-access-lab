#!/usr/bin/env bash
# Jason Stys: real signed-identity/native-policy acceptance and full maintained source/doc checks.
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# END CODE MAP
set -euo pipefail
mkdir -p out
python -m ruff check cial scripts tests
python -m ruff format --check cial scripts tests
python -m mypy
python -m pytest --cov=cial --cov-report=term-missing --cov-report=json:out/coverage.json
python scripts/code_map.py --check
python scripts/file_guide.py --check
python scripts/validate_repo.py
npm run typecheck
npm run build
npm run test:unit
npm run code-map:check
npm run format:check
