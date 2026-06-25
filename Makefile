.PHONY: sbom verify test lock

sbom:
	.venv/bin/cyclonedx-py requirements --output-reproducible -o SBOM.json requirements.lock

verify:
	.venv/bin/spektralia verify-integrity && .venv/bin/spektralia verify-installed

test:
	.venv/bin/pytest -q

lock:
	uv pip compile --python-version 3.11 --generate-hashes --output-file=requirements.lock pyproject.toml
