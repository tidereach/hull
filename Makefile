.PHONY: sbom verify test lock

sbom:
	.venv/bin/cyclonedx-py environment -o SBOM.json

verify:
	.venv/bin/spektralia verify-integrity && .venv/bin/spektralia verify-installed

test:
	.venv/bin/pytest -q

lock:
	.venv/bin/pip-compile --generate-hashes --output-file=requirements.lock pyproject.toml
