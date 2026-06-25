.PHONY: sbom verify test lock

sbom:
	.venv/bin/cyclonedx-py environment --output-reproducible -o SBOM.json
	python3 -c "\
import json; \
f=open('SBOM.json'); sbom=json.load(f); f.close(); \
[c.update({'externalReferences':[r for r in c.get('externalReferences',[]) if not r.get('url','').startswith('file://')]}) for c in sbom.get('components',[])]; \
f=open('SBOM.json','w'); json.dump(sbom,f,indent=2); f.write('\n'); f.close()"

verify:
	.venv/bin/spektralia verify-integrity && .venv/bin/spektralia verify-installed

test:
	.venv/bin/pytest -q

lock:
	.venv/bin/pip-compile --generate-hashes --output-file=requirements.lock pyproject.toml
