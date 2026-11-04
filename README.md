# CR Drafter

Pulls security and quality evidence from SonarQube, Anchore and OWASP ZAP, then drafts a change request as a Word document, with the raw reports exported as CSV and/or PDF.

It only reads existing scan results. It does not run scans or submit the change request: a person reviews the draft and submits it.

## Quick start

Requires Docker and `make`.

```bash
cp .env.example .env   # fill in URLs, credentials and change request details
make                   # builds the image and runs it with .env
```

Reports are written to `output/`. `.env` is ignored by git and Docker and is passed to the container at run time, so secrets are not stored in the image.

| Command | What it does |
|---|---|
| `make` or `make run` | Checks the env file exists, builds the image, then runs it |
| `make build` | Only builds the image |
| `make mock` | Builds the image and runs it with sample data, no `.env` or servers needed |

Override the defaults with `make IMAGE=cr-drafter:dev ENV_FILE=.env.staging OUTPUT=/tmp/cr-output`.

## Checks and output

| Module | Source | Output |
|---|---|---|
| `src/modules/sonarqube.py` | SonarQube quality gate, metrics and open issues for a branch (default `main`) | `sonarqube.csv/.pdf` |
| `src/modules/anchore.py` | Anchore vulnerabilities and policy check for an image tag (Enterprise v2 or Engine v1 API) | `anchore.csv/.pdf` |
| `src/modules/owasp_ocp.py` | Log of the OpenShift pod that ran the OWASP ZAP scan, parsed into alerts | `owasp_zap.csv/.pdf` and raw `owasp_zap_pod.log` |
| `src/report/word.py` | Change request draft with business justification, assurance summary, risk, rollback and approvals | `change_request_<CR_ID>.docx` |

A `summary.json` with each check's status is also written. If `CR_ID` is not set, the Word file is named after the application.

A check only runs if its required settings are present, so you can run any combination. If a source is down, it is marked `ERROR` in the draft and the rest still run.

| Check | Required settings |
|---|---|
| SonarQube | `SONAR_URL`, `SONAR_PROJECT` |
| Anchore | `ANCHORE_URL`, `ANCHORE_IMAGE` |
| OWASP ZAP | `OWASP_LOG_FILE`, or `OCP_API`, `OCP_NAMESPACE` and one of `OCP_POD` / `OCP_LABEL_SELECTOR` |

## Configuration

Every setting is either an env var or a command-line flag. See `.env.example` for a starting point and run `python src/main.py --help` for the full list.

You can also run the image directly and pass settings explicitly:

```bash
docker run --rm -v "$PWD/output:/app/output" \
  -e SONAR_TOKEN="$SONAR_TOKEN" -e ANCHORE_PASSWORD="$ANCHORE_PASSWORD" -e OCP_TOKEN="$OCP_TOKEN" \
  cr-drafter \
  --application payments-api --release-version 1.4.2 --cr-id CHG0012345 \
  --cr-reason "fix the intermittent payment timeout" \
  --sonar-url https://sonar.example.com --sonar-project payments-api \
  --anchore-url https://anchore.example.com --anchore-user ci --anchore-image registry.example.com/payments/payments-api:1.4.2 \
  --ocp-api https://api.cluster.example.com:6443 --ocp-namespace security-scans --ocp-label-selector job-name=zap-payments-api
```

Prefer env vars for secrets in CI: flags can appear in process lists and job logs.

### Useful options

- `REPORT_FORMATS=csv` / `pdf` / `csv,pdf` (default both)
- `CA_BUNDLE=/certs/ca.crt` for internal CAs (mount it in), or `INSECURE_TLS=true` for lab use only
- `STRICT=true` exits 1 if any check is FAIL or ERROR, so it can gate a pipeline. WARN does not fail it
- `OWASP_LOG_FILE=zap.log` parses a log you already captured with `oc logs` instead of calling the cluster
- `OCP_POD` picks an exact pod; otherwise `OCP_LABEL_SELECTOR` picks the newest matching pod. The OCP token needs `get/list` on `pods` and `pods/log` in that namespace
- `LOG_LEVEL=DEBUG` / `INFO` / `WARNING` / `ERROR` (default `INFO`)

### Justifying known CVEs

List CVEs that don't affect your release in a CSV file with these columns:

```csv
cve,justification
CVE-2024-12345,"TLS terminates at the load balancer, so the service never runs the affected code."
```

For each listed CVE found in the image, the Word draft adds a "Known CVEs with justification" section with Anchore's definition and your justification, and `anchore.csv/.pdf` gain `definition` and `justification` columns. PDF cells are shortened after 600 characters; the CSV and Word draft keep the full text.

- **Using the file:** `make run` picks up `anchore_justifications.csv` from the project root if it exists. Use `make run JUSTIFICATIONS=path/to/file.csv` for another location, or `ANCHORE_JUSTIFICATIONS` / `--anchore-justifications` without `make`.
- **Definitions:** these come from the description in Anchore's vulnerability results, or otherwise from `/query/vulnerabilities`. If neither has one, the draft says "Not available from Anchore".
- **Status and risk don't change:** a justified CVE still counts towards the Anchore status and risk rating.
- **Problems with the file:** if it can't be read or has the wrong columns, the check still runs and the draft notes that the file wasn't used.

## Run without Docker

```bash
pip install -r requirements.txt
python src/main.py
```

This does not load `.env` automatically: set the env vars in your shell or CI job, or pass flags.

## Try it with sample data

```bash
make mock                    # with Docker
python src/main.py --mock    # without Docker
```

Mock mode (`--mock` or `MOCK_MODE=true`) answers SonarQube, Anchore and OpenShift requests from the sample files in `src/mock_data/`, so the real parsing and report code runs without any servers. The sample data gives SonarQube PASS, Anchore FAIL and ZAP WARN, so the overall risk is High.

- Reports go to a `mock/` folder inside the output directory, so they stay apart from real ones.
- Real URLs, credentials, CR details and your justifications file are ignored and replaced with sample values.
- The Word draft is labelled as mock data. It uses invented findings, so never submit it.

To try other results, edit the files in `src/mock_data/`. For example, set `"status": "ERROR"` in `sonar_quality_gate.json` to make SonarQube FAIL.

## Run in CI

GitLab:

```yaml
draft_cr:
  image:
    name: registry.example.com/tools/cr-drafter:latest
    entrypoint: [""]
  script: ["python /app/src/main.py --output-dir $CI_PROJECT_DIR/output"]
  artifacts: { paths: [output/] }
```

Jenkins:

```groovy
withCredentials([...]) {
  sh 'docker run --rm -e SONAR_TOKEN -e ANCHORE_PASSWORD -e OCP_TOKEN --env-file cr.env -v $WORKSPACE/output:/app/output cr-drafter'
}
```

## Status and risk

Each check returns PASS, WARN, FAIL or ERROR:

| Check | FAIL | WARN | PASS |
|---|---|---|---|
| SonarQube | Quality gate `ERROR` | Quality gate `WARN` or unknown | Quality gate `OK` |
| Anchore | Policy evaluation failed | Any Critical or High vulnerability | Neither of those |
| OWASP ZAP | Any FAIL alert | Any WARN alert | Neither of those |

The worst status sets the risk rating and the wording of the justification:

| Worst status | Risk rating |
|---|---|
| PASS | Low |
| WARN | Medium |
| FAIL or ERROR | High |

Change the wording in `src/report/justification.py`.

### Review before submitting

- **Skipped checks don't affect the rating.** If only SonarQube runs and passes, the draft says all checks passed and rates the change Low. If nothing runs, it says the same, and `make` still succeeds. The log warns when no checks ran.
- **Some statements are fixed text.** The draft always says WARN findings were reviewed, tracked and accepted, and always describes automated health checks and rollback within the change window. Confirm these are true or change the wording.
- **Reports are not attached automatically.** The draft lists the filenames, so add the files from `output/` to the change request yourself.

## Logging

Logs go to stderr. To save them to a file, add `2> run.log`.

All logging settings are in `src/logger_config.py`. To log from another file:

```python
import logger_config

log = logger_config.get_logger(__name__)
```

## Project layout

```text
├── src/
│   ├── main.py               # entry point: runs the checks and writes the draft
│   ├── logger_config.py      # all logging settings
│   ├── mock.py               # mock mode: serves the sample data
│   ├── mock_data/            # sample API responses and ZAP log
│   ├── modules/              # one file per check, plus shared helpers in common.py
│   └── report/               # Word document and justification wording
├── .env.example              # template for your local .env
├── Dockerfile
├── Makefile
└── requirements.txt
```

## Adding a check

1. Create `src/modules/<name>.py` with `NAME`, `TITLE`, `add_args(parser)`, `enabled(args)` and `run(args, outdir)` returning a `Result` (see `src/modules/common.py`). Use `export(...)` to write CSV/PDF.
2. Add it to `MODULES` in `src/main.py`.

It then gets its own section, summary row and attachments in the Word document automatically.
