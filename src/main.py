#!/usr/bin/env python3
"""Change request drafter.

Runs each collector module, exports its report (CSV and/or PDF) and writes a Word change request
with a business justification. Every setting can be passed as a CLI flag or an environment
variable (e.g. --sonar-token or SONAR_TOKEN), so the same image works in Docker and any CI tool.

To add a check: create modules/<name>.py with NAME, TITLE, add_args(parser), enabled(args),
run(args, outdir) -> Result, then add it to MODULES below.
"""
import argparse
import json
import os
import sys

import logger_config
import mock
from modules import anchore, owasp_ocp, sonarqube
from modules.common import Result, env
from report import word

MODULES = [sonarqube, anchore, owasp_ocp]

log = logger_config.get_logger("cr_drafter")


def parse_args():
    p = argparse.ArgumentParser(description="Draft a change request from scan reports")
    g = p.add_argument_group("Change request")
    g.add_argument("--application", default=env("CR_APPLICATION", "Application"))
    g.add_argument("--release-version", default=env("CR_RELEASE_VERSION"))
    g.add_argument("--environment", default=env("CR_ENVIRONMENT", "Production"))
    g.add_argument("--cr-id", default=env("CR_ID"))
    g.add_argument("--cr-title", default=env("CR_TITLE"))
    g.add_argument("--cr-description", default=env("CR_DESCRIPTION"))
    g.add_argument("--cr-reason", default=env("CR_REASON"), help="Business driver, e.g. 'fix the payments timeout'")
    g.add_argument("--change-type", default=env("CR_CHANGE_TYPE", "Normal"))
    g.add_argument("--change-window", default=env("CR_CHANGE_WINDOW"))
    g.add_argument("--requester", default=env("CR_REQUESTER"))
    g.add_argument("--implementation-plan", default=env("CR_IMPLEMENTATION_PLAN"))
    g.add_argument("--rollback-plan", default=env("CR_ROLLBACK_PLAN"))

    g = p.add_argument_group("General")
    g.add_argument("--output-dir", default=env("OUTPUT_DIR", "output"))
    g.add_argument("--formats", default=env("REPORT_FORMATS", "csv,pdf"), help="csv, pdf or csv,pdf")
    g.add_argument("--insecure", action="store_true", default=env("INSECURE_TLS", "false").lower() == "true",
                   help="Skip TLS verification (lab use only)")
    g.add_argument("--ca-bundle", default=env("CA_BUNDLE"), help="Path to internal CA bundle")
    g.add_argument("--strict", action="store_true", default=env("STRICT", "false").lower() == "true",
                   help="Exit 1 if any check is FAIL or ERROR")
    g.add_argument("--mock", action="store_true", default=env("MOCK_MODE", "false").lower() == "true",
                   help="Use the sample data in src/mock_data instead of real servers")
    logger_config.add_args(g)

    for m in MODULES:
        m.add_args(p)
    a = p.parse_args()
    a.formats = [f.strip().lower() for f in a.formats.split(",") if f.strip()]
    return a


def main():
    a = parse_args()
    logger_config.setup(a.log_level)
    if a.mock:
        mock.apply(a)
    os.makedirs(a.output_dir, exist_ok=True)
    results = []

    for m in MODULES:
        if not m.enabled(a):
            log.info("Skipping %s: required parameters not set", m.NAME)
            continue
        log.info("Running %s", m.NAME)
        try:
            r = m.run(a, a.output_dir)
        except Exception as e:      # one broken source shouldn't stop the CR being drafted
            log.exception("%s failed", m.NAME)
            r = Result(m.NAME, m.TITLE, "ERROR", notes=str(e))
        log.log(logger_config.status_level(r.status), "%s finished: status=%s, findings=%d",
                m.NAME, r.status, len(r.findings))
        results.append(r)

    if not results:
        log.warning("No checks ran: the draft will contain no scan evidence")

    doc = word.write(a, results, a.output_dir)
    with open(os.path.join(a.output_dir, "summary.json"), "w") as f:
        json.dump([{"name": r.name, "status": r.status, "summary": r.summary, "notes": r.notes,
                    "files": [os.path.basename(x) for x in r.files]} for r in results], f, indent=2, default=str)
    log.info("Change request written to %s", doc)

    if a.strict and any(r.status in ("FAIL", "ERROR") for r in results):
        log.error("Strict mode: exiting 1 because at least one check is FAIL or ERROR")
        sys.exit(1)


if __name__ == "__main__":
    main()
