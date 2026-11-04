"""Mock mode: run the whole tool against the sample responses in mock_data/, with no real servers.

It replaces requests.Session.get, so the modules and report code run exactly as they normally do.
Connection settings and CR identifiers are overridden so that real URLs and credentials are never
used and a mock draft can't be mistaken for a real change request.
"""
import os
import re
from urllib.parse import urlsplit

import requests

import logger_config

log = logger_config.get_logger(__name__)

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mock_data")

# (URL path pattern, sample file)
ROUTES = [
    (r"/api/qualitygates/project_status$", "sonar_quality_gate.json"),
    (r"/api/measures/component$", "sonar_measures.json"),
    (r"/api/issues/search$", "sonar_issues.json"),
    (r"/images$", "anchore_images.json"),
    (r"/images/[^/]+/vuln/all$", "anchore_vulns.json"),
    (r"/images/[^/]+/check$", "anchore_check.json"),
    (r"/query/vulnerabilities$", "anchore_definitions.json"),
    (r"/pods$", "ocp_pods.json"),
    (r"/pods/[^/]+/log$", "zap_pod.log"),
]


def _fake_get(self, url, **kwargs):
    r = requests.Response()
    r.url = url
    r.encoding = "utf-8"
    path = urlsplit(url).path
    for pattern, filename in ROUTES:
        if re.search(pattern, path):
            log.debug("Serving %s from %s", path, filename)
            r.status_code = 200
            with open(os.path.join(DATA_DIR, filename), "rb") as f:
                r._content = f.read()
            return r
    log.warning("No sample response for %s", path)
    r.status_code = 404
    r._content = b""
    return r


def apply(a):
    """Switch this run to sample data."""
    log.warning("MOCK MODE: using sample data, not real scan results. Do not submit this draft")
    requests.Session.get = _fake_get

    # Sample change request, so a real CR ID or application can't end up on fake evidence
    a.application = "payments-api-sample"
    a.release_version = "0.0.0-mock"
    a.cr_id = "MOCK-0001"
    a.cr_title = "MOCK - Deploy payments-api-sample 0.0.0-mock"
    a.cr_reason = "demonstrate the change request draft using sample data"
    a.cr_description = "Sample change generated in mock mode. No real release is involved."

    # Sample connections, replacing any real URLs and credentials in the environment
    a.sonar_url = "https://sonarqube.mock.example.com"
    a.sonar_token = "mock"
    a.sonar_project = "payments-api-sample"
    a.anchore_url = "https://anchore.mock.example.com"
    a.anchore_user = "mock"
    a.anchore_password = "mock"
    a.anchore_image = "registry.example.com/sample/payments-api-sample:0.0.0-mock"
    a.anchore_digest = None
    a.anchore_justifications = os.path.join(DATA_DIR, "anchore_justifications.csv")
    a.ocp_api = "https://api.cluster.mock.example.com:6443"
    a.ocp_token = "mock"
    a.ocp_namespace = "security-scans"
    a.ocp_pod = None
    a.ocp_label_selector = "job-name=zap-payments-api-sample"
    a.owasp_log_file = None

    # Keep mock reports apart from real ones
    a.output_dir = os.path.join(a.output_dir, "mock")
