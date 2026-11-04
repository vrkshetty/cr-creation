"""OWASP ZAP: pull the log of the pod that ran the scan on OpenShift and extract the alerts.

Parses standard zap-baseline / zap-full-scan / zap-api-scan console output, e.g.
    WARN-NEW: Cookie No HttpOnly Flag [10010] x 3
        https://app.example.com/login (200 OK)
    FAIL-NEW: 0  FAIL-INPROG: 0  WARN-NEW: 9  WARN-INPROG: 0  INFO: 0  IGNORE: 0  PASS: 56
"""
import os
import re

import logger_config

from .common import Result, env, export, get, session, verify_flag

log = logger_config.get_logger(__name__)

NAME = "owasp_zap"
TITLE = "OWASP ZAP Dynamic Security Scan"
COLUMNS = ["level", "alert", "plugin_id", "instances", "sample_urls"]
ALERT = re.compile(r"\b(FAIL-NEW|FAIL-INPROG|WARN-NEW|WARN-INPROG|INFO|IGNORE|PASS):\s+(.+?)\s+\[(\d+)\](?:\s+x\s+(\d+))?")
TOTALS = re.compile(r"FAIL-NEW:\s*(\d+).*?WARN-NEW:\s*(\d+).*?PASS:\s*(\d+)")
URL = re.compile(r"^\s+(https?://\S+)")


def add_args(p):
    g = p.add_argument_group("OWASP ZAP on OpenShift")
    g.add_argument("--ocp-api", default=env("OCP_API"), help="e.g. https://api.cluster.example.com:6443")
    g.add_argument("--ocp-token", default=env("OCP_TOKEN"), help="Service account token with pods/log read")
    g.add_argument("--ocp-namespace", default=env("OCP_NAMESPACE"))
    g.add_argument("--ocp-pod", default=env("OCP_POD"), help="Exact pod name")
    g.add_argument("--ocp-label-selector", default=env("OCP_LABEL_SELECTOR"),
                   help="Used when no pod name given; newest matching pod wins, e.g. job-name=zap-scan")
    g.add_argument("--ocp-container", default=env("OCP_CONTAINER"))
    g.add_argument("--owasp-log-file", default=env("OWASP_LOG_FILE"),
                   help="Read an already-captured log instead of calling OpenShift")


def enabled(a):
    return bool(a.owasp_log_file or (a.ocp_api and a.ocp_namespace and (a.ocp_pod or a.ocp_label_selector)))


def _fetch_log(a):
    if a.owasp_log_file:
        log.info("Reading ZAP log from file %s", a.owasp_log_file)
        with open(a.owasp_log_file, encoding="utf-8", errors="replace") as f:
            return f.read(), os.path.basename(a.owasp_log_file)
    s = session(verify=verify_flag(a.insecure, a.ca_bundle), token=a.ocp_token)
    base = f"{a.ocp_api.rstrip('/')}/api/v1/namespaces/{a.ocp_namespace}/pods"
    pod = a.ocp_pod
    if not pod:
        pods = get(s, base, params={"labelSelector": a.ocp_label_selector}).json().get("items", [])
        if not pods:
            raise RuntimeError(f"No pods match '{a.ocp_label_selector}' in {a.ocp_namespace}")
        pod = max(pods, key=lambda p: p["metadata"]["creationTimestamp"])["metadata"]["name"]
        log.debug("Selected newest of %d pods matching '%s'", len(pods), a.ocp_label_selector)
    log.info("Fetching ZAP log from pod %s/%s", a.ocp_namespace, pod)
    params = {"container": a.ocp_container} if a.ocp_container else {}
    s.headers["Accept"] = "text/plain"
    return get(s, f"{base}/{pod}/log", params=params).text, pod


def parse(log):
    findings, totals, current = [], {}, None
    for line in log.splitlines():
        m = ALERT.search(line)
        if m:
            current = {"level": m.group(1), "alert": m.group(2).strip(), "plugin_id": m.group(3),
                       "instances": int(m.group(4) or 1), "urls": []}
            if current["level"] != "PASS":
                findings.append(current)
            continue
        t = TOTALS.search(line)
        if t:
            totals = {"FAIL-NEW": int(t.group(1)), "WARN-NEW": int(t.group(2)), "PASS": int(t.group(3))}
            current = None
            continue
        u = URL.match(line)
        if u and current is not None:
            current["urls"].append(u.group(1))
    for f in findings:
        f["sample_urls"] = " ".join(f.pop("urls")[:5])
    return findings, totals


def run(a, outdir):
    log, source = _fetch_log(a)
    raw = os.path.join(outdir, f"{NAME}_pod.log")
    with open(raw, "w", encoding="utf-8") as f:
        f.write(log)

    findings, totals = parse(log)
    findings.sort(key=lambda f: (not f["level"].startswith("FAIL"), not f["level"].startswith("WARN")))
    fails = sum(1 for f in findings if f["level"].startswith("FAIL"))
    warns = sum(1 for f in findings if f["level"].startswith("WARN"))

    summary = {
        "Log source": source if a.owasp_log_file else f"{a.ocp_namespace}/{source}",
        "FAIL alerts": totals.get("FAIL-NEW", fails), "WARN alerts": totals.get("WARN-NEW", warns),
        "Rules passed": totals.get("PASS", "-"), "Distinct alerts": len(findings),
    }
    status = "FAIL" if fails else "WARN" if warns else "PASS"
    notes = "" if totals or findings else "No ZAP alert lines found in the log - check the pod/container is correct."
    if notes:
        log.warning(notes)
    files = export(outdir, NAME, TITLE, summary, findings, COLUMNS, a.formats) + [raw]
    return Result(NAME, TITLE, status, summary, findings, files, notes)
