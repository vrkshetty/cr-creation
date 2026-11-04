"""SonarQube: quality gate, key metrics and open issues for a project branch (default: main)."""
import logger_config

from .common import Result, env, export, get, session, verify_flag

log = logger_config.get_logger(__name__)

NAME = "sonarqube"
TITLE = "SonarQube Static Code Analysis"
METRICS = "bugs,vulnerabilities,security_hotspots,code_smells,coverage,duplicated_lines_density,ncloc," \
          "reliability_rating,security_rating,sqale_rating"
COLUMNS = ["severity", "type", "rule", "component", "line", "message", "status", "key"]


def add_args(p):
    g = p.add_argument_group("SonarQube")
    g.add_argument("--sonar-url", default=env("SONAR_URL"))
    g.add_argument("--sonar-token", default=env("SONAR_TOKEN"))
    g.add_argument("--sonar-project", default=env("SONAR_PROJECT"), help="Project key")
    g.add_argument("--sonar-branch", default=env("SONAR_BRANCH", "main"))
    g.add_argument("--sonar-issue-types", default=env("SONAR_ISSUE_TYPES", "VULNERABILITY,BUG"),
                   help="Comma list: VULNERABILITY,BUG,CODE_SMELL")


def enabled(a):
    return bool(a.sonar_url and a.sonar_project)


def run(a, outdir):
    base = a.sonar_url.rstrip("/")
    # Sonar tokens work as basic-auth username with an empty password on all versions
    s = session(verify=verify_flag(a.insecure, a.ca_bundle), auth=(a.sonar_token or "", ""))
    q = {"branch": a.sonar_branch} if a.sonar_branch else {}

    log.info("Fetching quality gate, metrics and issues for %s (branch %s)", a.sonar_project, a.sonar_branch)
    gate = get(s, f"{base}/api/qualitygates/project_status",
               params={"projectKey": a.sonar_project, **q}).json().get("projectStatus", {})

    measures = get(s, f"{base}/api/measures/component",
                   params={"component": a.sonar_project, "metricKeys": METRICS, **q}).json()
    metrics = {m["metric"]: m.get("value", m.get("period", {}).get("value", ""))
               for m in measures.get("component", {}).get("measures", [])}

    issues, page = [], 1
    while True:
        data = get(s, f"{base}/api/issues/search", params={
            "componentKeys": a.sonar_project, "types": a.sonar_issue_types,
            "resolved": "false", "ps": 500, "p": page, **q}).json()
        for i in data.get("issues", []):
            issues.append({
                "severity": i.get("severity", ""), "type": i.get("type", ""), "rule": i.get("rule", ""),
                "component": i.get("component", "").split(":", 1)[-1], "line": i.get("line", ""),
                "message": i.get("message", ""), "status": i.get("status", ""), "key": i.get("key", ""),
            })
        total = data.get("paging", {}).get("total", data.get("total", 0))
        log.debug("Fetched issues page %d (%d of %d)", page, len(issues), total)
        if page * 500 >= min(total, 10000) or not data.get("issues"):   # API caps at 10k
            break
        page += 1
    if total > 10000:
        log.warning("SonarQube reports %d open issues but its API returns at most 10000", total)

    gate_status = gate.get("status", "NONE")
    by_sev = {}
    for i in issues:
        by_sev[i["severity"]] = by_sev.get(i["severity"], 0) + 1

    summary = {
        "Project": a.sonar_project, "Branch": a.sonar_branch,
        "Quality gate": gate_status,
        "Bugs": metrics.get("bugs", "-"), "Vulnerabilities": metrics.get("vulnerabilities", "-"),
        "Security hotspots": metrics.get("security_hotspots", "-"),
        "Code smells": metrics.get("code_smells", "-"), "Coverage %": metrics.get("coverage", "-"),
        "Duplication %": metrics.get("duplicated_lines_density", "-"), "Lines of code": metrics.get("ncloc", "-"),
        "Open issues (by severity)": ", ".join(f"{k}: {v}" for k, v in sorted(by_sev.items())) or "0",
        "Dashboard": f"{base}/dashboard?id={a.sonar_project}&branch={a.sonar_branch}",
    }
    status = {"OK": "PASS", "WARN": "WARN", "ERROR": "FAIL"}.get(gate_status, "WARN")
    files = export(outdir, NAME, TITLE, summary, issues, COLUMNS, a.formats)
    failed = [c for c in gate.get("conditions", []) if c.get("status") == "ERROR"]
    notes = "; ".join(f"{c.get('metricKey')} {c.get('actualValue')} (threshold {c.get('errorThreshold')})"
                      for c in failed)
    return Result(NAME, TITLE, status, summary, issues, files,
                  f"Failed gate conditions: {notes}" if notes else "")
