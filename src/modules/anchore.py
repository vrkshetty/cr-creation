"""Anchore: vulnerability list and policy evaluation for an image tag (Anchore Enterprise v2 or Engine v1 API)."""
import logger_config

from .common import Result, env, export, get, session, verify_flag

log = logger_config.get_logger(__name__)

NAME = "anchore"
TITLE = "Anchore Container Image Security Scan"
COLUMNS = ["severity", "vuln", "package", "package_version", "package_type", "fix", "url"]
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]


def add_args(p):
    g = p.add_argument_group("Anchore")
    g.add_argument("--anchore-url", default=env("ANCHORE_URL"), help="e.g. https://anchore.example.com")
    g.add_argument("--anchore-user", default=env("ANCHORE_USER"))
    g.add_argument("--anchore-password", default=env("ANCHORE_PASSWORD"))
    g.add_argument("--anchore-api", default=env("ANCHORE_API", "v2"), choices=["v1", "v2"])
    g.add_argument("--anchore-image", default=env("ANCHORE_IMAGE"),
                   help="Full tag, e.g. registry.example.com/team/app:1.4.2")
    g.add_argument("--anchore-digest", default=env("ANCHORE_DIGEST"), help="Optional: skip tag lookup")


def enabled(a):
    return bool(a.anchore_url and a.anchore_image)


def _resolve_digest(s, base, tag):
    data = get(s, f"{base}/images", params={"full_tag": tag, "fulltag": tag}).json()
    items = data.get("items", data) if isinstance(data, dict) else data
    for img in items or []:
        for d in img.get("image_detail", []) or img.get("tag_detail", []):
            if tag in (d.get("fulltag"), d.get("full_tag"), d.get("pull_string")):
                return img.get("image_digest") or img.get("imageDigest")
    raise RuntimeError(f"Image {tag} not found in Anchore - has it been added and analysed?")


def _find_status(obj):
    """Policy check responses differ between versions; take the first 'status' we find."""
    if isinstance(obj, dict):
        if isinstance(obj.get("status"), str):
            return obj["status"]
        obj = list(obj.values())
    if isinstance(obj, list):
        for v in obj:
            st = _find_status(v)
            if st:
                return st
    return None


def run(a, outdir):
    base = f"{a.anchore_url.rstrip('/')}/{a.anchore_api}"
    s = session(verify=verify_flag(a.insecure, a.ca_bundle), auth=(a.anchore_user or "", a.anchore_password or ""))

    log.info("Fetching vulnerabilities for %s", a.anchore_image)
    digest = a.anchore_digest or _resolve_digest(s, base, a.anchore_image)
    log.debug("Using image digest %s", digest)
    vulns_raw = get(s, f"{base}/images/{digest}/vuln/all").json().get("vulnerabilities", [])
    vulns = [{
        "severity": v.get("severity", "Unknown"), "vuln": v.get("vuln", v.get("vulnerability_id", "")),
        "package": v.get("package_name", v.get("package", "")), "package_version": v.get("package_version", ""),
        "package_type": v.get("package_type", ""), "fix": v.get("fix", "None"), "url": v.get("url", ""),
    } for v in vulns_raw]
    vulns.sort(key=lambda v: SEV_ORDER.index(v["severity"]) if v["severity"] in SEV_ORDER else 99)

    counts = {sev: sum(1 for v in vulns if v["severity"] == sev) for sev in SEV_ORDER}
    fixable = sum(1 for v in vulns if v["fix"] not in ("", "None", None))

    policy, notes = "not evaluated", ""
    try:
        policy = _find_status(get(s, f"{base}/images/{digest}/check", params={"tag": a.anchore_image}).json()) \
                 or "unknown"
    except Exception as e:                       # policy is useful but not essential
        notes = f"Policy evaluation unavailable: {e}"
        log.warning(notes)

    summary = {
        "Image": a.anchore_image, "Digest": digest, "Policy evaluation": policy,
        **{f"{k} vulnerabilities": c for k, c in counts.items() if c or k in ("Critical", "High")},
        "Total vulnerabilities": len(vulns), "Fix available": fixable,
    }
    if policy.lower() == "fail":
        status = "FAIL"
    elif counts["Critical"] or counts["High"]:
        status = "WARN"
    else:
        status = "PASS"
    files = export(outdir, NAME, TITLE, summary, vulns, COLUMNS, a.formats)
    return Result(NAME, TITLE, status, summary, vulns, files, notes)
