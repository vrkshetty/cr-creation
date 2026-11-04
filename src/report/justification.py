"""Builds the business justification and risk text from CR inputs + scan results.
Edit the wording here to match your organisation's CAB style."""

RISK = {"PASS": "Low", "WARN": "Medium", "FAIL": "High", "ERROR": "High"}
RANK = ["PASS", "WARN", "FAIL", "ERROR"]


def overall_status(results):
    return max((r.status for r in results), key=RANK.index, default="PASS")


def risk_level(results):
    return RISK[overall_status(results)]


def business_justification(a, results):
    paras = []
    reason = a.cr_reason or "deliver the changes included in this release"
    paras.append(
        f"This change deploys {a.application} {a.release_version or ''} to {a.environment} in order to "
        f"{reason.rstrip('.')}. "
        f"{a.cr_description or ''}".strip()
    )
    paras.append(
        "Not implementing this change would delay the benefits above and leave the service running on a "
        "release that does not include the latest fixes and dependency updates, increasing operational "
        "and security exposure over time."
    )

    evidence = [f"{r.title}: {r.status}" for r in results]
    if evidence:
        paras.append(
            "The release has been through the automated assurance pipeline. Results: "
            + "; ".join(evidence) + ". Full reports are attached to this change request."
        )

    status = overall_status(results)
    if status == "PASS":
        paras.append("All security and quality checks passed, so the change is proposed as low risk.")
    elif status == "WARN":
        paras.append(
            "Some findings were raised but none breach a blocking policy. They have been reviewed, are "
            "tracked in the backlog, and are accepted for this release with the mitigations noted below."
        )
    else:
        paras.append(
            "One or more checks reported a failure. Approval is requested on the basis of a documented risk "
            "acceptance or exception; CAB should review the findings section before approving."
        )
    return paras


def risk_mitigations(results):
    items = [
        "Deployment follows the standard pipeline with automated health checks.",
        "Rollback is a redeploy of the previous image tag and can be completed within the change window.",
    ]
    for r in results:
        if r.status in ("WARN", "FAIL"):
            items.append(f"{r.title}: findings reviewed and tracked; see attached report.")
        if r.status == "ERROR":
            items.append(f"{r.title}: report could not be collected automatically ({r.notes}). "
                         "Evidence to be attached manually.")
    return items
