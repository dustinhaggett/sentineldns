from __future__ import annotations


def domain_category_from_score(score: float) -> str:
    if score < 20:
        return "Normal"
    if score < 40:
        return "Ads-Tracking"
    if score < 75:
        return "Suspicious"
    return "Likely Malicious"


def explain_domain_result(risk_score: float, reason_tags: list[str]) -> dict[str, object]:
    category = domain_category_from_score(risk_score)
    if not reason_tags:
        reason_tags = ["pattern appears common"]
    return {"category": category, "reason_tags": reason_tags[:5]}


def explain_anomaly_result(
    anomaly_score: float,
    reason_tags: list[str],
    queries_per_min: float,
    nxdomain_rate: float,
) -> dict[str, str | list[str]]:
    if anomaly_score < 0.35:
        action = "No action needed"
        tone = "Traffic looks consistent with normal browsing behavior."
    elif anomaly_score < 0.65:
        action = "Keep an eye on it"
        tone = "This window has unusual DNS behavior that may still be benign."
    elif anomaly_score < 0.85:
        action = "Run a malware scan and change passwords if you entered credentials recently"
        tone = "The DNS pattern is suspicious and consistent with possible phishing or background malware activity."
    else:
        action = "Disconnect from network and investigate immediately"
        tone = "DNS activity is strongly unusual and consistent with possible compromise."

    summary = (
        f"{tone} Query volume was {queries_per_min:.1f} per minute, with an NXDOMAIN rate of "
        f"{nxdomain_rate:.0%}. This signal is not proof of compromise, but it warrants attention."
    )
    return {
        "summary": summary,
        "recommended_action": action,
        "reason_tags": reason_tags[:5],
    }
