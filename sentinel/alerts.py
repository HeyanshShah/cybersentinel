"""Alerts: what we found, how bad it is, and where to send it."""
from dataclasses import asdict, dataclass
import json
import os
import urllib.request

import pandas as pd

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Alert:
    rule: str
    severity: str
    ip: str
    user: str
    time: pd.Timestamp
    detail: str
    score: float | None = None


def to_frame(alerts: list[Alert]) -> pd.DataFrame:
    cols = ["severity", "rule", "time", "ip", "user", "detail", "score"]
    if not alerts:
        return pd.DataFrame(columns=cols)
    df = pd.DataFrame([asdict(a) for a in alerts])[cols]
    df["_rank"] = df.severity.map(SEVERITY_ORDER)
    return df.sort_values(["_rank", "time"]).drop(columns="_rank").reset_index(drop=True)


def dedupe(alerts: list[Alert]) -> list[Alert]:
    """Keep one alert per (rule, ip, user, hour) so analysts aren't spammed."""
    seen, out = set(), []
    for a in alerts:
        key = (a.rule, a.ip, a.user, pd.Timestamp(a.time).floor("h"))
        if key not in seen:
            seen.add(key)
            out.append(a)
    return out


def send_slack(alerts: list[Alert], webhook_url: str | None = None,
               min_severity: str = "high") -> int:
    """Post serious alerts to a Slack channel. Set SLACK_WEBHOOK_URL to enable.
    Returns how many alerts were sent."""
    url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
    if not url:
        return 0
    limit = SEVERITY_ORDER[min_severity]
    serious = [a for a in alerts if SEVERITY_ORDER[a.severity] <= limit]
    if not serious:
        return 0
    text = "\n".join(f":rotating_light: *{a.severity.upper()}* {a.rule} | {a.ip} | "
                     f"{a.user} | {a.detail}" for a in serious[:20])
    req = urllib.request.Request(url, data=json.dumps({"text": text}).encode(),
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10)
    return len(serious)
