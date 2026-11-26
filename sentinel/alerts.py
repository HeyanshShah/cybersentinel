"""Alerts: what we found, how bad it is, which ATT&CK technique, and where to send it."""
from dataclasses import asdict, dataclass, field
import json
import os
import urllib.request

import pandas as pd

from .mitre import lookup

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
    detector: str = "rule"          # rule | statistical | ml | baseline
    related_ips: tuple = ()          # for distributed attacks (many IPs, one alert)
    technique: str = field(init=False)
    tactic: str = field(init=False)

    def __post_init__(self):
        tid, name, tactic = lookup(self.rule)
        self.technique = f"{tid} {name}" if tid != "—" else name
        self.tactic = tactic


COLS = ["severity", "rule", "time", "ip", "user", "detail", "technique", "tactic",
        "detector", "score"]


def to_frame(alerts: list[Alert]) -> pd.DataFrame:
    if not alerts:
        return pd.DataFrame(columns=COLS)
    df = pd.DataFrame([asdict(a) for a in alerts])[COLS]
    df["_rank"] = df.severity.map(SEVERITY_ORDER)
    return df.sort_values(["_rank", "time"]).drop(columns="_rank").reset_index(drop=True)


def alert_key(a: Alert):
    return (a.rule, a.ip, a.user, pd.Timestamp(a.time).floor("h"))


def dedupe(alerts: list[Alert]) -> list[Alert]:
    """Keep one alert per (rule, ip, user, hour) so analysts aren't spammed."""
    seen, out = set(), []
    for a in alerts:
        k = alert_key(a)
        if k not in seen:
            seen.add(k)
            out.append(a)
    return out


def send_slack(alerts: list[Alert], webhook_url: str | None = None,
               min_severity: str = "high") -> int:
    """Post serious alerts to Slack. Set SLACK_WEBHOOK_URL to enable."""
    url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
    if not url:
        return 0
    serious = [a for a in alerts if SEVERITY_ORDER[a.severity] <= SEVERITY_ORDER[min_severity]]
    if not serious:
        return 0
    text = "\n".join(f":rotating_light: *{a.severity.upper()}* {a.rule} ({a.technique}) | "
                     f"{a.ip} | {a.user} | {a.detail}" for a in serious[:20])
    req = urllib.request.Request(url, data=json.dumps({"text": text}).encode(),
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10)
    return len(serious)
