"""Risk-based alerting: escalate weak signals only when they stack up.

A single 2am login or a single new country is weak evidence on its own; real people
travel and work late. Raising an alert for every one buries analysts in noise.
Instead, low-severity signals are kept as "observations" and only escalated when the
same account accumulates enough risk within 24 hours (the approach used by Splunk's
Risk-Based Alerting). Medium+ alerts always pass straight through.
"""
from collections import defaultdict

import pandas as pd

from .alerts import Alert

RISK = {"low": 15, "medium": 30, "high": 60, "critical": 100}
WINDOW = pd.Timedelta("24h")
ESCALATE_AT = 30          # two low signals, or one low + one medium


def correlate(alerts: list[Alert]) -> tuple[list[Alert], list[Alert]]:
    """Returns (alerts to show, suppressed observations)."""
    strong = [a for a in alerts if a.severity != "low"]
    weak = [a for a in alerts if a.severity == "low"]
    by_user = defaultdict(list)
    for a in alerts:
        if a.user not in ("-", "(many)", "(blank)"):
            by_user[a.user].append(a)

    escalated, suppressed = [], []
    for a in weak:
        t = pd.Timestamp(a.time)
        # only independent evidence counts: a different detection rule on this account
        related = [b for b in by_user.get(a.user, [])
                   if b.rule != a.rule and abs(pd.Timestamp(b.time) - t) <= WINDOW]
        risk = RISK[a.severity] + sum(RISK[b.severity] for b in related)
        if related and risk >= ESCALATE_AT:
            escalated.append(Alert(
                a.rule, "medium", a.ip, a.user, a.time,
                f"{a.detail} [risk {risk}: correlated with {len(related)} other signal(s)]",
                score=a.score, detector=a.detector))
        else:
            suppressed.append(a)
    return strong + escalated, suppressed
