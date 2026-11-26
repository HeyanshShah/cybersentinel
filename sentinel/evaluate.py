"""Measure detection quality against labeled data.

Two numbers matter in a security operations center (SOC):
  * Recall (detection rate): what fraction of real attacks raised at least one alert?
  * Precision: what fraction of alerts pointed at a real attack? Low precision means
    analysts drown in false alarms ("alert fatigue") and start ignoring alerts.
F1 is the harmonic mean of the two. We score each detector family separately and
combined, over several random seeds, so one lucky dataset can't inflate the numbers.
"""
from dataclasses import dataclass

import pandas as pd

from .detect import DETECTORS
from .alerts import dedupe
from .correlate import correlate
from .generate import ATTACK_TYPES, generate

PLACEHOLDER_USERS = {"-", "(many)", "(blank)"}
USER_MATCH_SLACK = pd.Timedelta("24h")   # follow-on alerts on the victim account
IP_MATCH_SLACK = pd.Timedelta("1h")


@dataclass
class Attack:
    attack_id: int
    kind: str
    ips: set
    users: set
    start: pd.Timestamp
    end: pd.Timestamp


def ground_truth(df: pd.DataFrame) -> list[Attack]:
    out = []
    for aid, g in df[df.label != "benign"].groupby("attack_id"):
        out.append(Attack(int(aid), g.label.iat[0], set(g.ip), set(g.user),
                          g.timestamp.min(), g.timestamp.max()))
    return out


def matches(alert, atk: Attack) -> bool:
    t = pd.Timestamp(alert.time)
    ips = {alert.ip, *alert.related_ips}
    if ips & atk.ips and atk.start - IP_MATCH_SLACK <= t <= atk.end + IP_MATCH_SLACK:
        return True
    return (alert.user not in PLACEHOLDER_USERS and alert.user in atk.users
            and atk.start - IP_MATCH_SLACK <= t <= atk.end + USER_MATCH_SLACK
            and alert.ip not in {"-"})


def score(alerts, attacks) -> dict:
    tp_alerts = sum(any(matches(a, k) for k in attacks) for a in alerts)
    detected = {k.attack_id for k in attacks if any(matches(a, k) for a in alerts)}
    precision = tp_alerts / len(alerts) if alerts else 0.0
    recall = len(detected) / len(attacks) if attacks else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"alerts": len(alerts), "true_alerts": tp_alerts, "precision": precision,
            "recall": recall, "f1": f1, "detected_ids": detected}


def evaluate(seeds=(1, 2, 3, 4, 5), **gen_kwargs) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Returns (scores per detector family, recall per attack type)."""
    rows, per_type = [], []
    configs = {name: (name,) for name in DETECTORS}
    configs["combined, no correlation"] = tuple(DETECTORS)
    configs["combined + risk correlation"] = tuple(DETECTORS)
    for seed in seeds:
        df = generate(seed=seed, **gen_kwargs)
        attacks = ground_truth(df)
        cache = {name: DETECTORS[name](df) for name in DETECTORS}
        for label, names in configs.items():
            alerts = dedupe([a for n in names for a in cache[n]])
            if label.endswith("risk correlation"):
                alerts, _ = correlate(alerts)
            s = score(alerts, attacks)
            rows.append({"detector": label, "seed": seed, **{k: v for k, v in s.items() if k != "detected_ids"}})
            if label.endswith("risk correlation"):
                for k in attacks:
                    per_type.append({"attack": k.kind, "detected": k.attack_id in s["detected_ids"]})
    res = pd.DataFrame(rows).groupby("detector", sort=False)[
        ["alerts", "true_alerts", "precision", "recall", "f1"]].mean()
    by_type = (pd.DataFrame(per_type).groupby("attack")["detected"]
               .agg(["sum", "count"]).rename(columns={"sum": "detected", "count": "total"})
               .reindex(ATTACK_TYPES))
    by_type["recall"] = by_type.detected / by_type.total
    return res, by_type


def to_markdown(res: pd.DataFrame, by_type: pd.DataFrame) -> str:
    lines = ["| Detector | Alerts/run | Precision | Recall | F1 |", "|---|---|---|---|---|"]
    for name, r in res.iterrows():
        lines.append(f"| {name} | {r.alerts:.0f} | {r.precision:.1%} | {r.recall:.1%} | {r.f1:.2f} |")
    lines += ["", "| Attack type | Detected | Recall |", "|---|---|---|"]
    for name, r in by_type.iterrows():
        lines.append(f"| {name} | {int(r.detected)}/{int(r.total)} | {r.recall:.0%} |")
    return "\n".join(lines)


if __name__ == "__main__":
    res, by_type = evaluate()
    print(to_markdown(res, by_type))
