"""Machine-learning detection with an Isolation Forest (unsupervised).

We summarize each IP's activity per hour into features (attempts, failure ratio,
distinct usernames, ...). An Isolation Forest builds many random decision trees;
unusual points get isolated in very few splits, so a short average path = anomaly.
No labels are needed to train it, which matters because real logs don't come with
an answer key.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .alerts import Alert

FEATURES = ["attempts", "failures", "fail_ratio", "distinct_users", "night",
            "new_ip", "log_attempts"]


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    d = df.assign(hour=df.timestamp.dt.floor("h"), fail=(df.event == "login_failed").astype(int))
    g = d.groupby(["ip", "hour"])
    feats = pd.DataFrame({
        "attempts": g.size(),
        "failures": g["fail"].sum(),
        "distinct_users": g["user"].nunique(),
    })
    feats["fail_ratio"] = feats.failures / feats.attempts
    hours = feats.index.get_level_values("hour")
    feats["night"] = ((hours.hour < 6) | (hours.hour >= 22)).astype(int)
    first_seen = d.groupby("ip")["hour"].min()
    feats["new_ip"] = (hours == first_seen.reindex(feats.index.get_level_values("ip")).values).astype(int)
    feats["log_attempts"] = np.log1p(feats.attempts)
    return feats[FEATURES]


def ml_anomalies(df: pd.DataFrame, contamination: float = 0.02, seed: int = 0) -> list[Alert]:
    if df.empty:
        return []
    feats = build_features(df)
    if len(feats) < 50:
        return []  # not enough data to learn "normal"
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed)
    model.fit(feats.values)
    scores = -model.score_samples(feats.values)  # higher = more anomalous
    flagged = model.predict(feats.values) == -1
    alerts = []
    for (ip, hour), row, s in zip(feats.index[flagged], feats[flagged].itertuples(), scores[flagged]):
        # Only alert on anomalies that look hostile (failures involved); an unusually
        # busy-but-successful hour is interesting but not a security alert.
        if row.failures == 0:
            continue
        sev = "high" if s > np.quantile(scores, 0.995) else "medium"
        alerts.append(Alert(
            "ml_anomaly", sev, ip, "-", hour,
            f"{row.attempts} attempts, {row.fail_ratio:.0%} failed, {row.distinct_users} usernames "
            f"(anomaly score {s:.2f})", score=round(float(s), 3), detector="ml"))
    return alerts
