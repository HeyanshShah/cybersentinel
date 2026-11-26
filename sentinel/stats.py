"""Statistical detection with z-scores.

Idea: learn what "normal" looks like, then flag anything far from normal.
For each hour we count events per IP. The z-score says how many standard deviations
a count is above the average:
        z = (count - mean) / standard_deviation
z = 0 is perfectly average; z > 3 happens by chance well under 1% of the time,
so we treat it as an anomaly. This catches attacks no rule was written for.
"""
import pandas as pd

from .alerts import Alert

Z_THRESHOLD = 3.0


def hourly_counts(df: pd.DataFrame) -> pd.DataFrame:
    """Table of events per IP per hour (rows = hours, columns = IPs)."""
    return (df.set_index("timestamp")
              .groupby("ip")
              .resample("1h")
              .size()
              .unstack(level=0, fill_value=0)
              .fillna(0))


def zscores(series: pd.Series) -> pd.Series:
    std = series.std(ddof=0)
    if std == 0:
        return pd.Series(0.0, index=series.index)
    return (series - series.mean()) / std


def traffic_zscores(df: pd.DataFrame) -> pd.DataFrame:
    """Z-score of total events per hour, plus failure rate. Used by the dashboard."""
    hourly = df.set_index("timestamp").resample("1h")
    out = pd.DataFrame({
        "events": hourly.size(),
        "failures": hourly["event"].apply(lambda s: (s == "login_failed").sum()),
    })
    out["z_events"] = zscores(out["events"])
    out["z_failures"] = zscores(out["failures"])
    out["anomaly"] = (out[["z_events", "z_failures"]].max(axis=1) > Z_THRESHOLD)
    return out


def ip_anomalies(df: pd.DataFrame, threshold: float = Z_THRESHOLD) -> list[Alert]:
    """Flag IP-hours whose activity is far above that hour's normal across all IPs."""
    counts = hourly_counts(df)
    stacked = counts.stack()
    stacked = stacked[stacked > 0]  # only compare IPs that were actually active
    if len(stacked) < 10:
        return []
    z = zscores(stacked)
    alerts = []
    for (hour, ip), score in z[z > threshold].items():
        alerts.append(Alert(
            rule="zscore_spike", severity="medium" if score < 6 else "high", ip=ip,
            user="-", time=hour,
            detail=f"{int(stacked[(hour, ip)])} events in 1h (z={score:.1f}, "
                   f"normal ≈ {stacked.mean():.1f})",
            score=round(float(score), 2)))
    return alerts
