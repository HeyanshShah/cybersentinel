"""Run every detector family and return one de-duplicated alert list."""
import pandas as pd

from .alerts import Alert, dedupe
from .correlate import correlate
from .baseline import unusual_hour
from .ml import ml_anomalies
from .rules import run_rules
from .stats import ip_anomalies

DETECTORS = {
    "rules": run_rules,
    "statistical": ip_anomalies,
    "baseline": unusual_hour,
    "ml": ml_anomalies,
}


def detect(df: pd.DataFrame, use=("rules", "statistical", "baseline", "ml"),
           with_observations: bool = False):
    """All detectors -> de-duplicate -> risk-based correlation.
    With with_observations=True also returns the suppressed low-risk signals."""
    if df.empty:
        return ([], []) if with_observations else []
    alerts, observations = correlate(dedupe([a for name in use for a in DETECTORS[name](df)]))
    return (alerts, observations) if with_observations else alerts
