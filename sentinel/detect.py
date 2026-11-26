"""Run every detector and return one combined, de-duplicated list of alerts."""
import pandas as pd

from .alerts import Alert, dedupe
from .rules import run_rules
from .stats import ip_anomalies


def detect(df: pd.DataFrame) -> list[Alert]:
    if df.empty:
        return []
    return dedupe(run_rules(df) + ip_anomalies(df))
