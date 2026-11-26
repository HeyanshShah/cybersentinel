"""Load logs into a pandas DataFrame with one row per event.

Supports two formats:
  * CSV with columns: timestamp, user, ip, event, country  (our generated sample data)
  * Linux /var/log/auth.log (real SSH server logs), e.g.
      Nov 25 03:14:07 web01 sshd[2211]: Failed password for root from 203.0.113.5 port 52100 ssh2
"""
from pathlib import Path
import re

import pandas as pd

COLUMNS = ["timestamp", "user", "ip", "event", "country"]

# Regex = a pattern for matching text. Each (?P<name>...) captures a named piece.
AUTH_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s\S+\ssshd\[\d+\]:\s"
    r"(?P<result>Failed|Accepted) \w+ for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.]+)"
)


def load_csv(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = set(COLUMNS[:4]) - set(df.columns)
    if missing:
        raise ValueError(f"CSV is missing columns: {sorted(missing)}")
    if "country" not in df:
        df["country"] = "Unknown"
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df[COLUMNS].sort_values("timestamp").reset_index(drop=True)


def parse_auth_log(lines, year: int = 2026) -> pd.DataFrame:
    rows = []
    for line in lines:
        m = AUTH_RE.search(line)
        if not m:
            continue  # ignore lines that aren't login attempts
        rows.append({
            "timestamp": pd.to_datetime(f"{year} {m['ts']}", format="%Y %b %d %H:%M:%S"),
            "user": m["user"],
            "ip": m["ip"],
            "event": "login_success" if m["result"] == "Accepted" else "login_failed",
            "country": "Unknown",
        })
    return pd.DataFrame(rows, columns=COLUMNS)


def load(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    if path.suffix.lower() == ".csv":
        return load_csv(path)
    with open(path, encoding="utf-8", errors="ignore") as f:
        return parse_auth_log(f)
