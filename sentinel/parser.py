"""Turn raw logs into one standard table: one row per login attempt.

Supported formats (auto-detected):
  * CSV  - timestamp,user,ip,event[,country,city,lat,lon,label,attack_id]
  * Linux auth.log / secure (OpenSSH), e.g.
      Dec 10 06:55:46 web01 sshd[24200]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2
  * Windows Security event export (CSV) - Event ID 4624 = logon success, 4625 = failure
  * Cowrie SSH honeypot JSON lines - cowrie.login.success / cowrie.login.failed
"""
from datetime import datetime
import json
from pathlib import Path
import re

import pandas as pd

BASE = ["timestamp", "user", "ip", "event"]
GEO = ["country", "city", "lat", "lon"]
COLUMNS = BASE + GEO

AUTH_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s(?P<time>[\d:]{8})\s\S+\ssshd\[\d+\]:\s"
    r"(?:message repeated (?P<repeat>\d+) times: \[ ?)?"  # syslog collapses duplicates
    r"(?P<result>Failed|Accepted) (?:password|publickey|keyboard-interactive/pam) for "
    r"(?:invalid user )?(?P<user>\S*) from (?P<ip>[\d.a-fA-F:]+)"
)
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _finish(df: pd.DataFrame) -> pd.DataFrame:
    for c in COLUMNS:
        if c not in df:
            df[c] = None if c in ("country", "city") else float("nan")
    df["country"] = df["country"].fillna("Unknown")
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["user"] = df["user"].fillna("").astype(str).replace("", "(blank)")
    extra = [c for c in df.columns if c not in COLUMNS]
    return df[COLUMNS + extra].sort_values("timestamp", kind="stable").reset_index(drop=True)


def parse_auth_log(lines, year: int = 2026) -> pd.DataFrame:
    """Parse syslog-style SSH logs. Syslog has no year, so we start at `year` and
    roll over when the month goes backwards (Dec -> Jan)."""
    rows, last_month = [], None
    for line in lines:
        m = AUTH_RE.search(line)
        if not m:
            continue
        month = MONTHS.get(m["mon"])
        if month is None:
            continue
        if last_month and month < last_month:
            year += 1
        last_month = month
        h, mi, s = map(int, m["time"].split(":"))
        row = (datetime(year, month, int(m["day"]), h, mi, s), m["user"], m["ip"],
               "login_success" if m["result"] == "Accepted" else "login_failed")
        rows.extend([row] * int(m["repeat"] or 1))
    return _finish(pd.DataFrame(rows, columns=BASE))


def parse_windows_csv(df: pd.DataFrame) -> pd.DataFrame:
    """Windows Security log exported to CSV (e.g. Get-WinEvent | Export-Csv)."""
    cols = {c.lower(): c for c in df.columns}
    id_col = cols.get("eventid") or cols.get("id")
    df = df[df[id_col].isin([4624, 4625])]
    out = pd.DataFrame({
        "timestamp": df[cols.get("timecreated") or cols.get("timestamp")],
        "user": df[cols.get("targetusername") or cols.get("user")],
        "ip": df[cols.get("ipaddress") or cols.get("ip")].fillna("-"),
        "event": df[id_col].map({4624: "login_success", 4625: "login_failed"}),
    })
    return _finish(out)


def parse_cowrie(lines) -> pd.DataFrame:
    rows = []
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("eventid") in ("cowrie.login.success", "cowrie.login.failed"):
            rows.append((e["timestamp"], e.get("username", ""), e.get("src_ip", "-"),
                         "login_success" if e["eventid"].endswith("success") else "login_failed"))
    df = pd.DataFrame(rows, columns=BASE)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True).dt.tz_localize(None)
    return _finish(df)


def load_csv(path_or_buffer) -> pd.DataFrame:
    df = pd.read_csv(path_or_buffer)
    lower = {c.lower() for c in df.columns}
    if {"eventid", "id"} & lower and "event" not in lower:
        return parse_windows_csv(df)
    missing = set(BASE) - set(df.columns)
    if missing:
        raise ValueError(f"CSV is missing columns: {sorted(missing)}")
    return _finish(df)


def load(path) -> pd.DataFrame:
    path = Path(path)
    if path.suffix.lower() == ".csv":
        return load_csv(path)
    with open(path, encoding="utf-8", errors="ignore") as f:
        first = f.readline()
        f.seek(0)
        if first.lstrip().startswith("{"):
            return parse_cowrie(f)
        return parse_auth_log(f)


def parse_lines(lines) -> pd.DataFrame:
    """Auto-detect format for a list of raw lines (used by the live monitor)."""
    lines = list(lines)
    if lines and lines[0].lstrip().startswith("{"):
        return parse_cowrie(lines)
    return parse_auth_log(lines)
