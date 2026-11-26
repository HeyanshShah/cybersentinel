"""Rule-based detection: fixed "if this, then alert" checks for known attack patterns.

Rules are precise and easy to explain, but only catch attacks you already know about.
That's why we pair them with statistical detection (stats.py).
"""
import pandas as pd

from .alerts import Alert

BRUTE_FORCE_THRESHOLD = 10      # failed logins from one IP...
BRUTE_FORCE_WINDOW = "5min"     # ...inside this window
SPRAY_USER_THRESHOLD = 8        # one IP trying this many different usernames
OFF_HOURS = range(0, 5)         # 12am-5am local time


def brute_force(df: pd.DataFrame) -> list[Alert]:
    """Many failed logins from one IP in a short window = password guessing."""
    fails = df[df.event == "login_failed"].set_index("timestamp").sort_index()
    alerts = []
    for ip, g in fails.groupby("ip"):
        counts = g["user"].rolling(BRUTE_FORCE_WINDOW).count()
        if counts.max() >= BRUTE_FORCE_THRESHOLD:
            alerts.append(Alert(
                rule="brute_force", severity="high", ip=ip, user=g["user"].mode()[0],
                time=counts.idxmax(),
                detail=f"{int(counts.max())} failed logins within {BRUTE_FORCE_WINDOW}"))
    return alerts


def password_spray(df: pd.DataFrame) -> list[Alert]:
    """One IP trying many different usernames = spraying a common password."""
    fails = df[df.event == "login_failed"]
    alerts = []
    for ip, g in fails.groupby("ip"):
        n_users = g["user"].nunique()
        if n_users >= SPRAY_USER_THRESHOLD:
            alerts.append(Alert(
                rule="password_spray", severity="high", ip=ip, user="(many)",
                time=g["timestamp"].min(),
                detail=f"tried {n_users} different usernames"))
    return alerts


def success_after_failures(df: pd.DataFrame, min_fails: int = 5) -> list[Alert]:
    """A successful login right after many failures = the guessing may have worked."""
    alerts = []
    for (ip, user), g in df.sort_values("timestamp").groupby(["ip", "user"]):
        streak = 0
        for row in g.itertuples():
            if row.event == "login_failed":
                streak += 1
            elif row.event == "login_success":
                if streak >= min_fails:
                    alerts.append(Alert(
                        rule="success_after_failures", severity="critical", ip=ip,
                        user=user, time=row.timestamp,
                        detail=f"successful login after {streak} failures"))
                streak = 0
    return alerts


def off_hours_login(df: pd.DataFrame) -> list[Alert]:
    ok = df[(df.event == "login_success") & df.timestamp.dt.hour.isin(OFF_HOURS)]
    return [Alert(rule="off_hours_login", severity="low", ip=r.ip, user=r.user,
                  time=r.timestamp, detail=f"login at {r.timestamp:%H:%M}")
            for r in ok.itertuples()]


def new_country(df: pd.DataFrame) -> list[Alert]:
    """A user logging in from a country they've never logged in from before."""
    ok = df[(df.event == "login_success") & (df.country != "Unknown")].sort_values("timestamp")
    seen: dict[str, set] = {}
    alerts = []
    for r in ok.itertuples():
        countries = seen.setdefault(r.user, set())
        if countries and r.country not in countries:
            alerts.append(Alert(
                rule="new_country", severity="medium", ip=r.ip, user=r.user,
                time=r.timestamp,
                detail=f"first login from {r.country} (usual: {', '.join(sorted(countries))})"))
        countries.add(r.country)
    return alerts


ALL_RULES = [brute_force, password_spray, success_after_failures, off_hours_login, new_country]


def run_rules(df: pd.DataFrame) -> list[Alert]:
    return [a for rule in ALL_RULES for a in rule(df)]
