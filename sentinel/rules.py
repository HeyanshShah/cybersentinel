"""Rule-based detection: precise checks for known attack patterns.

Rules are explainable and low-noise but only catch what you anticipated, which is
why CyberSentinel pairs them with statistical, behavioral-baseline, and ML detectors.
"""
import pandas as pd

from .alerts import Alert
from .geo import MAX_TRAVEL_KMH, haversine_km

BRUTE_FORCE_THRESHOLD = 10       # failures from one IP...
BRUTE_FORCE_WINDOW = "5min"      # ...inside this window
SLOW_THRESHOLD = 30              # failures from one IP in 24h, without a fast burst
PERSISTENT_THRESHOLD = 20        # ...or this many total, spread over 2+ days
SPRAY_USER_THRESHOLD = 8         # distinct usernames from one IP within 1 hour
STUFFING_MIN_IPS = 15            # distinct "quiet" IPs failing in one hour...
STUFFING_MIN_USERS = 10          # ...against this many different accounts
TAKEOVER_MIN_FAILS = 5
MIN_TRAVEL_KM = 500


def _fails(df):
    return df[df.event == "login_failed"]


def _peak_rate(df, window):
    """For each IP: the most failures seen inside any `window` (rolling count)."""
    f = _fails(df).sort_values("timestamp")
    if f.empty:
        return pd.Series(dtype=float), pd.Series(dtype="datetime64[ns]")
    counts = (f.set_index("timestamp").groupby("ip")["user"]
              .rolling(window).count().reset_index())
    idx = counts.groupby("ip")["user"].idxmax()
    peak = counts.loc[idx].set_index("ip")
    return peak["user"], peak["timestamp"]


def brute_force(df):
    peak, when = _peak_rate(df, BRUTE_FORCE_WINDOW)
    fails = _fails(df)
    top_user = fails.groupby("ip")["user"].agg(lambda s: s.mode().iat[0])
    return [Alert("brute_force", "high", ip, top_user[ip], when[ip],
                  f"{int(n)} failed logins within {BRUTE_FORCE_WINDOW}")
            for ip, n in peak.items() if n >= BRUTE_FORCE_THRESHOLD]


def low_and_slow(df):
    """Attackers who stay under rate limits: many failures spread over hours."""
    burst, _ = _peak_rate(df, BRUTE_FORCE_WINDOW)
    daily, when = _peak_rate(df, "24h")
    ok_ips = set(df.loc[df.event == "login_success", "ip"])
    fails = _fails(df)
    top_user = fails.groupby("ip")["user"].agg(lambda s: s.mode().iat[0])
    alerts = [Alert("low_and_slow", "medium", ip, top_user[ip], when[ip],
                    f"{int(n)} failures in 24h, never more than {int(burst.get(ip, 0))} per 5 min")
              for ip, n in daily.items()
              if n >= SLOW_THRESHOLD and burst.get(ip, 0) < BRUTE_FORCE_THRESHOLD and ip not in ok_ips]
    # Persistent: patient attackers who come back day after day, never tripping rate limits.
    flagged = {a.ip for a in alerts}
    per_ip = fails.groupby("ip").agg(n=("user", "size"), days=("timestamp", lambda t: t.dt.date.nunique()),
                                     last=("timestamp", "max"))
    for ip, r in per_ip.iterrows():
        if (ip not in flagged and ip not in ok_ips and r.n >= PERSISTENT_THRESHOLD and r.days >= 2
                and burst.get(ip, 0) < BRUTE_FORCE_THRESHOLD):
            alerts.append(Alert("low_and_slow", "medium", ip, top_user[ip], r["last"],
                                f"{int(r.n)} failures over {int(r.days)} days, max "
                                f"{int(burst.get(ip, 0))} per 5 min (persistent)"))
    return alerts


def password_spray(df):
    """One IP trying many usernames: 8+ in an hour, or 20+ in a day (slow spray)."""
    alerts = []
    for freq, need, label in (("h", SPRAY_USER_THRESHOLD, "1 hour"), ("D", 20, "24 hours")):
        f = _fails(df).assign(bucket=lambda d: d.timestamp.dt.floor(freq))
        g = f.groupby(["ip", "bucket"])["user"].nunique()
        hits = g[g >= need]
        best = hits.groupby(level="ip").idxmax()
        done = {a.ip for a in alerts}
        alerts += [Alert("password_spray", "high", ip, "(many)", bucket,
                         f"tried {hits[(ip, bucket)]} different usernames in {label}")
                   for ip, (_, bucket) in best.items() if ip not in done]
    return alerts


def credential_stuffing(df):
    """Distributed attack: many IPs, each making only 1-3 attempts (so per-IP rules
    miss it), together hitting many accounts. Detected by looking at the crowd."""
    known_good = set(df.loc[df.event == "login_success", "ip"])
    f = _fails(df)
    f = f[~f.ip.isin(known_good)].assign(hour=lambda d: d.timestamp.dt.floor("h"))
    alerts = []
    for hour, g in f.groupby("hour"):
        per_ip = g.groupby("ip").size()
        quiet = per_ip[per_ip <= 3].index
        sub = g[g.ip.isin(quiet)]
        if len(quiet) >= STUFFING_MIN_IPS and sub.user.nunique() >= STUFFING_MIN_USERS:
            alerts.append(Alert(
                "credential_stuffing", "high", f"{len(quiet)} IPs", "(many)", hour,
                f"{len(quiet)} IPs × ≤3 attempts each against {sub.user.nunique()} accounts",
                related_ips=tuple(quiet)))
    return alerts


def success_after_failures(df, min_fails: int = TAKEOVER_MIN_FAILS):
    """Many failures and then a success from the same IP on the same account:
    the guessing probably worked. Vectorized with a running failure streak."""
    d = df.sort_values(["ip", "user", "timestamp"]).reset_index(drop=True)
    fail = (d.event == "login_failed").astype(int)
    new_group = (d.ip != d.ip.shift()) | (d.user != d.user.shift()) | (fail == 0).shift(fill_value=True)
    streak = fail.groupby(new_group.cumsum()).cumsum()
    prev_streak = streak.shift(fill_value=0).where(~((d.ip != d.ip.shift()) | (d.user != d.user.shift())), 0)
    hits = d[(d.event == "login_success") & (prev_streak >= min_fails)]
    return [Alert("success_after_failures", "critical", r.ip, r.user, r.timestamp,
                  f"successful login after {int(prev_streak[i])} failures")
            for i, r in zip(hits.index, hits.itertuples())]


def impossible_travel(df):
    ok = df[(df.event == "login_success") & df.lat.notna()].sort_values(["user", "timestamp"])
    alerts = []
    for user, g in ok.groupby("user"):
        prev = None
        for r in g.itertuples():
            if prev is not None:
                km = haversine_km(prev.lat, prev.lon, r.lat, r.lon)
                hours = max((r.timestamp - prev.timestamp).total_seconds() / 3600, 1 / 60)
                if km >= MIN_TRAVEL_KM and km / hours > MAX_TRAVEL_KMH:
                    alerts.append(Alert(
                        "impossible_travel", "high", r.ip, user, r.timestamp,
                        f"{prev.city} → {r.city}: {km:,.0f} km in {hours * 60:,.0f} min "
                        f"({km / hours:,.0f} km/h)"))
            prev = r
    return alerts


def new_country(df, min_history: int = 5):
    ok = df[(df.event == "login_success") & (df.country != "Unknown")].sort_values("timestamp")
    seen: dict[str, dict] = {}
    alerts = []
    for r in ok.itertuples():
        hist = seen.setdefault(r.user, {})
        if sum(hist.values()) >= min_history and r.country not in hist:
            alerts.append(Alert("new_country", "medium", r.ip, r.user, r.timestamp,
                                f"first login from {r.country} (usual: {', '.join(sorted(hist))})"))
        hist[r.country] = hist.get(r.country, 0) + 1
    return alerts


ALL_RULES = [brute_force, low_and_slow, password_spray, credential_stuffing,
             success_after_failures, impossible_travel, new_country]


def run_rules(df):
    return [a for rule in ALL_RULES for a in rule(df)]
