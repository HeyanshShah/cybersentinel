"""Behavioral baselines: learn each user's own normal, then flag departures.

A 3am login is normal for a night-shift admin and suspicious for a 9-to-5 accountant,
so a global "off-hours" rule is noisy. Instead each user gets an hour-of-day profile
built only from their PAST logins (no peeking at the future), smoothed so that
logging in at 7pm when you usually log in at 6pm isn't flagged.
"""
import numpy as np
import pandas as pd

from .alerts import Alert

MIN_HISTORY = 10        # need this many past logins before judging a user
PROB_THRESHOLD = 0.015  # flag hours this user almost never logs in at
SMOOTH = np.array([0.25, 0.5, 0.25])  # spread each login over neighboring hours


def _smoothed(hist: np.ndarray) -> np.ndarray:
    padded = np.concatenate([hist[-1:], hist, hist[:1]])  # hours wrap around midnight
    sm = np.convolve(padded, SMOOTH, mode="valid") + 0.05  # +0.05 = Laplace smoothing
    return sm / sm.sum()


def unusual_hour(df: pd.DataFrame) -> list[Alert]:
    ok = df[df.event == "login_success"].sort_values("timestamp")
    hist: dict[str, np.ndarray] = {}
    alerts = []
    for r in ok.itertuples():
        h = hist.setdefault(r.user, np.zeros(24))
        hour = r.timestamp.hour
        if h.sum() >= MIN_HISTORY:
            p = _smoothed(h)[hour]
            if p < PROB_THRESHOLD:
                # Learn only a little from suspicious logins (weight 0.3), so an attacker
                # who keeps coming back at 3am can't quickly teach the model 3am is normal,
                # while a real schedule change is still learned over time.
                alerts.append(Alert("unusual_hour", "low", r.ip, r.user, r.timestamp,
                                    f"login at {r.timestamp:%H:%M}; this user logs in at this "
                                    f"hour {p:.1%} of the time", score=round(float(p), 4),
                                    detector="baseline"))
                h[hour] += 0.3
                continue
        h[hour] += 1
    return _escalate_repeats(alerts)


def _escalate_repeats(alerts: list[Alert], window=pd.Timedelta("2h")) -> list[Alert]:
    """One odd-hour login is often innocent; several in a row is sustained activity
    at a time this person never works, so raise it to medium."""
    out, by_user = [], {}
    for a in alerts:
        by_user.setdefault(a.user, []).append(a)
    for user, items in by_user.items():
        items.sort(key=lambda a: a.time)
        i = 0
        while i < len(items):
            j = i
            while j + 1 < len(items) and items[j + 1].time - items[i].time <= window:
                j += 1
            first = items[i]
            if j > i:
                out.append(Alert("unusual_hour", "medium", first.ip, user, first.time,
                                 f"{j - i + 1} logins between {first.time:%H:%M} and "
                                 f"{items[j].time:%H:%M}, hours this user almost never works",
                                 score=first.score, detector="baseline"))
            else:
                out.append(first)
            i = j + 1
    return out
