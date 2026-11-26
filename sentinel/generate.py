"""Generate realistic fake login logs with hidden attacks, for demos and testing.

Normal users log in during work hours from their home country, with an occasional
typo'd password. On top of that we inject 4 attacks the detectors should find.
Using a fixed random seed means the same data comes out every time.
"""
from datetime import datetime, timedelta
import random

import pandas as pd

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
         "ivan", "judy", "mallory", "oscar", "peggy", "trent", "victor", "wendy"]


def generate(days: int = 7, seed: int = 42, start: datetime | None = None) -> pd.DataFrame:
    rng = random.Random(seed)
    start = start or datetime(2026, 11, 16)
    home_ip = {u: f"10.0.{i // 250}.{i % 250 + 2}" for i, u in enumerate(USERS)}
    rows = []

    # --- normal activity -------------------------------------------------
    for d in range(days):
        day = start + timedelta(days=d)
        if day.weekday() >= 5:
            continue  # quieter weekends: skip
        for u in USERS:
            for _ in range(rng.randint(2, 5)):
                t = day + timedelta(hours=rng.uniform(8, 18))
                if rng.random() < 0.15:  # typo'd password once in a while
                    rows.append((t - timedelta(seconds=20), u, home_ip[u], "login_failed", "US"))
                rows.append((t, u, home_ip[u], "login_success", "US"))

    # --- attack 1: brute force on one account ----------------------------
    t = start + timedelta(days=1, hours=2, minutes=13)
    for i in range(40):
        rows.append((t + timedelta(seconds=6 * i), "admin", "203.0.113.45", "login_failed", "RU"))

    # --- attack 2: password spraying across many accounts ----------------
    t = start + timedelta(days=2, hours=14)
    for i, u in enumerate(USERS):
        rows.append((t + timedelta(seconds=40 * i), u, "198.51.100.77", "login_failed", "CN"))

    # --- attack 3: guessed password -> successful break-in ---------------
    t = start + timedelta(days=3, hours=3, minutes=2)
    for i in range(7):
        rows.append((t + timedelta(seconds=10 * i), "mallory", "192.0.2.10", "login_failed", "BR"))
    rows.append((t + timedelta(seconds=80), "mallory", "192.0.2.10", "login_success", "BR"))

    # --- attack 4: stolen credentials used from abroad -------------------
    t = start + timedelta(days=4, hours=11)
    rows.append((t, "grace", "185.220.101.4", "login_success", "NL"))

    df = pd.DataFrame(rows, columns=["timestamp", "user", "ip", "event", "country"])
    return df.sort_values("timestamp").reset_index(drop=True)


if __name__ == "__main__":
    out = "sample_data/login_logs.csv"
    generate().to_csv(out, index=False)
    print(f"wrote {out}")
