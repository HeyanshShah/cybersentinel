"""Labeled synthetic login logs for testing and measuring detection accuracy.

Real attack logs almost never come with an answer key, so to measure precision and
recall we simulate an organization: employees with home cities and work-hour habits
(including realistic noise: typos, late nights, legitimate business trips), plus
randomly placed attacks of 7 types. Every event carries `label` (attack type or
"benign") and `attack_id`, so detections can be scored against ground truth.
"""
from datetime import datetime, timedelta
import random

import pandas as pd

from .geo import CITIES

US_CITIES = [c for c, v in CITIES.items() if v[2] == "US"]
FOREIGN = [c for c, v in CITIES.items() if v[2] not in ("US", "CA")]
ATTACK_TYPES = ["brute_force", "password_spray", "credential_stuffing", "account_takeover",
                "impossible_travel", "low_and_slow", "after_hours_abuse"]
COLUMNS = ["timestamp", "user", "ip", "event", "country", "city", "lat", "lon",
           "label", "attack_id"]


class _Sim:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.rows = []
        self._ip_n = 0

    def new_ip(self, private=False):
        self._ip_n += 1
        n = self._ip_n
        if private:
            return f"10.{n // 65536 % 256}.{n // 256 % 256}.{n % 256}"
        return f"{self.rng.randint(23, 223)}.{n // 256 % 256}.{n % 256}.{self.rng.randint(1, 254)}"

    def add(self, t, user, ip, ok, city, label="benign", attack_id=-1):
        lat, lon, cc = CITIES[city]
        self.rows.append((t, user, ip, "login_success" if ok else "login_failed",
                          cc, city, lat, lon, label, attack_id))


def generate(days: int = 14, users: int = 40, attacks_per_type: int = 3, seed: int = 42,
             start: datetime | None = None) -> pd.DataFrame:
    sim = _Sim(seed)
    rng = sim.rng
    start = start or datetime(2026, 11, 2)
    names = [f"user{i:02d}" for i in range(users)]
    home = {u: rng.choice(US_CITIES) for u in names}
    home_ip = {u: sim.new_ip(private=True) for u in names}
    shift = {u: rng.choice([0, 0, 0, 1, 2, -1]) for u in names}  # some start early/late

    # ---------- benign activity ----------
    for d in range(days):
        day = start + timedelta(days=d)
        weekend = day.weekday() >= 5
        # a legitimate business trip: the traveler doesn't log in from home that day
        traveler = rng.choice(names) if rng.random() < 0.5 else None
        if traveler:
            dest = rng.choice([c for c in US_CITIES + ["London", "Toronto"] if c != home[traveler]])
            sim.add(day + timedelta(hours=rng.uniform(17, 22)), traveler, sim.new_ip(), True, dest)
        for u in names:
            if u == traveler or (weekend and rng.random() < 0.85):
                continue
            for _ in range(rng.randint(1, 4)):
                hour = rng.gauss(13 + shift[u], 2.6)
                if rng.random() < 0.03:          # occasional genuine late-night login
                    hour = rng.uniform(0, 24)
                t = day + timedelta(hours=min(max(hour, 0), 23.99))
                if rng.random() < 0.12:          # typo'd password, then success
                    for k in range(rng.choice([1, 1, 2, 3])):
                        sim.add(t - timedelta(seconds=15 * (k + 1)), u, home_ip[u], False, home[u])
                sim.add(t, u, home_ip[u], True, home[u])

    # ---------- attacks ----------
    aid = 0
    span = days * 24 - 30

    def when():
        return start + timedelta(hours=rng.uniform(2, span))

    for attack in ATTACK_TYPES:
        for _ in range(attacks_per_type):
            t0 = when()
            city = rng.choice(FOREIGN)
            if attack == "brute_force":
                ip, target = sim.new_ip(), rng.choice(names + ["root", "admin"])
                for i in range(rng.randint(30, 200)):
                    sim.add(t0 + timedelta(seconds=rng.uniform(1, 4) * i), target, ip, False, city, attack, aid)
            elif attack == "password_spray":
                ip = sim.new_ip()
                for i, u in enumerate(rng.sample(names, k=min(len(names), rng.randint(12, 30)))):
                    sim.add(t0 + timedelta(seconds=30 * i), u, ip, False, city, attack, aid)
            elif attack == "credential_stuffing":
                # botnet: many IPs, each tries only 1-2 leaked username/password pairs
                pool = names + [f"leak{n}" for n in range(60)]
                for _ in range(rng.randint(25, 45)):
                    ip, c = sim.new_ip(), rng.choice(FOREIGN)
                    for _ in range(rng.randint(1, 2)):
                        sim.add(t0 + timedelta(minutes=rng.uniform(0, 50)), rng.choice(pool), ip, False, c, attack, aid)
            elif attack == "account_takeover":
                ip, victim = sim.new_ip(), rng.choice(names)
                n = rng.randint(6, 25)
                for i in range(n):
                    sim.add(t0 + timedelta(seconds=8 * i), victim, ip, False, city, attack, aid)
                sim.add(t0 + timedelta(seconds=8 * n + 5), victim, ip, True, city, attack, aid)
            elif attack == "impossible_travel":
                # stolen session/password used abroad shortly after the real user logged in
                victim = rng.choice(names)
                sim.add(t0, victim, home_ip[victim], True, home[victim])
                sim.add(t0 + timedelta(minutes=rng.uniform(5, 90)), victim, sim.new_ip(), True, city, attack, aid)
            elif attack == "low_and_slow":
                ip, target = sim.new_ip(), rng.choice(["root", "admin", "oracle"] + names)
                t = t0
                for _ in range(rng.randint(40, 70)):
                    t += timedelta(minutes=rng.uniform(6, 15))
                    sim.add(t, target, ip, False, city, attack, aid)
            elif attack == "after_hours_abuse":
                # an insider with valid credentials logging in at 3am from the usual place
                # placed after a 5-day warm-up: behavioral baselines need history to learn from
                victim = rng.choice(names)
                t0 = start + timedelta(days=rng.uniform(5, days - 1))
                t = t0.replace(hour=rng.choice([2, 3, 4]), minute=rng.randint(0, 59))
                for k in range(rng.randint(2, 4)):
                    sim.add(t + timedelta(minutes=12 * k), victim, home_ip[victim], True, home[victim], attack, aid)
            aid += 1

    df = pd.DataFrame(sim.rows, columns=COLUMNS)
    return df.sort_values("timestamp").reset_index(drop=True)


if __name__ == "__main__":
    out = "sample_data/login_logs.csv"
    generate().to_csv(out, index=False)
    print(f"wrote {out}")
