from datetime import datetime, timedelta

import pandas as pd

from sentinel import rules
from sentinel.alerts import Alert, dedupe, to_frame
from sentinel.baseline import unusual_hour
from sentinel.correlate import correlate
from sentinel.detect import detect
from sentinel.evaluate import evaluate, ground_truth, matches
from sentinel.generate import generate
from sentinel.geo import haversine_km
from sentinel.ml import build_features, ml_anomalies
from sentinel.parser import parse_auth_log, parse_cowrie, parse_windows_csv, _finish
from sentinel.stats import zscores
from sentinel.stream import LiveMonitor

T = datetime(2026, 11, 20, 10, 0)


def make(rows):
    cols = ["timestamp", "user", "ip", "event", "country", "city", "lat", "lon"]
    return _finish(pd.DataFrame(rows, columns=cols[:len(rows[0])]))


# ---------- rules ----------
def test_brute_force_detected():
    df = make([(T + timedelta(seconds=i), "root", "1.2.3.4", "login_failed") for i in range(12)])
    a = rules.brute_force(df)
    assert [x.rule for x in a] == ["brute_force"]
    assert a[0].technique.startswith("T1110.001")


def test_slow_failures_not_brute_force_but_low_and_slow():
    df = make([(T + timedelta(minutes=10 * i), "root", "6.6.6.6", "login_failed") for i in range(40)])
    assert rules.brute_force(df) == []
    assert [a.rule for a in rules.low_and_slow(df)] == ["low_and_slow"]


def test_persistent_attacker_over_days():
    df = make([(T + timedelta(hours=7 * i), "root", "6.6.6.7", "login_failed") for i in range(25)])
    assert "persistent" in rules.low_and_slow(df)[0].detail


def test_user_with_typos_is_not_low_and_slow():
    rows = []
    for d in range(10):
        rows += [(T + timedelta(days=d, minutes=k), "bob", "10.0.0.5", "login_failed") for k in range(3)]
        rows.append((T + timedelta(days=d, minutes=5), "bob", "10.0.0.5", "login_success"))
    assert rules.low_and_slow(make(rows)) == []


def test_success_after_failures_is_critical():
    rows = [(T + timedelta(seconds=i), "eve", "9.9.9.9", "login_failed") for i in range(6)]
    rows.append((T + timedelta(seconds=10), "eve", "9.9.9.9", "login_success"))
    a = rules.success_after_failures(make(rows))
    assert len(a) == 1 and a[0].severity == "critical" and "6 failures" in a[0].detail


def test_streak_resets_between_ip_user_pairs():
    rows = [(T + timedelta(seconds=i), "a", "1.1.1.1", "login_failed") for i in range(6)]
    rows.append((T + timedelta(seconds=10), "b", "1.1.1.1", "login_success"))  # different user
    assert rules.success_after_failures(make(rows)) == []


def test_password_spray():
    df = make([(T + timedelta(seconds=i), f"user{i}", "5.5.5.5", "login_failed") for i in range(9)])
    assert rules.password_spray(df)[0].technique.startswith("T1110.003")


def test_credential_stuffing_catches_distributed_attack():
    rows = [(T + timedelta(seconds=i), f"u{i % 12}", f"77.0.0.{i}", "login_failed") for i in range(20)]
    a = rules.credential_stuffing(make(rows))
    assert len(a) == 1 and len(a[0].related_ips) == 20
    assert rules.brute_force(make(rows)) == []  # per-IP rules can't see it


def test_impossible_travel_vs_plausible_trip():
    sj, tokyo, la = (37.34, -121.89), (35.68, 139.69), (34.05, -118.24)
    fast = make([(T, "ann", "1.1.1.1", "login_success", "US", "San Jose", *sj),
                 (T + timedelta(minutes=30), "ann", "2.2.2.2", "login_success", "JP", "Tokyo", *tokyo)])
    assert rules.impossible_travel(fast)[0].severity == "high"
    slow = make([(T, "ann", "1.1.1.1", "login_success", "US", "San Jose", *sj),
                 (T + timedelta(hours=5), "ann", "2.2.2.2", "login_success", "US", "Los Angeles", *la)])
    assert rules.impossible_travel(slow) == []


def test_haversine():
    assert abs(haversine_km(37.34, -121.89, 40.71, -74.01) - 4100) < 60  # San Jose -> NYC


# ---------- baseline, ML, stats ----------
def test_unusual_hour_flags_3am_for_9_to_5_user():
    rows = [(T + timedelta(days=d, hours=h - 10), "kim", "10.0.0.9", "login_success")
            for d in range(15) for h in (9, 13, 16)]
    rows.append((T + timedelta(days=16, hours=-7), "kim", "10.0.0.9", "login_success"))  # 3am
    a = unusual_hour(make(rows))
    assert len(a) == 1 and a[0].time.hour == 3


def test_ml_features_and_detection():
    df = generate(seed=3)
    f = build_features(df)
    assert {"fail_ratio", "distinct_users"} <= set(f.columns)
    a = ml_anomalies(df)
    assert a and all(x.detector == "ml" for x in a)


def test_zscore_math():
    z = zscores(pd.Series([1, 1, 1, 1, 10]))
    assert z.iloc[-1] > 1.9 and abs(z.iloc[0] + 0.5) < 0.01


# ---------- correlation ----------
def test_single_weak_signal_is_suppressed_but_corroborated_one_escalates():
    weak = Alert("unusual_hour", "low", "1.1.1.1", "kim", pd.Timestamp(T), "late")
    shown, hidden = correlate([weak])
    assert shown == [] and hidden == [weak]
    other = Alert("new_country", "medium", "2.2.2.2", "kim", pd.Timestamp(T + timedelta(hours=2)), "BR")
    shown, hidden = correlate([weak, other])
    assert {a.rule for a in shown} == {"unusual_hour", "new_country"} and not hidden


# ---------- parsers ----------
def test_parse_auth_log_handles_repeats_invalid_users_and_year_rollover():
    lines = [
        "Dec 31 23:59:01 h sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 1 ssh2",
        "Dec 31 23:59:05 h sshd[1]: message repeated 5 times: [ Failed password for root from 1.2.3.4 port 1 ssh2]",
        "Jan  1 00:00:02 h sshd[2]: Accepted publickey for deploy from 10.0.0.2 port 2 ssh2",
        "Jan  1 00:00:03 h systemd[1]: Started session.",
    ]
    df = parse_auth_log(lines, year=2025)
    assert len(df) == 7
    assert df.timestamp.iloc[-1].year == 2026
    assert "admin" in set(df.user)


def test_parse_windows_and_cowrie():
    win = pd.DataFrame({"TimeCreated": ["2026-11-20 10:00:00", "2026-11-20 10:00:05", "2026-11-20 10:01:00"],
                        "Id": [4625, 4624, 4688], "TargetUserName": ["bob", "bob", "x"],
                        "IpAddress": ["1.1.1.1", "1.1.1.1", None]})
    w = parse_windows_csv(win)
    assert list(w.event) == ["login_failed", "login_success"]
    cow = ['{"eventid":"cowrie.login.failed","username":"root","src_ip":"8.8.8.8","timestamp":"2026-11-20T10:00:00Z"}',
           '{"eventid":"cowrie.session.connect","src_ip":"8.8.8.8","timestamp":"2026-11-20T10:00:00Z"}']
    assert len(parse_cowrie(cow)) == 1


# ---------- live monitor ----------
def test_live_monitor_alerts_once_when_attack_appears():
    mon = LiveMonitor()
    line = "Nov 20 03:00:{:02d} h sshd[9]: Failed password for root from 6.6.6.6 port 22 ssh2"
    assert mon.feed([line.format(i) for i in range(5)]) == []           # not yet
    new = mon.feed([line.format(i) for i in range(5, 12)])               # crosses threshold
    assert any(a.rule == "brute_force" for a in new)
    assert not any(a.rule == "brute_force" for a in mon.feed([line.format(12)]))  # no repeat


# ---------- end to end + accuracy ----------
def test_detect_finds_every_attack_type_in_demo_data():
    df = generate(seed=7)
    alerts = detect(df)
    found = {k.kind for k in ground_truth(df) if any(matches(a, k) for a in alerts)}
    assert {"brute_force", "password_spray", "credential_stuffing", "account_takeover",
            "impossible_travel", "low_and_slow"} <= found


def test_accuracy_floor():
    """Guards against regressions: combined detection must stay accurate."""
    res, _ = evaluate(seeds=(1, 2))
    combined = res.loc["combined + risk correlation"]
    assert combined.precision >= 0.85 and combined.recall >= 0.90


def test_dedupe_and_sorting():
    a = Alert("x", "low", "1.1.1.1", "u", pd.Timestamp(T), "d")
    b = Alert("y", "critical", "1.1.1.1", "u", pd.Timestamp(T), "d")
    assert len(dedupe([a, a])) == 1
    assert to_frame([a, b]).severity.tolist() == ["critical", "low"]


def test_matplotlib_report(tmp_path):
    from sentinel.report import save_report
    df = generate(seed=1)
    save_report(df, to_frame(detect(df)), str(tmp_path / "r.png"))
    assert (tmp_path / "r.png").stat().st_size > 10_000
