from datetime import datetime, timedelta

import pandas as pd

from sentinel import rules
from sentinel.alerts import Alert, dedupe, to_frame
from sentinel.detect import detect
from sentinel.generate import generate
from sentinel.parser import parse_auth_log
from sentinel.stats import zscores


def make(rows):
    return pd.DataFrame(rows, columns=["timestamp", "user", "ip", "event", "country"])


T = datetime(2026, 11, 20, 10, 0)


def test_brute_force_detected():
    df = make([(T + timedelta(seconds=i), "root", "1.2.3.4", "login_failed", "RU")
               for i in range(12)])
    assert [a.rule for a in rules.brute_force(df)] == ["brute_force"]


def test_slow_failures_not_brute_force():
    # 12 failures spread over 12 hours is a forgetful user, not an attack
    df = make([(T + timedelta(hours=i), "bob", "1.2.3.4", "login_failed", "US")
               for i in range(12)])
    assert rules.brute_force(df) == []


def test_success_after_failures_is_critical():
    rows = [(T + timedelta(seconds=i), "eve", "9.9.9.9", "login_failed", "BR") for i in range(6)]
    rows.append((T + timedelta(seconds=10), "eve", "9.9.9.9", "login_success", "BR"))
    alerts = rules.success_after_failures(make(rows))
    assert alerts and alerts[0].severity == "critical"


def test_password_spray():
    df = make([(T, f"user{i}", "5.5.5.5", "login_failed", "CN") for i in range(9)])
    assert rules.password_spray(df)[0].detail == "tried 9 different usernames"


def test_new_country():
    df = make([(T, "ann", "10.0.0.1", "login_success", "US"),
               (T + timedelta(days=1), "ann", "8.8.8.8", "login_success", "FR")])
    assert rules.new_country(df)[0].user == "ann"


def test_zscore_math():
    z = zscores(pd.Series([1, 1, 1, 1, 10]))
    assert z.iloc[-1] > 1.9 and abs(z.iloc[0] + 0.5) < 0.01


def test_parse_auth_log():
    lines = open("sample_data/auth.log").read().splitlines()
    df = parse_auth_log(lines)
    assert len(df) == 12  # systemd line ignored
    assert (df.event == "login_failed").sum() == 11
    assert "admin" in set(df.user)  # "invalid user admin" handled


def test_all_injected_attacks_found_and_no_false_positives():
    alerts = detect(generate())
    found = {a.rule for a in alerts}
    assert {"brute_force", "password_spray", "success_after_failures", "new_country"} <= found
    attacker_ips = {"203.0.113.45", "198.51.100.77", "192.0.2.10", "185.220.101.4"}
    assert {a.ip for a in alerts} <= attacker_ips  # nothing flagged on normal users


def test_dedupe_and_sorting():
    a = Alert("x", "low", "1.1.1.1", "u", pd.Timestamp(T), "d")
    b = Alert("y", "critical", "1.1.1.1", "u", pd.Timestamp(T), "d")
    assert len(dedupe([a, a])) == 1
    assert to_frame([a, b]).severity.tolist() == ["critical", "low"]


def test_matplotlib_report(tmp_path):
    from sentinel.report import save_report
    df = generate()
    out = save_report(df, to_frame(detect(df)), str(tmp_path / "r.png"))
    assert (tmp_path / "r.png").stat().st_size > 10_000
