"""Build docs/REAL_DATA_RESULTS.md from the real Loghub SSH dataset."""
import sys
import time

import pandas as pd

sys.path.insert(0, ".")
from sentinel.alerts import to_frame  # noqa: E402
from sentinel.detect import detect  # noqa: E402
from sentinel.parser import load  # noqa: E402
from sentinel.report import save_report  # noqa: E402

path = sys.argv[1] if len(sys.argv) > 1 else "data/SSH.log"
t0 = time.time()
df = load(path)
alerts, obs = detect(df, with_observations=True)
secs = time.time() - t0
t = to_frame(alerts)

fails = df[df.event == "login_failed"]
ok = df[df.event == "login_success"]
attack_ips = set(t.ip) | {ip for a in alerts for ip in a.related_ips}
heavy = fails.groupby("ip").size()
heavy = set(heavy[heavy >= 20].index)
coverage = len(heavy & attack_ips) / len(heavy)
both = sorted(set(ok.ip) & set(fails.ip))
breached = [ip for ip in both if ip in attack_ips]

lines = [
    "# Real-world results: Loghub OpenSSH dataset",
    "",
    f"CyberSentinel was run on **{sum(1 for _ in open(path, errors='ignore')):,} real log lines** "
    "from an internet-facing SSH server (Loghub `SSH.log`, ~1 month). No labels exist for "
    "real traffic, so these are observations, not precision/recall.",
    "",
    "| Metric | Value |", "|---|---|",
    f"| Login events parsed | {len(df):,} |",
    f"| Failed logins | {len(fails):,} ({len(fails) / len(df):.1%}) |",
    f"| Successful logins | {len(ok):,} |",
    f"| Distinct source IPs | {df.ip.nunique():,} |",
    f"| Distinct usernames tried | {df.user.nunique():,} |",
    f"| Processing time | {secs:.1f} s ({len(df) / secs:,.0f} events/s) |",
    f"| Alerts raised | {len(alerts):,} (+{len(obs)} low-risk observations suppressed) |",
    f"| Attacker IPs flagged | {len(attack_ips):,} |",
    f"| Coverage of heavy attackers (≥20 failures) | {coverage:.1%} ({len(heavy & attack_ips)}/{len(heavy)}) |",
    f"| IPs with both failures and a success, flagged | {len(breached)} |",
    "",
    "## Alerts by MITRE ATT&CK technique", "", "| Technique | Alerts |", "|---|---|",
    *[f"| {k} | {v} |" for k, v in t.technique.value_counts().items()],
    "", "## Top 10 attacking IPs by failed logins", "", "| IP | Failed logins | Usernames tried |", "|---|---|---|",
    *[f"| {ip} | {n:,} | {fails[fails.ip == ip].user.nunique():,} |"
      for ip, n in fails.groupby("ip").size().nlargest(10).items()],
    "", "## Most-guessed usernames", "", "| Username | Attempts |", "|---|---|",
    *[f"| `{u}` | {n:,} |" for u, n in fails.user.value_counts().head(10).items()],
    "", "![report](real_report.png)", "",
    "Syslog omits the year, so timestamps are shown with a placeholder year.",
]
open("docs/REAL_DATA_RESULTS.md", "w").write("\n".join(lines) + "\n")
save_report(df, t, "docs/real_report.png")
print("\n".join(lines[:20]))
