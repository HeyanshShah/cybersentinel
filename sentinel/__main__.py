"""Command line:  python -m sentinel <logfile> [--json alerts.json] [--slack]"""
import argparse
import sys

from .alerts import send_slack, to_frame
from .detect import detect
from .parser import load


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sentinel", description="Detect threats in login logs.")
    p.add_argument("logfile", help="CSV (timestamp,user,ip,event,country) or Linux auth.log")
    p.add_argument("--json", help="also save alerts to this JSON file")
    p.add_argument("--plot", help="save a Matplotlib PNG report to this path")
    p.add_argument("--slack", action="store_true", help="post high/critical alerts to Slack")
    args = p.parse_args(argv)

    df = load(args.logfile)
    alerts = detect(df)
    table = to_frame(alerts)
    print(f"Analyzed {len(df):,} events from {df.ip.nunique()} IPs -> {len(alerts)} alerts\n")
    if not table.empty:
        print(table.drop(columns="score").to_string(index=False))
    if args.json:
        table.to_json(args.json, orient="records", date_format="iso", indent=2)
        print(f"\nSaved {args.json}")
    if args.plot:
        from .report import save_report
        print(f"Saved chart {save_report(df, table, args.plot)}")
    if args.slack:
        print(f"Sent {send_slack(alerts)} alerts to Slack")
    # exit code 1 when something critical was found, so scripts/cron can react
    return 1 if (table.severity == "critical").any() else 0


if __name__ == "__main__":
    sys.exit(main())
