"""Command line interface.

  python -m sentinel analyze <logfile> [--json out.json] [--plot out.png] [--slack]
  python -m sentinel watch <logfile> [--from-start] [--ml] [--slack]
  python -m sentinel evaluate [--seeds 5]
  python -m sentinel generate [--out sample_data/login_logs.csv]

`python -m sentinel <logfile>` is shorthand for `analyze`.
"""
import argparse
import sys
import time

from .alerts import send_slack, to_frame
from .detect import detect
from .parser import load

COMMANDS = {"analyze", "watch", "evaluate", "generate"}


def cmd_analyze(args) -> int:
    t0 = time.time()
    df = load(args.logfile)
    alerts, obs = detect(df, with_observations=True)
    table = to_frame(alerts)
    print(f"Analyzed {len(df):,} events from {df.ip.nunique():,} IPs in {time.time() - t0:.1f}s "
          f"-> {len(alerts)} alerts ({len(obs)} low-risk observations suppressed)\n")
    if not table.empty:
        show = table.drop(columns=["score", "tactic"]).head(args.top)
        print(show.to_string(index=False, max_colwidth=60))
        if len(table) > args.top:
            print(f"... {len(table) - args.top} more (use --json to save all)")
        print("\nBy technique:\n" + table.technique.value_counts().to_string())
    if args.json:
        table.to_json(args.json, orient="records", date_format="iso", indent=2)
        print(f"\nSaved {args.json}")
    if args.plot:
        from .report import save_report
        print(f"Saved chart {save_report(df, table, args.plot)}")
    if args.slack:
        print(f"Sent {send_slack(alerts)} alerts to Slack")
    return 1 if (table.severity == "critical").any() else 0


def cmd_watch(args) -> int:
    from .stream import watch
    try:
        watch(args.logfile, slack=args.slack, from_start=args.from_start, use_ml=args.ml)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def cmd_evaluate(args) -> int:
    from .evaluate import evaluate, to_markdown
    res, by_type = evaluate(seeds=tuple(range(1, args.seeds + 1)))
    print(to_markdown(res, by_type))
    return 0


def cmd_generate(args) -> int:
    from .generate import generate
    generate(seed=args.seed).to_csv(args.out, index=False)
    print(f"wrote {args.out}")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in COMMANDS and not argv[0].startswith("-"):
        argv.insert(0, "analyze")
    p = argparse.ArgumentParser(prog="sentinel", description="Detect threats in login logs.")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyze a log file")
    a.add_argument("logfile")
    a.add_argument("--json")
    a.add_argument("--plot", help="save a Matplotlib PNG report")
    a.add_argument("--slack", action="store_true")
    a.add_argument("--top", type=int, default=25, help="rows to print")
    a.set_defaults(fn=cmd_analyze)

    w = sub.add_parser("watch", help="monitor a log file live")
    w.add_argument("logfile")
    w.add_argument("--from-start", action="store_true")
    w.add_argument("--ml", action="store_true", help="also run the Isolation Forest live")
    w.add_argument("--slack", action="store_true")
    w.set_defaults(fn=cmd_watch)

    e = sub.add_parser("evaluate", help="measure precision/recall on labeled data")
    e.add_argument("--seeds", type=int, default=5)
    e.set_defaults(fn=cmd_evaluate)

    g = sub.add_parser("generate", help="write labeled synthetic logs")
    g.add_argument("--out", default="sample_data/login_logs.csv")
    g.add_argument("--seed", type=int, default=42)
    g.set_defaults(fn=cmd_generate)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
