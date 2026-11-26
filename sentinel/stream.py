"""Live monitoring: follow a log file like `tail -f` and alert within seconds.

New lines are parsed as they're written, added to a sliding 24-hour window of
events, and the detectors re-run on that window. Each alert is printed only once
(keyed by rule/IP/user/hour), so a long attack doesn't spam the console.
"""
import os
import time

import pandas as pd

from .alerts import alert_key, send_slack
from .detect import detect
from .parser import parse_lines

WINDOW = pd.Timedelta("24h")


class LiveMonitor:
    def __init__(self, use=("rules", "statistical", "baseline")):
        self.events = pd.DataFrame()
        self.seen = set()
        self.use = use  # ML retrains on every batch, so it's opt-in for live mode

    def feed(self, lines) -> list:
        """Add raw log lines; return only alerts we haven't reported before."""
        new = parse_lines(lines)
        if new.empty:
            return []
        self.events = pd.concat([self.events, new], ignore_index=True) if len(self.events) else new
        newest = self.events.timestamp.max()
        self.events = self.events[self.events.timestamp >= newest - WINDOW].reset_index(drop=True)
        fresh = []
        for a in detect(self.events, use=self.use):
            k = alert_key(a)
            if k not in self.seen:
                self.seen.add(k)
                fresh.append(a)
        return fresh


def follow(path, poll: float = 1.0, from_start: bool = False):
    """Yield batches of new lines appended to `path` (handles log rotation)."""
    f = open(path, encoding="utf-8", errors="ignore")
    if not from_start:
        f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    while True:
        lines = f.readlines()
        if lines:
            yield lines
        else:
            time.sleep(poll)
            try:
                if os.stat(path).st_ino != inode:  # file was rotated
                    f.close()
                    f = open(path, encoding="utf-8", errors="ignore")
                    inode = os.fstat(f.fileno()).st_ino
            except FileNotFoundError:
                pass


def watch(path, slack: bool = False, from_start: bool = False, use_ml: bool = False):
    mon = LiveMonitor(use=("rules", "statistical", "baseline", "ml") if use_ml
                      else ("rules", "statistical", "baseline"))
    print(f"Watching {path} (Ctrl+C to stop)...", flush=True)
    for batch in follow(path, from_start=from_start):
        for a in mon.feed(batch):
            print(f"[{a.severity.upper():8}] {a.time} {a.rule:22} {a.ip:16} {a.user:12} "
                  f"{a.detail}  <{a.technique}>", flush=True)
            if slack:
                send_slack([a])
