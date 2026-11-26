# CyberSentinel: how to explain it (plain English)

## The 30-second pitch
"CyberSentinel reads login logs and flags suspicious activity. It uses two approaches:
rules for attacks we already know about, like brute force or password spraying, and
statistics, specifically z-scores, to catch anything that's way outside normal
behavior even if no rule covers it. Results show up in a dashboard with charts and a
ranked alert table, and serious alerts can be sent to Slack. It's Python with pandas
for the data and Plotly/Streamlit for the dashboard."

## The attacks, in normal words
- **Brute force:** someone guesses one account's password over and over, fast.
- **Password spraying:** someone tries one common password (like "Winter2026!") on
  MANY accounts, so no single account gets locked out.
- **Success after failures:** lots of wrong passwords, then a correct one. The guessing
  may have worked. This is the most serious, so it's "critical".
- **New country:** your account always logs in from the US, then suddenly the
  Netherlands. Maybe stolen credentials.
- **Off-hours:** a login at 3am. Low severity on its own, but adds context.

## How it works, step by step
1. **Parse** (parser.py): logs become a pandas table, one row per login attempt:
   time, user, IP, success/fail, country. For real Linux server logs (auth.log) I use a
   regex, a text pattern, to pull the user and IP out of lines like
   "Failed password for root from 203.0.113.5".
2. **Rules** (rules.py): for brute force I group failures by IP and use a rolling
   5-minute window to count them. 10+ in 5 minutes = alert.
3. **Statistics** (stats.py): I count events per IP per hour. Then the z-score:
   (this count − average count) ÷ standard deviation. It says "how unusual is this?"
   z of 3+ happens by random chance well under 1% of the time, so that's my threshold.
4. **Alerts** (alerts.py): each finding gets a severity, duplicates get removed (one
   alert per rule/IP/user/hour, so nobody gets spammed), and they're sorted
   critical → low.
5. **Charts**: Plotly for the interactive dashboard, Matplotlib (report.py) for a static
   PNG report you can attach to a ticket or email (`--plot report.png`).
6. **Dashboard** (dashboard.py): metrics, color-coded alert table, failed logins per hour
   with anomalies marked, the z-score over time with the threshold line, and top IPs.

## Why rules AND statistics?
Rules are precise and easy to explain, but they only catch what you predicted.
Statistics catch the unexpected, but can't tell you *what kind* of attack it is. Real
security tools (SIEMs like Splunk) use both. In my demo the brute-force attack was
caught by both: the rule said "brute force" and the z-score said "40 events when
normal is 1.6".

## How I tested it
I wrote a generator that creates a week of fake but realistic logs: 16 normal users
logging in during work hours, occasionally typing their password wrong, plus 4 hidden
attacks. The end-to-end test checks that all 4 attacks are found AND that no normal
user gets flagged (no false positives). Also unit tests for each rule, the z-score
math, and the log parser. 9 tests, all passing.

## A problem I hit
"At first a user who mistyped their password 12 times across a whole day could look
like brute force. Using a rolling 5-minute time window instead of a total count fixed
it. I wrote a test for exactly that case."

## What I'd improve
- Learn a separate "normal" for each user instead of one global normal
- Real IP geolocation (MaxMind GeoIP) instead of a country column
- Stream logs in real time instead of batch files
- Try an ML model like Isolation Forest and compare with z-scores

## Likely questions
- **What's a z-score?** How many standard deviations a value is from the average.
- **What's a false positive?** An alert on something harmless. Too many and people
  ignore alerts ("alert fatigue"), which is why I de-duplicate and rank by severity.
- **What's a SIEM?** Security Information and Event Management: tools like Splunk or
  Microsoft Sentinel that collect logs and alert on threats. This is a mini version.
- **Why exit code 1?** So an automated script or scheduled job can react when
  something critical is found.

## Commands to remember
- `python -m sentinel sample_data/login_logs.csv`  command-line report
- `streamlit run dashboard.py`  dashboard
- `pytest`  tests
