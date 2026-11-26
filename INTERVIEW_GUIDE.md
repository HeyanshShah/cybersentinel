# CyberSentinel: how to explain it (plain English)

## 30-second pitch
"CyberSentinel detects attacks in login logs. It combines four approaches: rules for known
attacks like brute force and password spraying, z-score statistics, a per-user baseline that
learns when each person normally logs in, and an Isolation Forest machine-learning model.
To avoid drowning analysts in false alarms, it uses risk-based correlation: weak signals only
become alerts when they stack up on the same account. Every alert maps to MITRE ATT&CK. I
measured it on labeled data, 94.5% precision and 96% recall, and ran it on 655,000 lines of
real SSH logs from an internet-facing server, where it flagged 99% of the heavy attackers."

## The numbers to remember
- **94.5% precision, 96.2% recall, F1 0.95** (combined, 105 labeled attacks)
- Correlation raised precision **66.9% → 94.5%**
- Real data: **344,624 login attempts, 1,042 IPs, ~4 seconds, 99.1% of heavy attackers flagged**
- **21 automated tests**, run on GitHub Actions on every push

## Key ideas, simply
- **Precision** = of my alerts, how many were real? **Recall** = of the real attacks, how many did I catch?
  Security cares about both: low precision means analysts ignore alerts ("alert fatigue"); low recall means you miss breaches.
- **Why 4 detector types?** Rules are precise but only catch what you predicted. Stats catch volume
  spikes. Baselines catch "normal for others, weird for you." ML catches combinations no single rule describes.
- **Isolation Forest:** builds random trees that split the data. Weird points get isolated in very
  few splits. It's unsupervised: no labels needed, which matters because real logs have no answer key.
- **Per-user baseline:** each user gets a 24-hour histogram of past logins, smoothed so neighboring hours
  count a bit. It only looks at past data (no peeking at the future). Suspicious logins are learned at
  30% weight, so an attacker can't quickly "teach" it that 3am is normal.
- **Risk-based correlation:** low signals = 15 points, medium = 30. A weak signal is escalated only if a
  *different* detector also flagged the same account within 24h. That's the same idea as Splunk's Risk-Based Alerting.
- **Impossible travel:** haversine formula = distance on a sphere. If the distance divided by the time
  between logins is faster than 900 km/h (a jet), one login isn't the real person.
- **Credential stuffing:** a botnet with many IPs, each trying 1–3 leaked passwords. Per-IP rules never
  fire, so the rule looks at the crowd: 15+ quiet IPs hitting 10+ accounts in one hour.
- **MITRE ATT&CK:** a public catalog of attacker techniques. T1110 = Brute Force, T1078 = Valid Accounts.
  SOC teams talk in these IDs.

## How I measured it (they WILL ask)
Real logs don't say which events are attacks, so I wrote a simulator: 40 employees with home cities and
work-hour habits, plus realistic noise (typos, late nights, legitimate business trips), plus 7 attack types
at random times. Every event has a label. I ran each detector on 5 different random companies and averaged
precision, recall, and F1. A test in the suite fails the build if accuracy drops below 85%/90%.

## Real data story
I ran it on Loghub's OpenSSH dataset: 655k log lines from a real server. 99.9% of logins failed, so it's
under constant attack. The top attacker made 28,000+ attempts. I found the parser was missing about 180k
events because syslog collapses duplicates into "message repeated 5 times", so I fixed the parser. My
first version only flagged 80% of heavy attackers: the misses were *patient* attackers doing about 20
attempts a day for weeks. I added a "persistent attacker" rule and a 24-hour spray window, and coverage went to 99.1%.

## Problems I solved (pick one for "tell me about a challenge")
1. The behavioral baseline was noisy (35% precision). Adding risk correlation took combined precision from 67% to 94.5%.
2. The insider detector kept missing repeat 3am logins because the baseline was *learning* from the
   attacker. Learning from suspicious events at reduced weight fixed it.
3. Syslog "message repeated" lines were hiding about half the real attack volume.

## Limits (be honest; interviewers love this)
- Insiders using valid credentials from their normal location: only 73% caught.
- New users need about 10 logins before the baseline can judge them (cold start).
- The simulator is my model of attacks, so real-world precision would need labeled real incidents to confirm.

## Commands
`python -m sentinel analyze <log>` · `python -m sentinel watch <log>` · `python -m sentinel evaluate` · `streamlit run dashboard.py` · `pytest`
