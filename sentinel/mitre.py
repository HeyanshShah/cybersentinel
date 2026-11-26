"""Map each detection to MITRE ATT&CK, the industry-standard catalog of attacker
techniques (attack.mitre.org). Security teams use these IDs to share and triage."""

TECHNIQUES = {
    "brute_force":            ("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
    "low_and_slow":           ("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
    "password_spray":         ("T1110.003", "Brute Force: Password Spraying", "Credential Access"),
    "credential_stuffing":    ("T1110.004", "Brute Force: Credential Stuffing", "Credential Access"),
    "success_after_failures": ("T1078", "Valid Accounts", "Initial Access"),
    "impossible_travel":      ("T1078", "Valid Accounts", "Initial Access"),
    "new_country":            ("T1078", "Valid Accounts", "Initial Access"),
    "unusual_hour":           ("T1078", "Valid Accounts", "Defense Evasion"),
    "zscore_spike":           ("T1110", "Brute Force (statistical anomaly)", "Credential Access"),
    "ml_anomaly":             ("—", "Behavioral anomaly (needs triage)", "—"),
}


def lookup(rule: str) -> tuple[str, str, str]:
    return TECHNIQUES.get(rule, ("—", "Unmapped", "—"))
