"""Canonical attack labels shared by CIC-IDS-2017 and CSE-CIC-IDS-2018 (CNS 2022 versions).

The improved datasets (Liu et al., CNS 2022) mark flows that belong to an attack
but carry no malicious effect with the suffix " - Attempted". The dataset authors
state they must not be used as a separate class; we keep them as traffic events
(they exist on the wire and feed the evidence counters) but exclude them from
training labels and from detection metrics.
"""

from __future__ import annotations

import re

BENIGN = "benign"
ATTEMPTED_SUFFIX = re.compile(r"\s*-\s*attempted\s*$", re.IGNORECASE)

# (regex on the lower-cased base label, canonical attack, family). First match wins.
_RULES: list[tuple[str, str, str]] = [
    (r"^benign$", BENIGN, BENIGN),
    (r"hulk", "dos_hulk", "dos"),
    (r"goldeneye", "dos_goldeneye", "dos"),
    (r"slowloris", "dos_slowloris", "dos"),
    (r"slowhttp", "dos_slowhttptest", "dos"),
    (r"heartbleed", "heartbleed", "heartbleed"),
    (r"loic.*udp", "ddos_loic_udp", "ddos"),
    (r"hoic", "ddos_hoic", "ddos"),
    (r"loic|^ddos$", "ddos_loic_http", "ddos"),
    (r"ftp", "bf_ftp", "bruteforce"),
    (r"ssh", "bf_ssh", "bruteforce"),
    (r"web attack.*(brute|force)", "web_bruteforce", "web"),
    (r"xss", "web_xss", "web"),
    (r"sql", "web_sqli", "web"),
    (r"port\s*scan|nmap", "portscan", "portscan"),
    (r"infiltration|infilteration", "infiltration", "infiltration"),
    (r"bot", "botnet", "botnet"),
]


class UnknownLabelError(ValueError):
    pass


def canonical(label: str) -> tuple[str, str, bool]:
    """Map a raw label to (attack, family, attempted).

    >>> canonical("DoS Hulk - Attempted")
    ('dos_hulk', 'dos', True)
    >>> canonical("Infiltration - Portscan")
    ('portscan', 'portscan', False)
    """
    raw = label.strip()
    attempted = bool(ATTEMPTED_SUFFIX.search(raw))
    base = ATTEMPTED_SUFFIX.sub("", raw).lower()
    for pattern, attack, family in _RULES:
        if re.search(pattern, base):
            return attack, family, attempted
    raise UnknownLabelError(f"no canonical mapping for label {label!r}")
