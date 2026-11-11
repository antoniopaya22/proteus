import pytest

from proteus.datasets.labels import UnknownLabelError, canonical

CASES = {
    "BENIGN": ("benign", "benign", False),
    "DoS Hulk - Attempted": ("dos_hulk", "dos", True),
    "DoS Slowhttptest": ("dos_slowhttptest", "dos", False),
    "DDoS": ("ddos_loic_http", "ddos", False),
    "DDoS-LOIC-UDP": ("ddos_loic_udp", "ddos", False),
    "DDoS-HOIC": ("ddos_hoic", "ddos", False),
    "FTP-Patator": ("bf_ftp", "bruteforce", False),
    "SSH-BruteForce": ("bf_ssh", "bruteforce", False),
    "Web Attack - Brute Force - Attempted": ("web_bruteforce", "web", True),
    "Web Attack - SQL Injection": ("web_sqli", "web", False),
    "Infiltration - Portscan": ("portscan", "portscan", False),
    "Portscan": ("portscan", "portscan", False),
    "Infiltration - Attempted": ("infiltration", "infiltration", True),
    "Botnet": ("botnet", "botnet", False),
}


@pytest.mark.parametrize("raw,expected", CASES.items())
def test_canonical(raw, expected):
    assert canonical(raw) == expected


def test_unknown_label_raises():
    with pytest.raises(UnknownLabelError):
        canonical("Something new")
