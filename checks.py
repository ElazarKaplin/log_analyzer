import ipaddress


def extract_external_ips(data):
    external_ips = [
        row[1] for row in data
        if not (row[1].startswith("192.168") or row[1].startswith("10."))
    ]

    return external_ips


def filter_sensitive_ports(data):
    sensitive_ports = ['22', '23', '3389']
    suspicious_rows = [
        row for row in data
        if row[3] in sensitive_ports
    ]

    return suspicious_rows


def filter_large_packets(data):
    large_packets = [
        row for row in data
        if int(row[5]) > 5000
    ]

    return large_packets


# checks.py

def tag_traffic_size(data):
    tags = [
        "LARGE" if int(row[5]) > 5000 else "NORMAL"
        for row in data
    ]

    return tags


suspicion_checks = {
    "EXTERNAL_IP": lambda row: not (row[1].startswith("192.168") or row[1].startswith("10.")),
    "SENSITIVE_PORT": lambda row: row[3] in ["22", "23", "3389"],
    "LARGE_PACKET": lambda row: int(row[5]) > 5000,
    "NIGHT_ACTIVITY": lambda row: 0 <= int(row[0].split()[1].split(':')[0]) < 6
}

def get_row_suspicions_dynamic(row, checks_dict):
    active_suspicions = list(filter(lambda key: checks_dict[key](row), checks_dict.keys()))
    return active_suspicions