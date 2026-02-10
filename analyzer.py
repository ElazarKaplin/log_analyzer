def count_requests_by_ip(data):
    all_source_ips = [row[1] for row in data]
    ip_counts = {ip: all_source_ips.count(ip) for ip in set(all_source_ips)}
    return ip_counts


def map_port_to_protocol(data):
    port_map = {row[3]: row[4] for row in data}
    return port_map


# analyzer.py

def map_suspicions_by_ip(data):

    sus_map = {}

    for row in data:
        if len(row) < 6:
            continue

        ip = row[1]  # כתובת ה-IP (טקסט)
        port = row[3]  # הפורט (טקסט)
        size_str = row[5]  # הגודל (טקסט)
        try:
            size = int(size_str)
        except ValueError:
            size = 0
        try:
            time_part = row[0].split()[1]  # "08:23:45"
            hour = int(time_part.split(':')[0])  # 8
        except:
            hour = 12

        current_row_suspicions = []
        if not (ip.startswith("192.168") or ip.startswith("10.")):
            current_row_suspicions.append("EXTERNAL_IP")

        if port in ['22', '23', '3389']:
            current_row_suspicions.append("SENSITIVE_PORT")
        if size > 5000:
            current_row_suspicions.append("LARGE_PACKET")
        if 0 <= hour < 6:
            current_row_suspicions.append("NIGHT_ACTIVITY")
        if current_row_suspicions:
            if ip not in sus_map:
                sus_map[ip] = set()
            for s in current_row_suspicions:
                sus_map[ip].add(s)
    return {ip: list(sus) for ip, sus in sus_map.items()}



def filter_high_risk_ips(suspicious_map):

    high_risk_map = {
        ip: issues
        for ip, issues in suspicious_map.items()
        if len(issues) >= 2
    }
    return high_risk_map