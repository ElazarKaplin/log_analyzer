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

from checks import suspicion_checks, get_row_suspicions_dynamic

def extract_hours(data):
    return list(map(lambda row: int(row[0].split()[1].split(':')[0]), data))
def convert_sizes_to_kb(data):
    return list(map(lambda row: int(row[5]) / 1024, data))
def filter_by_sensitive_port(data):
    return list(filter(lambda row: row[3] in ["22", "23", "3389"], data))
def filter_night_activity(data):
    return list(filter(lambda row: 0 <= int(row[0].split()[1].split(':')[0]) < 6, data))
def analyze_all_logs_dynamic(data):
    results = map(lambda r: {"ip": r[1], "suspicions": get_row_suspicions_dynamic(r, suspicion_checks)}, data)
    return list(filter(lambda x: len(x["suspicions"]) > 0, results))


from checks import suspicion_checks, get_row_suspicions_dynamic

def filter_suspicious_generator(log_generator):
    for row in log_generator:
        suspicions = get_row_suspicions_dynamic(row, suspicion_checks)
        if len(suspicions) > 0:
            yield row

def add_suspicion_details_generator(suspicious_generator):
    for row in suspicious_generator:
        suspicions = get_row_suspicions_dynamic(row, suspicion_checks)
        yield row, suspicions  # [cite: 90]

def count_items_generator(generator):
    return sum(1 for _ in generator) # משתמש ב-Generator Expression לספירה יעילה [cite: 98, 100]