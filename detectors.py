import re
from collections import defaultdict
from datetime import datetime

def detect_ssh_brute_force(log_entries, config):
    """
    Detects SSH brute-force attempts from log entries.

    Args:
        log_entries (list): A list of log entry strings.
        config (dict): Configuration dictionary with 'max_failed_logins'
                       and 'time_window_seconds'.
                       
    Returns:
        list: A list of alert-worthy events.
    """
    failed_logins = defaultdict(list)
    alerts = []

    # Regex to capture failed SSH login attempts
    # Example log: Aug 10 09:32:20 sshd[12345]: Failed password for invalid user admin from 192.168.1.101 port 22 ssh2
    ssh_regex = re.compile(r".*Failed password for .* from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*")

    for entry in log_entries:
        match = ssh_regex.match(entry)
        if match:
            ip_address = match.group('ip')
            # A simple timestamp is used here; for production, parse the log's timestamp
            timestamp = datetime.now()
            failed_logins[ip_address].append(timestamp)

    # Check for brute-force attempts based on configuration
    for ip, timestamps in failed_logins.items():
        if len(timestamps) > config['max_failed_logins']:
            # Check if the attempts are within the defined time window
            time_diff = (max(timestamps) - min(timestamps)).total_seconds()
            if time_diff <= config['time_window_seconds']:
                alerts.append({
                    "type": "SSH Brute Force",
                    "ip": ip,
                    "count": len(timestamps),
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
    return alerts

def detect_sql_injection(log_entries, config):
    """
    Detects potential SQL injection attempts in web server logs.

    Args:
        log_entries (list): A list of log entry strings.
        config (dict): Configuration dictionary (currently unused but for future extensibility).

    Returns:
        list: A list of alert-worthy events.
    """
    alerts = []
    # Regex for common SQL injection patterns
    sql_injection_patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # URL encoded characters
        r"\b(union|select|insert|update|delete|drop|truncate)\b"
    ]
    sql_regex = re.compile(f"({'|'.join(sql_injection_patterns)})", re.IGNORECASE)

    # Regex to capture IP and request from a common log format
    # Example: 127.0.0.1 - - [10/Aug/2025:13:55:36 +0000] "GET /index.php?id=1' or '1'='1 HTTP/1.1" 200 426
    log_format_regex = re.compile(r'(?P<ip>[\d\.]+) .*? "GET (?P<request>.*?) HTTP.*"')

    for entry in log_entries:
        log_match = log_format_regex.match(entry)
        if log_match:
            request = log_match.group('request')
            if sql_regex.search(request):
                alerts.append({
                    "type": "SQL Injection Attempt",
                    "ip": log_match.group('ip'),
                    "request": request,
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
    return alerts

def detect_directory_traversal(log_entries, config):
    """
    Detects directory traversal attempts.

    Args:
        log_entries (list): A list of log entry strings.
        config (dict): Configuration dictionary (currently unused).

    Returns:
        list: A list of alert-worthy events.
    """
    alerts = []
    # Regex for directory traversal patterns
    traversal_pattern = r"(\.\./|%2e%2e/)"
    traversal_regex = re.compile(traversal_pattern)

    log_format_regex = re.compile(r'(?P<ip>[\d\.]+) .*? "GET (?P<request>.*?) HTTP.*"')

    for entry in log_entries:
        log_match = log_format_regex.match(entry)
        if log_match:
            request = log_match.group('request')
            if traversal_regex.search(request):
                alerts.append({
                    "type": "Directory Traversal Attempt",
                    "ip": log_match.group('ip'),
                    "request": request,
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
    return alerts