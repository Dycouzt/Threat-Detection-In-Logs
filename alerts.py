# alerts.py

def generate_alert(alert_info):
    """
    Formats and prints an alert to the console and writes it to a file.

    Args:
        alert_info (dict): A dictionary containing the alert details.
    """
    alert_type = alert_info.get("type", "Unknown")
    timestamp = alert_info.get("timestamp", "N/A")
    ip = alert_info.get("ip", "N/A")

    if alert_type == "SSH Brute Force":
        count = alert_info.get("count", 0)
        message = f"[ALERT] [{timestamp}] Type: {alert_type} | IP: {ip} | Count: {count}"
    elif alert_type in ["SQL Injection Attempt", "Directory Traversal Attempt"]:
        request = alert_info.get("request", "N/A")
        message = f"[ALERT] [{timestamp}] Type: {alert_type} | IP: {ip} | Request: \"{request}\""
    else:
        message = f"[ALERT] [{timestamp}] An unknown threat has been detected from IP: {ip}"

    print(message)
    write_alert_to_file(message)

def write_alert_to_file(message, filename="alerts.log"):
    """
    Appends an alert message to a log file.

    Args:
        message (str): The alert message to write.
        filename (str): The name of the file to write to.
    """
    with open(filename, 'a') as f:
        f.write(message + "\n")