# main.py

import log_parser
import detectors
import alerts

# --- Configuration ---
DETECTION_RULES = {
    "ssh_brute_force": True,
    "sql_injection": True,
    "directory_traversal": True,
}

DETECTION_CONFIG = {
    "ssh_brute_force": {
        "max_failed_logins": 5,
        "time_window_seconds": 60,
    },
    "sql_injection": {},
    "directory_traversal": {},
}

LOG_DIRECTORY = "logs"

def main():
    """
    Main function to run the threat detection system.
    """
    print("Starting threat detection process...")
    log_files = log_parser.get_log_files(LOG_DIRECTORY)

    if not log_files:
        print("No log files found. Exiting.")
        return

    for log_file in log_files:
        print(f"\n--- Analyzing {log_file} ---")
        log_entries = log_parser.parse_log_file(log_file)

        if not log_entries:
            continue

        # Run enabled detection rules
        if DETECTION_RULES.get("ssh_brute_force"):
            ssh_alerts = detectors.detect_ssh_brute_force(
                log_entries, DETECTION_CONFIG["ssh_brute_force"]
            )
            for alert in ssh_alerts:
                alerts.generate_alert(alert)

        if DETECTION_RULES.get("sql_injection"):
            sql_alerts = detectors.detect_sql_injection(
                log_entries, DETECTION_CONFIG["sql_injection"]
            )
            for alert in sql_alerts:
                alerts.generate_alert(alert)

        if DETECTION_RULES.get("directory_traversal"):
            traversal_alerts = detectors.detect_directory_traversal(
                log_entries, DETECTION_CONFIG["directory_traversal"]
            )
            for alert in traversal_alerts:
                alerts.generate_alert(alert)

    print("\nThreat detection process finished.")

if __name__ == "__main__":
    main()