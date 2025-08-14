# Threat Detection in Logs

This project is a modular Python-based security tool designed to detect suspicious activities by analyzing log files. As a practical application for cybersecurity engineers, it identifies common attack patterns like SSH brute-force attempts, SQL injection, and directory traversal by parsing and inspecting system and application logs.

---

## Goal

The primary goal is to build a foundational, extensible threat detection engine that automates the process of log analysis. This project serves as a practical demonstration of using Python for cybersecurity tasks, focusing on modular design, pattern matching with regular expressions, and configurable alerting.

---

## Features

-   **Multi-Attack Detection**: Identifies several common threat types:
    -   SSH Brute-Force Attempts
    -   SQL Injection (SQLi)
    -   Directory Traversal
-   **Modular Architecture**: Code is cleanly separated into modules for parsing, detection, and alerting, making it easy to maintain and extend.
-   **Configurable Rules**: Detection rules and thresholds (e.g., max failed logins) can be easily enabled, disabled, or modified in the main script.
-   **Log Aggregation**: Automatically reads and processes all `.log` files from a designated `/logs` directory.
-   **Clear Alerting**: Generates human-readable alerts for the console and saves them to a persistent `alerts.log` file.
-   **Zero Dependencies**: Built using only standard Python 3 libraries, requiring no external packages.

---

## Requirements

This project is written in Python 3.x and uses only standard libraries. No external packages are needed.

-   Python 3.6+

---

## Project Structure

```plaintext
threat_detection_project/
├── main.py               # Main script to orchestrate the process
├── log_parser.py         # Handles reading and parsing log files
├── detectors.py          # Contains all threat detection logic
├── alerts.py             # Manages alert formatting and output
├── logs/
│   ├── sample_ssh.log    # Test data for SSH attacks
│   └── sample_apache.log # Test data for web attacks
└── README.md
```
---

## How It Works

1.  **Initialization**: The `main.py` script loads the configuration, which specifies which detection rules are active and their parameters (e.g., 5 failed logins within 60 seconds).
2.  **Log Parsing**: The `log_parser.py` module scans the `/logs` directory, reads each log file, and returns its content as a list of entries.
3.  **Threat Detection**: For each log file, `main.py` calls the enabled detector functions from `detectors.py`.
4.  **Pattern Matching**: Each detector uses optimized regular expressions to find attack signatures.
    -   **SSH Brute-Force**: Tracks failed login attempts per IP address within a specific time window.
    -   **SQL Injection & Directory Traversal**: Scans web server log requests for malicious patterns and keywords (e.g., `UNION SELECT`, `../../`).
5.  **Alert Generation**: If a detector identifies a threat, it passes the relevant information (IP, timestamp, attack type) to the `alerts.py` module, which formats and outputs the alert to both the console and `alerts.log`.

---

## Code Highlights

-   **`re.compile()`**: Regular expressions are pre-compiled for efficient matching across thousands of log entries.
-   **`defaultdict`**: Used in the SSH brute-force detector to efficiently group failed login timestamps by IP address.
-   **Configurable Dictionaries**: Detection rules in `main.py` are controlled via a simple dictionary, allowing an admin to easily toggle rules on or off.
-   **Modular Functions**: Each detection function is self-contained, making it simple to add new detectors without modifying existing code.

---

## Sample Output

```plaintext
Starting threat detection process...

--- Analyzing logs/sample_ssh.log ---
[ALERT] [2025-08-14 21:30:45] Type: SSH Brute Force | IP: 192.168.1.101 | Count: 6

--- Analyzing logs/sample_apache.log ---
[ALERT] [2025-08-14 21:30:45] Type: SQL Injection Attempt | IP: 10.0.0.5 | Request: "/login.php?user=admin&pass=password' or '1'='1' --"
[ALERT] [2025-08-14 21:30:45] Type: SQL Injection Attempt | IP: 10.0.0.5 | Request: "/products.php?id=1 UNION SELECT user, pass FROM users"
[ALERT] [2025-08-14 21:30:45] Type: Directory Traversal Attempt | IP: 203.0.113.78 | Request: "/scripts/..%2f../etc/passwd"
[ALERT] [2025-08-14 21:30:45] Type: Directory Traversal Attempt | IP: 203.0.113.78 | Request: "/../../../../../../windows/system.ini"

Threat detection process finished.
```
---

## To run the script:

1.  Ensure you have sample files in the `/logs` directory.
2.  Execute the main script from the project's root directory:

```bash
python3 main.py
```
The script will automatically process the logs and print any alerts to your console. A file named alerts.log will be created in the root directory with a history of all alerts.

---

## Extensibility & Future Improvements

The modular design makes it easy to enhance the tool:

-   **Add New Detectors**: Create new functions in `detectors.py` for other attacks like Cross-Site Scripting (XSS) or Command Injection.
-   **Support More Log Formats**: Enhance `log_parser.py` to handle different formats like JSON, XML, or Windows Event Logs.
-   **Real-time Analysis**: Integrate with a log streaming service like Syslog to analyze events in real-time instead of processing static files.
-   **Advanced Alerting**: Connect `alerts.py` to external services like Slack, PagerDuty, or email for instant notifications.

---

## Author

Diego Acosta – Dycouzt
