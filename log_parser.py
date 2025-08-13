import os
import re

def parse_log_file(file_path):
    """
    Reads a log file and returns a list of log entries.

    Args:
        file_path (str): The full path to the log file.

    Returns:
        list: A list of strings, where each string is a line from the log file.
    """
    try:
        with open(file_path, 'r') as f:
            return f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {file_path}")
        return []

def get_log_files(directory="logs"):
    """
    Retrieves a list of log files from a given directory.

    Args:
        directory (str): The directory to search for log files.

    Returns:
        list: A list of full paths to the log files.
    """
    log_files = []
    if not os.path.exists(directory):
        print(f"[ERROR] Log directory not found: {directory}")
        return log_files

    for filename in os.listdir(directory):
        if filename.endswith(".log"):
            log_files.append(os.path.join(directory, filename))
    return log_files
