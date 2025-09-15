import sys
import logging

def backup_source_alert(data):
    """
    Backup the source alert data to a file.
    :param data: alert data.
    """
    backup_path = "history/source_alert_%s.json" % data['id']
    with open(backup_path, 'w') as backup_file:
        backup_file.write(data)


def ingest_alert(alert_file_path):
    """
    Ingest the alert from the specified file path.
    :param alert_file_path: alert file path.
    """
    # Read the alert file
    with open(alert_file_path, 'r') as file:
            alert_data = file.read()
            print(alert_data)

    # backup_source_alert(alert_data)


if __name__ == "__main__":
    logging.basicConfig(
        filename='out/log.log',  # Name of the log file
        level=logging.INFO,  # Set the logging level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format='%(asctime)s - %(levelname)s - %(message)s' # Define the log message format
    )

    if len(sys.argv) != 2:
        print("Usage: python main.py path/to/alert.json")
        sys.exit(1)

    alert_file_path = sys.argv[1]

    print(f"Alert file path: {alert_file_path}")
    logging.info(f"Alert file path: {alert_file_path}")

    backup_source_alert(alert_file_path)

    # Log source alert
    # Copy original alert file to a new location

    ingest_alert(alert_file_path)

