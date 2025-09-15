import sys
import os
import logging
import json
import yaml


def set_logging():
    """
    Define logging path and configuration
    """
    try:
        open('out/log.log', 'r')
    except FileNotFoundError:
        os.makedirs('out', exist_ok=True)
        open('out/log.log', 'w').close()

    logging.basicConfig(
        filename='out/log.log',  # Name of the log file
        level=logging.INFO,  # Set the logging level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format='%(asctime)s; %(levelname)s; %(message)s' # Define the log message format
    )


def backup_source_alert(data):
    """
    Backup the source alert data to a file
    :param data: json alert data as dict
    """
    backup_path = f"history/source_alert_{data['alert_id']}.json"

    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    with open(backup_path, 'w') as backup_file:
        json.dump(data, backup_file, indent=4)


def normalization(data):
    """
    Normalize the alert data
    Output should contain: alert_id, source, type, created_at, asset, indicators
    :param data: json alert data as dict
    :return: normalized data as dict
    """
    # Convert indicators to a list
    normalized_indicators = []
    for i in data['indicators']:
        normalized_indicators.append({
            "type": i,
            "value": data['indicators'][i]
        })

    data['indicators'] = normalized_indicators

    return data


def enrich(data):
    """
    Enrich the alert data with local sources
    :param data: normalized alert data as dict
    :return: enriched data as dict
    """
    enrichment_source_path = "sources/ioc_list.json"
    try:
        with open(enrichment_source_path, 'r') as file:
            enrichment_data = json.load(file)
            logging.info(f"Enrichment source file loaded: {enrichment_source_path}")
    except FileNotFoundError:
        logging.error(f"Enrichment source file not found: {enrichment_source_path}")
        return data
    

    # Will treat everything as if there is only one possible value per indicator for simplification, also only enriching with score, risk, and source values
    # I would also nor enumerate the entire IOC list for searching
    for i in data['indicators']:
        match i['type']:
            case 'ipv4':
                for index, ip in enumerate(i['value']):
                    i['value'] = [{f"{ip}": []}]

                    # Check if the IP exists in the enrichment data
                    for enriched_data in enrichment_data:
                        if enriched_data['type'] == 'ipv4' and enriched_data['ip'] == ip:
                            i['value'][index][ip].append({
                                "source": enriched_data['source'],
                                "risk": enriched_data.get('risk', enriched_data.get('reputation', enriched_data.get('classification', 'unknown'))),
                                "score": enriched_data.get('score', enriched_data.get('confidence', 'unknown'))
                            })
                            logging.info(f"Indicator enriched: {i}")

            case 'domains':
                for index, domain in enumerate(i['value']):
                    i['value'] = [{f"{domain}": []}]

                    # Check if the domain exists in the enrichment data
                    for enriched_data in enrichment_data:
                        if enriched_data['type'] == 'domain' and enriched_data['domain'] == domain:
                            i['value'][index][domain].append({
                                "source": enriched_data['source'],
                                "risk": enriched_data.get('risk', enriched_data.get('reputation', enriched_data.get('classification', 'unknown'))),
                                "score": enriched_data.get('score', enriched_data.get('confidence', 'unknown'))
                            })
                            logging.info(f"Indicator enriched: {i}")

            case 'sha256':
                for index, hash in enumerate(i['value']):
                    i['value'] = [{f"{hash}": []}]

                    # Check if the hash exists in the enrichment data
                    for enriched_data in enrichment_data:
                        if enriched_data['type'] == 'hash' and enriched_data['sha256'] == hash:
                            i['value'][index][hash].append({
                                "source": enriched_data['source'],
                                "risk": enriched_data.get('risk', enriched_data.get('reputation', enriched_data.get('classification', 'unknown'))),
                                "score": enriched_data.get('score', enriched_data.get('confidence', 'unknown'))
                            })
                            logging.info(f"Indicator enriched: {i}")
            case _:
                for index, value in enumerate(i['value']):
                    i['value'] = [{f"{value}": []}]
                logging.warning(f"Unknown indicator type: {i['type']}")

    return data


def triage_alert(data):
    """
    Triage the alert based on predefined rules
    :param data: enriched alert data as dict
    """
    # Rules could be defined in a separate configuration file or database
    # Defining directly in the code for simplicity

    base_severity = {
        'Malware': 70,
        'Phishing': 60,
        'Beaconing': 65,
        'CredentialAccess': 75,
        'C2': 80,
        'Unknown': 40
    }

    # Base severity by alert type
    data['severity'] = base_severity.get(data['type'], base_severity['Unknown'])
    
    # Evaluate indicators
    risk_boost = 0
    flagged_indicators = 0
    highest_risk = 'unknown'

    with open("configs/allowlists.yml", 'r') as file:
        allowlist = yaml.safe_load(file)
        # print(json.dumps(allowlist, indent=4)) # DEBUG
    
    for i in data['indicators']:
        i['verdict'] = 'unknown'
        i['flagged'] = False
        i['suppressed'] = False
        
    #     for value in i['value']:
    #         for indicator in value:
    #             for entry in value[indicator]:
    #                 match entry['risk']:
    #                     case 'malicious':
    #                         i['flagged'] = True
    #                         i['verdict'] = 'malicious'
    #                     case 'suspicious':
    #                         i['flagged'] = True
    #                         if i['verdict'] != 'malicious':
    #                             i['verdict'] = 'suspicious'
    #                     case _:
    #                         pass

    #     if i['flagged']:
    #         flagged_indicators += 1

    #         match i['verdict']:
    #             case 'malicious':
    #                 highest_risk = 'malicious'
    #             case 'suspicious':
    #                 if highest_risk != 'malicious':
    #                     highest_risk = 'suspicious'
    #             case _:
    #                 pass

    #         # Check if the indicator is in the allowlist
    #         if i['type'] in allowlist and any(indicator in allowlist[i['type']] for value in i['value'] for indicator in value):
    #             i['suppressed'] = True
    #             logging.info(f"Indicator suppressed by allowlist: {i}")

    # risk_boost += 20 if highest_risk == 'malicious' else 10 if highest_risk == 'suspicious' else 0
    # if risk_boost > 0:
    #     risk_boost += min(flagged_indicators - 1, 4) * 5  # Additional boost for multiple flagged indicators, capped at 4 (20 points max)


    # data['severity'] += risk_boost
    # data['severity'] = min(data['severity'], 100)  # Cap severity at 100

    print(json.dumps(data, indent=4)) # DEBUG    

    return data


def ingest_alert(alert_file_path):
    """
    Ingest the alert from the specified file path
    :param alert_file_path: alert file path
    """
    # Step 1. Read the alert
    with open(alert_file_path, 'r') as file:
            alert_data = file.read()
            # print(alert_data)

    # Convert string data to dictionary
    alert_data = json.loads(alert_data)

    # Step 2. Backup the original alert data
    backup_source_alert(alert_data)

    # Step 3. Normalize
    normalized_data = normalization(alert_data)

    # Step 4. Enrich
    enriched_data = enrich(normalized_data)

    # Step 5. Triage
    triage_alert(enriched_data)

if __name__ == "__main__":
    set_logging()

    if len(sys.argv) != 2:
        print("Usage: python main.py path/to/alert.json")
        sys.exit(1)

    alert_file_path = sys.argv[1]

    print(f"Alert file path: {alert_file_path}")
    logging.info(f"Alert file path: {alert_file_path}")

    ingest_alert(alert_file_path)

