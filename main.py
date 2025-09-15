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
    
    # Load allowlist
    with open("configs/allowlists.yml", 'r') as file:
        allowlist = yaml.safe_load(file)
    
    # Evaluate indicators
    for indicator in data['indicators']:
        for value in indicator['value']:
            # Count all TI provider verdicts
            verdict_count = {
                'malicious': sum(1 for entry in value[next(iter(value))] if entry['risk'] == 'malicious'),
                'suspicious': sum(1 for entry in value[next(iter(value))] if entry['risk'] == 'suspicious'),
                'allowlisted': sum(1 for entry in value[next(iter(value))] if entry['risk'] == 'allowlisted'),
                'other': sum(1 for entry in value[next(iter(value))] if entry['risk'] not in ['malicious', 'suspicious', 'allowlisted'])
            }
            
            if (verdict_count['malicious'] > 0):
                value['flagged'] = True
                value['verdict'] = 'malicious'
            elif (verdict_count['suspicious'] > 0):
                value['flagged'] = True
                value['verdict'] = 'suspicious'
                        
            # Check against allowlist
            if indicator['type'] in allowlist['indicators']:
                if next(iter(value)) in allowlist['indicators'][indicator['type']]:
                    value['flagged'] = False
                    value['verdict'] = 'allowlisted'
                    logging.info(f"Indicator allowlisted: {next(iter(value))}")

    # Count how many indicators are flagged as malicious or suspicious
    flagged_indicators = sum(1 for i in data['indicators'] for value in i['value'] if value.get('flagged', False))

    # Get the highest verdict among all indicators
    highest_verdict = 'unknown'

    if any(value.get('verdict') == 'malicious' for i in data['indicators'] for value in i['value']):
        highest_verdict = 'malicious'
    elif any(value.get('verdict') == 'suspicious' for i in data['indicators'] for value in i['value']):
        highest_verdict = 'suspicious'

    # Evaluate asset allowlist
    # TODO: asset enrichment

    # Calculate risk boost based on TI verdicts
    # If all indicators are allowlisted, set severity to 0
    if all(value.get('verdict') == 'allowlisted' for i in data['indicators'] for value in i['value']):
        data['suppressed'] = True
        data['severity'] = 0
    else:
        data['suppressed'] = False
        # Apply risk boost based on highest verdict and number of flagged indicators (20 points for malicious, 10 for suspicious, plus 5 points for each additional flagged indicator, capped at +20 points)
        risk_boost = 20 if highest_verdict == 'malicious' else 10 if highest_verdict == 'suspicious' else 0
        if risk_boost > 0:
            risk_boost += min(flagged_indicators - 1, 4) * 5  # Additional boost for multiple flagged indicators, capped at 4 (20 points max)

        # Reduce 25 points from risk boost for each allowlisted indicator, capped at 4 (100 points max)
        allowlisted_indicators = sum(1 for i in data['indicators'] for value in i['value'] if value.get('verdict') == 'allowlisted')
        if allowlisted_indicators > 0:
            risk_boost -= min(allowlisted_indicators, 4) * 25  # Reduce risk boost for allowlisted indicators, capped at 4 (20 points max)
            risk_boost = max(risk_boost, 0)  # Ensure risk boost doesn't go negative

        data['severity'] += risk_boost
        data['severity'] = min(data['severity'], 100) # Cap severity at 100
        data['severity'] = max(data['severity'], 0) # Ensure severity doesn't go negative

    # Classify severity
    severity_classification = {
        range(0, 1): 'Suppressed', # 0
        range(1, 40): 'Low', # 1-39
        range(40, 70): 'Medium', # 40-69
        range(70, 90): 'High', # 70-89
        range(90, 101): 'Critical' # 90-100
    }

    for severity_range, classification in severity_classification.items():
        if data['severity'] in severity_range:
            data['severity_classification'] = classification
            break

    # Tag using Mitre ATT&CK framework
    with open("configs/mitre_map.yml", 'r') as file:
        mitre_mapping = yaml.safe_load(file)
    
    data['tags'] = mitre_mapping["types"].get(data['type'], mitre_mapping['defaults'])

    data['tags'] += { f"suppressed={data['suppressed']}" }

    logging.info(f"Alert triaged: severity={data['severity']}, classification={data['severity_classification']}, suppressed={data['suppressed']}")

    return data

def get_file(file_path):
    """
    Read and return the content of a file
    :param file_path: path to the file
    :return: file content as dict
    """
    try:
        with open(file_path, 'r') as file:
            file_data = file.read()
            logging.info(f"File loaded: {file_path}")
            return json.loads(file_data)
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return {}

def output_isolation_log(data):
    """
    Output the alert isolation log to a file
    :param data: triaged alert data as dict
    """
    # TODO: output isolation log
    output_path = f"out/isolation.log.json"

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # with open(output_path, 'w') as output_file:
    # <ISO-TS> isolate device_id=<ID> incident=<INCIDENT_ID> result=isolated
    #     json.dump(data, output_file, indent=4)

    logging.info(f"Alert analysis output to file: {output_path}")


def output_incident(data):
    """
    Output the alert as an incident to a file according to certain criteria
    :param data: triaged alert data as dict
    """
    # TODO: output incident
    # Determine next incident ID
    next_incident_id = 1
    existing_incidents = os.listdir("out/incidents")
    if existing_incidents:
        next_incident_id = max(int(f.split('_')[1].split('.')[0]) for f in existing_incidents if f.startswith('incident_')) + 1

    output_path = f"out/incidents/{next_incident_id}.json"

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    source_alert = get_file(f"history/source_alert_{data['alert_id']}.json")

    # Remove 'suppressed=' tag from tags if present
    output_format = {
        "incident_id": data['alert_id'],
        "source_alert": source_alert,
        "asset": data['asset'],
        "indicators": data['indicators'],
        "triage": {
            "severity": data['severity'],
            "bucket": data['severity_classification'],
            "tags": data['tags'],
            "suppressed": data['suppressed']
        },
        "mitre": { "techniques": [tag for tag in data['tags'] if not str(tag).startswith('suppressed=')] },
        "actions": [], # [ { "type":"isolate","target":"device:<ID>","result":"isolated","ts":"..."} ]
        "timeline": [] # [ { "stage":"ingest|enrich|triage|respond", "ts":"...", "details":"..." } 
    }

    print(json.dumps(output_format, indent=2)) # DEBUG

    # with open(output_path, 'w') as output_file:
    #     json.dump(data, output_file, indent=4)

    logging.info(f"Alert analysis output to file: {output_path}")


def output_analyst_summary(data):
    """
    Output a summary for the analyst to a markdown file
    :param data: triaged alert data as dict
    """
    # TODO: output analyst summary
    pass


def ingest_alert(alert_file_path):
    """
    Ingest the alert from the specified file path
    :param alert_file_path: alert file path
    """
    # Step 1. Read the alert
    with open(alert_file_path, 'r') as file:
            alert_data = file.read()

    # Convert string data to dictionary
    alert_data = json.loads(alert_data)

    # Step 2. Backup the original alert data
    backup_source_alert(alert_data)

    # Step 3. Normalize
    normalized_data = normalization(alert_data)

    # Step 4. Enrich
    enriched_data = enrich(normalized_data)

    # Step 5. Triage
    triaged_alert = triage_alert(enriched_data)

    # Step 6. Output the final alert data
    # print(json.dumps(triaged_alert, indent=2))
    # output_isolation_log(triaged_alert)
    output_incident(triaged_alert)

if __name__ == "__main__":
    set_logging()

    if len(sys.argv) != 2:
        print("Usage: python main.py path/to/alert.json")
        sys.exit(1)

    alert_file_path = sys.argv[1]

    print(f"Alert file path: {alert_file_path}")
    logging.info(f"Alert file path: {alert_file_path}")

    ingest_alert(alert_file_path)

