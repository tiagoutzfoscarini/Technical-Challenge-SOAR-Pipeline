import sys
import os
import logging
import json
import yaml
import jinja2
from datetime import datetime


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
        filename='out/log.log',
        level=logging.INFO, 
        format='%(asctime)s; %(levelname)s; %(message)s'
    )

    
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
            # return json.loads(file_data)
            return json.loads(file_data) if file_path.endswith('.json') else yaml.safe_load(file_data) if file_path.endswith(('.yml', '.yaml')) else file_data
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return {}


def output_file(file_path, data):
    """
    Output data to a specified file path
    :param file_path: output file path
    :param data: data to be written as dict
    """
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)
    logging.info(f"Output file created: {file_path}")



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
    # enrichment_source_path = "sources/ioc_list.json"
    # try:
    #     with open(enrichment_source_path, 'r') as file:
    #         enrichment_data = json.load(file)
    #         logging.info(f"Enrichment source file loaded: {enrichment_source_path}")
    # except FileNotFoundError:
    #     logging.error(f"Enrichment source file not found: {enrichment_source_path}")
    #     return data

    sources = get_file("configs/connectors.yml")

    for provider in sources['providers']:
        provider_path = sources['providers'][provider]['base_url'].replace("file://", "") # Local path

        # Simulate provider API calls by reading local files
        enrichment_data = []

        match provider:
            case 'anomali':
                for file_name in os.listdir(provider_path):
                    if file_name.startswith('anomali_') and file_name.endswith('.json'):
                        file_path = os.path.join(provider_path, file_name)
                        file_data = get_file(file_path)
                        file_data['source'] = 'anomali'
                        enrichment_data.append(file_data)
            case 'defender_ti':
                for file_name in os.listdir(provider_path):
                    if file_name.startswith('defender_ti_') and file_name.endswith('.json'):
                        file_path = os.path.join(provider_path, file_name)
                        file_data = get_file(file_path)
                        file_data['source'] = 'defender_ti'
                        enrichment_data.append(file_data)
            case 'reversinglabs':
                for file_name in os.listdir(provider_path):
                    if file_name.startswith('reversinglabs_') and file_name.endswith('.json'):
                        file_path = os.path.join(provider_path, file_name)
                        file_data = get_file(file_path)
                        file_data['source'] = 'reversinglabs'
                        enrichment_data.append(file_data)
            case _:
                logging.error(f"Unknown provider: {provider}")

    if not enrichment_data:
        logging.error("No enrichment data available")
        return data

    # Assuming only 1 value per indicator type
    # Adding only the values for score, risk, and source values
    for i in data['indicators']:
        flagged = 0 # Count how many providers flagged this IOC as malicious or suspicious
        highest_risk = 'clean'
        highest_score = 0
        
        match i['type']:
            case 'ipv4':
                for enriched_data in enrichment_data:
                    if "ip" in enriched_data and enriched_data['ip'] == i['value'][0]:
                        risk = enriched_data.get('risk', enriched_data.get('reputation', enriched_data.get('classification', 'unknown')))
                        flagged += 1 if risk in ['malicious', 'suspicious'] else 0
                        highest_risk = 'malicious' if risk == 'malicious' else 'suspicious' if highest_risk != 'malicious' and risk == 'suspicious' else highest_risks
                        highest_score = max(highest_score, enriched_data.get('score', enriched_data.get('confidence', 0)))
            case 'domains':
                for enriched_data in enrichment_data:
                    if "domain" in enriched_data and enriched_data['domain'] == i['value'][0]:
                        flagged += 1 if enriched_data['risk'] in ['malicious', 'suspicious'] else 0

                        risk = enriched_data.get('risk', enriched_data.get('reputation', enriched_data.get('classification', 'unknown')))
                        flagged += 1 if risk in ['malicious', 'suspicious'] else 0
                        highest_risk = 'malicious' if risk == 'malicious' else 'suspicious' if highest_risk != 'malicious' and risk == 'suspicious' else highest_risks
                        highest_score = max(highest_score, enriched_data.get('score', enriched_data.get('confidence', 0)))
                        
            case 'urls':
                for enriched_data in enrichment_data:
                    if "url" in enriched_data and enriched_data['url'] == i['value'][0]:
                        flagged += 1 if enriched_data['risk'] in ['malicious', 'suspicious'] else 0

                        risk = enriched_data.get('risk', enriched_data.get('reputation', enriched_data.get('classification', 'unknown')))
                        flagged += 1 if risk in ['malicious', 'suspicious'] else 0
                        highest_risk = 'malicious' if risk == 'malicious' else 'suspicious' if highest_risk != 'malicious' and risk == 'suspicious' else highest_risks
                        highest_score = max(highest_score, enriched_data.get('score', enriched_data.get('confidence', 0)))
                        
            case 'sha256':
                for enriched_data in enrichment_data:
                    if "sha256" in enriched_data and enriched_data['sha256'] == i['value'][0]:
                        flagged += 1 if enriched_data['risk'] in ['malicious', 'suspicious'] else 0

                        risk = enriched_data.get('risk', enriched_data.get('reputation', enriched_data.get('classification', 'unknown')))
                        flagged += 1 if risk in ['malicious', 'suspicious'] else 0
                        highest_risk = 'malicious' if risk == 'malicious' else 'suspicious' if highest_risk != 'malicious' and risk == 'suspicious' else highest_risks
                        highest_score = max(highest_score, enriched_data.get('score', enriched_data.get('confidence', 0)))
            case _:
                logging.warning(f"Unknown indicator type: {i['type']}")

        # Default values if not found in enrichment data
        i['risk'] = highest_risk if highest_risk != 'clean' else 'unknown'
        i['score'] = highest_score if highest_score > 0 else 'unknown'
        i['flagged'] = flagged

    return data


def evaluate_indicators(data, allowlist):
    """
    Evaluate the alert indicators based on TI verdicts and check against allowlist
    :param data: alert data as dict
    :param allowlist: allowlist as dict
    :return: evaluated indicators as list, count of flagged indicators as int, highest verdict as str
    """
    # Check against allowlist
    for indicator in data['indicators']:
        if indicator['type'] in allowlist['indicators'].keys():
            if indicator['value'][0] in allowlist['indicators'][indicator['type']]:
                indicator['allowlisted'] = True
                logging.info(f"Indicator allowlisted: {indicator['type']}={indicator['value'][0]}")
            else:
                indicator['allowlisted'] = False
        else:
            indicator['allowlisted'] = False
            logging.warning(f"Unknown indicator type for allowlist check: {indicator['type']}")

    # Count how many indicators are flagged as malicious or suspicious
    flagged_indicators = sum(1 for i in data['indicators'] if i.get('risk') in ['malicious', 'suspicious'])

    # Get the highest verdict among all indicators
    highest_risk = 'unknown'

    if any(indicator.get('risk') == 'malicious' for indicator in data['indicators']):
        highest_risk = 'malicious'
    elif any(indicator.get('risk') == 'suspicious' for indicator in data['indicators']):
        highest_risk = 'suspicious'

    return data['indicators'], flagged_indicators, highest_risk


def evaluate_assets(data, allowlist):
    """
    Evaluate the alert assets against allowlist
    :param data: alert data as dict
    :param allowlist: allowlist as dict
    :return: evaluated assets as list
    """
    allowlist_assets = allowlist.get('assets', {})

    for k, v in data['asset'].items(): 
        match k:
            case 'device_id':
                if v in allowlist_assets.get('device_ids', []):
                    data['asset']['verdict'] = 'allowlisted'
                    data['asset']['allowlisted_field'] = k
                    logging.info(f"Asset allowlisted: {k}={v}")
            case 'ip':
                # Placeholder - No allowlist for IPs for now
                pass
            case 'hostname':
                # Placeholder - No allowlist for hostnames for now
                pass
            case _:
                logging.warning(f"Unknown asset type: {k}")

    if data['asset'].get('verdict') is None:
        data['asset']['verdict'] = 'unknown'
        data['asset']['allowlisted_field'] = None

    return data['asset']


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


    # Evaluate all alert indicators, and check against allowlist
    data['indicators'], flagged_indicators, highest_risk = evaluate_indicators(data, allowlist)

    # Evaluate assets against allowlist
    data['asset'] = evaluate_assets(data, allowlist)

    # Calculate risk boost based on TI verdicts
    # If all indicators are allowlisted, set severity to 0
    if all(indicator.get('allowlisted') == True for indicator in data['indicators']):
        data['suppressed'] = True
        data['severity'] = 0
    else:
        data['suppressed'] = False
        # Apply risk boost based on highest verdict and number of flagged indicators (20 points for malicious, 10 for suspicious, plus 5 points for each additional flagged indicator, capped at +20 points)
        risk_boost = 20 if highest_risk == 'malicious' else 10 if highest_risk == 'suspicious' else 0
        if risk_boost > 0:
            risk_boost += min(flagged_indicators - 1, 4) * 5  # Additional boost for multiple flagged indicators, capped at 4 (20 points max)

        # Reduce 25 points from risk boost if an indicator is allowlisted
        allowlisted_indicators = sum(1 for indicator in data['indicators'] if indicator.get('allowlisted') == True)
        if allowlisted_indicators > 0:
            risk_boost -= 25  # Reduce risk boost for allowlisted indicators, capped at 4 (20 points max)
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
    
    data['mitre_techniques'] = mitre_mapping["types"].get(data['type'], mitre_mapping['defaults'])
    data['tags'] = data.get('tags', []) + data['mitre_techniques'] + [ f"suppressed={data['suppressed']}" ]

    logging.info(f"Alert triaged: severity={data['severity']}, classification={data['severity_classification']}, suppressed={data['suppressed']}")

    return data


def take_response_action(data):
    """
    Take automated response actions based on predefined rules
    :param data: incident data as dict
    :return: data with actions taken as dict
    """
    if data['triage']['severity'] >= 70 and data['asset'].get('device_id') and data['asset'].get('allowlisted_field') != 'device_id':
        # Isolate the device
        # Append a line to out/isolation.log:
        isolation_log_path = "out/isolation.log"
        with open(isolation_log_path, 'a') as log_file:
            log_file.write(f"<ISO-TS> isolate device_id={data['asset']['device_id']} incident={data['incident_id']} result=isolated\n")
        logging.info(f"Device isolated: device_id={data['asset']['device_id']}, incident={data['incident_id']}")

        # Record the action taken
        if 'actions' not in data:
            data['actions'] = []
        
        data['actions'].append({
            "type": "isolate",
            "target": f"device:{data['asset']['device_id']}",
            "result": "isolated",
            "ts": datetime.now().isoformat()
        })

    return data


def create_incident(data):
    """
    Create an incident from the triaged alert data
    :param data: triaged alert data as dict
    :return: incident data as dict
    """
    # Define next incident ID
    next_incident_id = 1
    existing_incidents = os.listdir("out/incidents")
    if existing_incidents:
        next_incident_id = max(int(f.split('_')[1].split('.')[0]) for f in existing_incidents if f.startswith('incident_')) + 1

    # Get source alert from history
    source_alert_path = f"history/source_alert_{data['alert_id']}.json"
    source_alert = get_file(source_alert_path)
    if not source_alert:
        logging.error(f"Source alert not found for incident creation: {source_alert_path}")
        return {}

    incident = {
        "incident_id": f"incident_{next_incident_id:04d}",
        "source_alert": source_alert,
        "asset": data['asset'],
        "indicators": data['indicators'],
        "triage": {
            "severity": data['severity'],
            "bucket": data['severity_classification'],
            "tags": data['tags'],
            "suppressed": data['suppressed']
        },
        "mitre": data['mitre_techniques'],
        "actions": data.get('actions', []),
        "timeline": data['timeline']
    }

    return incident


def create_analyst_summary(data):
    """
    Create an analyst summary report in markdown format
    :param data: incident data as dict
    :return: summary report as str
    """
    template_loader = jinja2.FileSystemLoader(searchpath="./templates")
    template_env = jinja2.Environment(loader=template_loader)
    template = template_env.get_template("summary_report.md.j2")

    summary_report = template.render(incident=data)

    return summary_report


def log_timeline(action, ts, data):
    """
    Log an action to the incident timeline
    :param action: action stage performed
    :param ts: timestamp of the action
    :param data: alert or incident data as dict
    :return: updated data with timeline entry as dict
    """
    if 'timeline' not in data:
        data['timeline'] = []

    data['timeline'].append({
        "action": action,
        "ts": ts,
        "details": "*"  # Placeholder for additional details if needed
    })

    return data


if __name__ == "__main__":
    set_logging()

    if len(sys.argv) != 2:
        print("Usage: python main.py path/to/alert.json")
        sys.exit(1)

    alert_file_path = sys.argv[1]

    print(f"Alert file path: {alert_file_path}")
    logging.info(f"Alert file path: {alert_file_path}")

    # Step 1. Ingest the alert and backup the original alert data
    alert_data = get_file(alert_file_path)
    # Backup source alert to history
    output_file(f"history/source_alert_{alert_data['alert_id']}.json", alert_data)
    alert_data = log_timeline("ingest", datetime.now().isoformat(), alert_data)

    # Step 2. Normalize
    alert_data = normalization(alert_data)

    # Step 3. Enrich
    alert_data = enrich(alert_data)
    alert_data = log_timeline("enrich", datetime.now().isoformat(), alert_data)
    
    # Step 4. Triage
    triaged_alert_data = triage_alert(alert_data)
    triaged_alert_data = log_timeline("triage", datetime.now().isoformat(), triaged_alert_data)

    # Step 5. Define incident schema
    incident = create_incident(triaged_alert_data)

    # Step 6. Actions and automated response
    if incident['triage']['suppressed'] == False: # Only take actions if not suppressed
        incident = take_response_action(incident)
        incident = log_timeline("respond", datetime.now().isoformat(), incident)

    # Step 7. Final outputs
    # Incident JSON
    output_file(f"out/incidents/{incident['incident_id']}.json", incident)

    # Analyst summary report
    # TODO: Implement Jinja template for summary report
    summary_report = create_analyst_summary(incident)
    output_file(f"out/summaries/{incident['incident_id']}.md", summary_report)

