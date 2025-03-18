import os
import json
import pandas as pd
import streamlit as st
from llama_cpp import Llama
from mitreattack.stix20 import MitreAttackData
import tempfile
import uuid
import re
from datetime import datetime
import csv
import io

# Configuration
MODEL_PATH = r"C:/Users/youss/Downloads/llama-2-7b.Q4_K_M.gguf"
MITRE_DATA_CACHE = "mitre_data_cache.json"

# Paths to MITRE STIX JSON files
ENTERPRISE_ATTACK_PATH = r"C:\Users\youss\OneDrive\Desktop\Mitter Attack Data\enterprise-attack (1).json"
ICS_ATTACK_PATH        = r"C:\Users\youss\OneDrive\Desktop\Mitter Attack Data\ics-attack.json"
MOBILE_ATTACK_PATH     = r"C:\Users\youss\OneDrive\Desktop\Mitter Attack Data\mobile-attack.json"

def initialize_llm():
    llm = Llama(
        model_path=MODEL_PATH,
        n_ctx=27388,  # Context window size
        n_gpu_layers=-1  # Use GPU acceleration if available
    )
    return llm

def get_mitre_data():
    if os.path.exists(MITRE_DATA_CACHE):
        with open(MITRE_DATA_CACHE, 'r') as f:
            return json.load(f)
    else:
        filepaths = [
            ENTERPRISE_ATTACK_PATH,
            ICS_ATTACK_PATH,
            MOBILE_ATTACK_PATH
        ]

        all_techniques = []
        all_tactics = []

        # Load each STIX file and collect techniques/tactics
        for path in filepaths:
            if os.path.exists(path):
                mitre = MitreAttackData(stix_filepath=path)
                # Use the get_techniques() and get_tactics() methods
                all_techniques.extend(mitre.get_techniques())
                all_tactics.extend(mitre.get_tactics())
            else:
                print(f"Warning: STIX file not found at {path}")

        # Combine them into a single dictionary
        techniques = {}
        tactics = {}

        # Process techniques
        for technique in all_techniques:
            technique_id = technique.get('id', '')
            if not technique_id.startswith('attack-pattern--'):
                continue

            external_id = technique.get('external_references', [{}])[0].get('external_id', '')
            if not external_id:
                continue

            if external_id not in techniques:
                technique_data = {
                    'id': external_id,
                    'name': technique.get('name', ''),
                    'description': technique.get('description', ''),
                    'tactics': [],
                    'detection': technique.get('x_mitre_detection', ''),
                    'keywords': []
                }

                # Extract keywords for matching
                if technique_data['description']:
                    keywords = re.findall(r'\b[a-zA-Z]{4,}\b', technique_data['description'].lower())
                    technique_data['keywords'] = list(set(keywords))

                # Map kill_chain_phases to tactics
                if 'kill_chain_phases' in technique:
                    for phase in technique['kill_chain_phases']:
                        if phase.get('kill_chain_name') == 'mitre-attack':
                            technique_data['tactics'].append(phase.get('phase_name', ''))

                techniques[external_id] = technique_data

        # Process tactics
        for tactic in all_tactics:
            tactic_id = tactic.get('external_references', [{}])[0].get('external_id', '')
            if tactic_id and tactic_id not in tactics:
                tactics[tactic_id] = {
                    'id': tactic_id,
                    'name': tactic.get('name', ''),
                    'description': tactic.get('description', '')
                }

        mitre_data = {
            'techniques': techniques,
            'tactics': tactics
        }

        with open(MITRE_DATA_CACHE, 'w') as f:
            json.dump(mitre_data, f)

        return mitre_data

def process_logs(log_data, log_format):
    processed_data = []
    
    if log_format == "JSON":
        try:
            if isinstance(log_data, str):
                logs = json.loads(log_data)
            else:
                logs = log_data
            if isinstance(logs, dict):
                logs = [logs]
            for log in logs:
                event = {
                    'timestamp': log.get('deviceReceiptTime', log.get('endTime', '')),
                    'source_ip': log.get('sourceAddress', ''),
                    'dest_ip': log.get('destinationAddress', ''),
                    'username': log.get('sourceUserName', ''),
                    'event_name': log.get('name', ''),
                    'severity': log.get('agentSeverity', ''),
                    'device_action': log.get('deviceAction', ''),
                    'raw_message': json.dumps(log)
                }
                processed_data.append(event)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON format"}
    
    elif log_format == "CSV":
        try:
            csv_data = csv.DictReader(io.StringIO(log_data))
            for row in csv_data:
                event = {
                    'timestamp': row.get('deviceReceiptTime', row.get('endTime', '')),
                    'source_ip': row.get('sourceAddress', ''),
                    'dest_ip': row.get('destinationAddress', ''),
                    'username': row.get('sourceUserName', ''),
                    'event_name': row.get('name', ''),
                    'severity': row.get('agentSeverity', ''),
                    'device_action': row.get('deviceAction', ''),
                    'raw_message': str(row)
                }
                processed_data.append(event)
        except Exception as e:
            return {"error": f"CSV parsing error: {str(e)}"}
    
    elif log_format == "CEF":
        lines = log_data.strip().split('\n')
        for line in lines:
            if line.startswith("CEF:"):
                parts = line.split('|')
                if len(parts) >= 8:
                    extension = parts[7]
                    extension_pairs = {}
                    key_val_pattern = r'(\w+)=((?:[^ =]+)|(?:"[^"]+"))'
                    matches = re.finditer(key_val_pattern, extension)
                    
                    for match in matches:
                        key, value = match.groups()
                        extension_pairs[key] = value.strip('"')
                    
                    event = {
                        'timestamp': extension_pairs.get('rt', extension_pairs.get('end', '')),
                        'source_ip': extension_pairs.get('src', ''),
                        'dest_ip': extension_pairs.get('dst', ''),
                        'username': extension_pairs.get('suser', ''),
                        'event_name': parts[4] if len(parts) > 4 else '',
                        'severity': parts[6] if len(parts) > 6 else '',
                        'device_action': extension_pairs.get('act', ''),
                        'raw_message': line
                    }
                    processed_data.append(event)
    return processed_data

def map_to_mitre(processed_logs, mitre_data):
    mapped_techniques = {}
    techniques = mitre_data['techniques']
    
    for log in processed_logs:
        log_text = ' '.join([str(value).lower() for value in log.values() if value])
        
        for technique_id, technique in techniques.items():
            for keyword in technique['keywords']:
                if keyword in log_text and len(keyword) > 4:
                    if technique_id not in mapped_techniques:
                        mapped_techniques[technique_id] = {
                            'id': technique_id,
                            'name': technique['name'],
                            'description': technique['description'],
                            'tactics': technique['tactics'],
                            'matching_logs': []
                        }
                    if log not in mapped_techniques[technique_id]['matching_logs']:
                        mapped_techniques[technique_id]['matching_logs'].append(log)
    return list(mapped_techniques.values())

def generate_response_scenario(llm, log_data, mitre_mappings):
    prompt = f"""
    Based on the following security log data and MITRE ATT&CK mappings, 
    generate a detailed incident response scenario and recommendations:
    
    LOG DATA SUMMARY:
    - Number of events: {len(log_data)}
    - Event types: {', '.join(set([log.get('event_name', 'Unknown') for log in log_data if log.get('event_name')]))}
    - Source IPs: {', '.join(set([log.get('source_ip', '') for log in log_data if log.get('source_ip')]))}
    - Destination IPs: {', '.join(set([log.get('dest_ip', '') for log in log_data if log.get('dest_ip')]))}
    - Users involved: {', '.join(set([log.get('username', '') for log in log_data if log.get('username')]))}
    
    MITRE ATT&CK MAPPINGS:
    {json.dumps([{'id': m['id'], 'name': m['name'], 'tactics': m['tactics']} for m in mitre_mappings], indent=2)}
    
    Please provide a structured response with the following sections:
    
    1. THREAT ASSESSMENT:
    [Provide a concise threat classification based on the observed logs and MITRE ATT&CK techniques]
    
    2. POTENTIAL IMPACT:
    [Assess the potential business impact if this threat is not addressed]
    
    3. INCIDENT RESPONSE PROCEDURE:
    [Provide a step-by-step incident response procedure tailored to this specific threat]
    
    4. CONTAINMENT STRATEGY:
    [Recommend specific containment actions to isolate and mitigate the threat]
    
    5. RECOVERY RECOMMENDATIONS:
    [Suggest recovery steps to restore normal operations]
    
    6. PREVENTION MEASURES:
    [Recommend prevention measures to avoid similar incidents in the future]
    """
    
    response = llm(prompt, max_tokens=2048)
    return response['choices'][0]['text']

def main():
    st.set_page_config(page_title="Cybersecurity Incident Response Testing Tool", layout="wide")
    
    st.title("Cybersecurity Incident Response Testing Tool")
    st.markdown("### LLM-Powered Incident Response Scenario Generator with MITRE ATT&CK Integration")
    
    if 'llm' not in st.session_state:
        with st.spinner("Initializing LLM..."):
            st.session_state.llm = initialize_llm()
    
    if 'mitre_data' not in st.session_state:
        with st.spinner("Loading MITRE ATT&CK data..."):
            st.session_state.mitre_data = get_mitre_data()
    
    st.header("Log Data Input")
    upload_option = st.radio("Select input method:", ["Upload File", "Paste Text", "Sample Data"])
    
    log_data = None
    log_format = None
    
    if upload_option == "Upload File":
        uploaded_file = st.file_uploader("Upload ArcSight logs", type=["json", "csv", "txt"])
        if uploaded_file:
            log_format = st.selectbox("Select log format:", ["JSON", "CSV", "CEF"])
            if log_format == "JSON":
                log_data = json.load(uploaded_file)
            else:
                log_data = uploaded_file.getvalue().decode("utf-8")
    
    elif upload_option == "Paste Text":
        log_text = st.text_area("Paste log data here:", height=200)
        log_format = st.selectbox("Select log format:", ["JSON", "CSV", "CEF"])
        log_data = log_text
    
    elif upload_option == "Sample Data":
        sample_option = st.selectbox("Select sample scenario:", [
            "Brute Force Attack", 
            "Data Exfiltration", 
            "Privilege Escalation"
        ])
        
        if sample_option == "Brute Force Attack":
            log_format = "JSON"
            log_data = json.dumps([
                {
                    "deviceReceiptTime": "2023-09-15T02:14:22.000Z",
                    "sourceAddress": "192.168.1.100",
                    "destinationAddress": "10.0.0.5",
                    "sourceUserName": "unknown",
                    "name": "Authentication Failure",
                    "agentSeverity": "High",
                    "deviceAction": "Block",
                    "deviceEventClassId": "Authentication",
                    "message": "Failed login attempt from 192.168.1.100 - attempt 5 of 5"
                },
                {
                    "deviceReceiptTime": "2023-09-15T02:14:20.000Z",
                    "sourceAddress": "192.168.1.100",
                    "destinationAddress": "10.0.0.5",
                    "sourceUserName": "unknown",
                    "name": "Authentication Failure",
                    "agentSeverity": "Medium",
                    "deviceAction": "Block",
                    "deviceEventClassId": "Authentication",
                    "message": "Failed login attempt from 192.168.1.100 - attempt 4 of 5"
                },
                {
                    "deviceReceiptTime": "2023-09-15T02:14:18.000Z",
                    "sourceAddress": "192.168.1.100",
                    "destinationAddress": "10.0.0.5",
                    "sourceUserName": "unknown",
                    "name": "Authentication Failure",
                    "agentSeverity": "Medium",
                    "deviceAction": "Block",
                    "deviceEventClassId": "Authentication",
                    "message": "Failed login attempt from 192.168.1.100 - attempt 3 of 5"
                }
            ])
        
        elif sample_option == "Data Exfiltration":
            log_format = "JSON"
            log_data = json.dumps([
                {
                    "deviceReceiptTime": "2023-09-15T14:22:45.000Z",
                    "sourceAddress": "10.0.0.15",
                    "destinationAddress": "203.0.113.100",
                    "sourceUserName": "jsmith",
                    "name": "Large File Transfer",
                    "agentSeverity": "Medium",
                    "deviceAction": "Allow",
                    "bytesOut": "250000000",
                    "message": "Unusual data transfer detected - 250MB to external host"
                },
                {
                    "deviceReceiptTime": "2023-09-15T14:20:30.000Z",
                    "sourceAddress": "10.0.0.15",
                    "destinationAddress": "203.0.113.100",
                    "sourceUserName": "jsmith",
                    "name": "Access to Sensitive Data",
                    "agentSeverity": "Low",
                    "deviceAction": "Allow",
                    "message": "User accessed confidential customer database"
                },
                {
                    "deviceReceiptTime": "2023-09-15T14:15:22.000Z",
                    "sourceAddress": "10.0.0.15",
                    "destinationAddress": "10.0.0.5",
                    "sourceUserName": "jsmith",
                    "name": "Authentication Success",
                    "agentSeverity": "Info",
                    "deviceAction": "Allow",
                    "message": "User authenticated outside normal hours"
                }
            ])
        
        elif sample_option == "Privilege Escalation":
            log_format = "JSON"
            log_data = json.dumps([
                {
                    "deviceReceiptTime": "2023-09-15T10:45:22.000Z",
                    "sourceAddress": "10.0.0.22",
                    "destinationAddress": "10.0.0.5",
                    "sourceUserName": "serviceacct",
                    "name": "User Added to Admin Group",
                    "agentSeverity": "High",
                    "deviceAction": "Success",
                    "message": "User serviceacct added to Domain Admins group"
                },
                {
                    "deviceReceiptTime": "2023-09-15T10:44:15.000Z",
                    "sourceAddress": "10.0.0.22",
                    "destinationAddress": "10.0.0.5",
                    "sourceUserName": "jdoe",
                    "name": "PowerShell Command Execution",
                    "agentSeverity": "Medium",
                    "deviceAction": "Success",
                    "message": "PowerShell command executed with encoded parameters"
                },
                {
                    "deviceReceiptTime": "2023-09-15T10:40:05.000Z",
                    "sourceAddress": "10.0.0.22",
                    "destinationAddress": "10.0.0.5",
                    "sourceUserName": "jdoe",
                    "name": "Authentication Success",
                    "agentSeverity": "Low",
                    "deviceAction": "Success",
                    "message": "User successfully authenticated"
                }
            ])
    
    if log_data and log_format and st.button("Generate Response Scenario"):
        with st.spinner("Processing logs..."):
            processed_logs = process_logs(log_data, log_format)
            if isinstance(processed_logs, dict) and "error" in processed_logs:
                st.error(f"Error processing logs: {processed_logs['error']}")
            else:
                with st.spinner("Mapping to MITRE ATT&CK framework..."):
                    mitre_mappings = map_to_mitre(processed_logs, st.session_state.mitre_data)
                
                with st.spinner("Generating incident response scenario..."):
                    response_scenario = generate_response_scenario(
                        st.session_state.llm, 
                        processed_logs, 
                        mitre_mappings
                    )
                
                st.success("Response scenario generated!")
                
                tab1, tab2, tab3 = st.tabs(["Processed Logs", "MITRE ATT&CK Mapping", "Response Scenario"])
                
                with tab1:
                    st.subheader("Processed Log Events")
                    st.dataframe(pd.DataFrame(processed_logs))
                
                with tab2:
                    st.subheader("MITRE ATT&CK Mapping")
                    for technique in mitre_mappings:
                        with st.expander(f"**{technique['id']}**: {technique['name']}"):
                            st.markdown(f"**Description**: {technique['description']}")
                            st.markdown(f"**Tactics**: {', '.join(technique['tactics'])}")
                            st.markdown("**Matching Logs**:")
                            st.dataframe(pd.DataFrame(technique['matching_logs']))
                
                with tab3:
                    st.subheader("Incident Response Scenario")
                    st.markdown(response_scenario)
                    
                    export_format = st.selectbox("Export format:", ["Markdown", "JSON", "Text"])
                    if st.button("Export Scenario"):
                        if export_format == "Markdown":
                            content = f"# Incident Response Scenario\n\n{response_scenario}"
                            filename = f"incident_response_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
                        elif export_format == "JSON":
                            content = json.dumps({
                                "scenario": response_scenario,
                                "mitre_mappings": mitre_mappings,
                                "timestamp": datetime.now().isoformat()
                            }, indent=2)
                            filename = f"incident_response_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                        else:
                            content = response_scenario
                            filename = f"incident_response_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                        
                        st.download_button(
                            label="Download",
                            data=content,
                            file_name=filename,
                            mime="text/plain"
                        )

if __name__ == "__main__":
    main()
