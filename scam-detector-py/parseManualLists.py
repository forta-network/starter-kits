import requests
import logging
import pandas as pd
import io
import traceback

res = requests.get('https://raw.githubusercontent.com/forta-network/starter-kits/Scam-Detector-ML/scam-detector-py/manual_alert_list.tsv')
logging.info(f"Manual finding: made request to fetch manual alerts: {res.status_code}")
content = res.content.decode('utf-8') if res.status_code == 200 else logging.info(f"Manual finding: failed to fetch manual alerts: {res.status_code}")

df_manual_findings = pd.read_csv(io.StringIO(content), sep='\t')
for index, row in df_manual_findings.iterrows():
    chain_id = -1
    try:
        chain_id_float = row['Chain ID']
        chain_id = int(chain_id_float)
    except Exception as e:
        logging.warning("Manual finding: Failed to get chain ID from manual finding")
        continue


    try:
        scammer_address_lower = row['Address'].lower().strip()

        threat_category = "unknown" if 'nan' in str(row["Threat category"]) else row['Threat category']
        alert_id_threat_category = threat_category.upper().replace(" ", "-")
        alert_id = "SCAM-DETECTOR-MANUAL-"+alert_id_threat_category
        tweet = "" if 'nan' in str(row["Tweet"]) else row['Tweet']
        account = "" if 'nan' in str(row["Account"]) else row['Account']
        logging.warning(f"Succesfully parsed manual finding: {alert_id} {scammer_address_lower} {chain_id} {tweet} {account}")
    except Exception as e:
        logging.warning(f"Manual finding: Failed to process manual finding: {e} : {traceback.format_exc()}")
        continue

try:
    res = requests.get('https://raw.githubusercontent.com/forta-network/starter-kits/main/scam-detector-py/fp_list.csv')
    content = res.content.decode('utf-8') if res.status_code == 200 else open('fp_list.csv', 'r').read()
    df_fp = pd.read_csv(io.StringIO(content), sep=',')
    for index, row in df_fp.iterrows():
        chain_id = int(row['chain_id'])
        cluster = row['address'].lower()
        for address in cluster.split(','):
            logging.warning(f"adding {address} to fp list")
except BaseException as e:
    logging.warning(f"emit fp finding exception: {e} - {traceback.format_exc()}")
