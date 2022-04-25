import time

import requests
import pandas as pd
from forta_agent import Finding, FindingType, FindingSeverity
from .utils import create_finding

LUABASE_URL = "https://api.luabase.com/run"
ETHERSCAN_UPDATE_CADENCE = 60 * 60 # every 1 hr
ETHERSCAN_BLOCKLIST_PATH = './etherscan_blocklist.csv'
etherscan_blocklist_update_at = 1650564930 # 04-21-2022


def update_etherscan_blocklist():
    payload = {"uuid": "d28e0444cf554438a7ada7d377c2d3e1"}
    headers = {"content-type": "application/json"}
    try:
        print(f'updating blocklist: {ETHERSCAN_BLOCKLIST_PATH}')
        response = requests.request("POST", LUABASE_URL, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        df = pd.DataFrame.from_dict(data['data'])
        df.to_csv(ETHERSCAN_BLOCKLIST_PATH, index=None)
    except requests.exceptions.HTTPError as err:
        print(err)


def provide_handle_transaction():
    def handle_transaction(transaction_event):
        global etherscan_blocklist_update_at

        findings = []

        addresses = transaction_event.addresses

        blocklist = pd.read_csv(ETHERSCAN_BLOCKLIST_PATH)
        matches = blocklist.loc[blocklist.banned_address.isin(addresses)].drop_duplicates(subset=["banned_address"], keep='first').fillna("")

        for _, match in matches.iterrows():
            blocklisted_address = match.banned_address
            wallet_tag = match.wallet_tag
            data_source = match.data_source
            description_msg = f'Transaction involving a blocklisted address: {blocklisted_address}'

            if wallet_tag:
                description_msg += f' with wallet tag: {wallet_tag}'

            finding = create_finding(blocklisted_address, description_msg, wallet_tag, data_source)
            findings.append(finding)

        # update list
        now = time.time()
        if now - etherscan_blocklist_update_at >= ETHERSCAN_UPDATE_CADENCE:
            update_etherscan_blocklist()
            etherscan_blocklist_update_at = now

        return findings
    return handle_transaction

real_handle_transaction = provide_handle_transaction()

def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
