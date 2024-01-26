from web3 import Web3
from hexbytes import HexBytes
import requests
import re
import traceback
import logging
import json
import base64
import math
import gnupg
from forta_agent import Finding, FindingType, FindingSeverity, AlertEvent, get_alerts, get_labels

from src.error_cache import ErrorCache
from src.constants import TX_COUNT_FILTER_THRESHOLD
from src.fp_mitigation.fp_mitigator import FPMitigator
from src.constants import FP_THRESHOLD

etherscan_label_api = "https://api.forta.network/labels/state?sourceIds=etherscan,0x6f022d4a65f397dffd059e269e1c2b5004d822f905674dbf518d968f744c2ede&entities="

class Utils:
    ERROR_CACHE = ErrorCache
    CONTRACT_CACHE = dict()
    TOTAL_SHARDS = None
    IS_BETA = None
    gpg = None

    @staticmethod
    def decrypt_alert_event(w3, alert_event: AlertEvent, private_key:str) -> AlertEvent:
        if Utils.gpg is None:
            logging.info("Importing private keys into GPG")
    
            Utils.gpg =  gnupg.GPG(gnupghome='.')
            import_result = Utils.gpg.import_keys(private_key)
            if len(import_result.fingerprints) == 0:
                logging.info("Imported no private key into GPG")
    
            for fingerprint in import_result.fingerprints:
                Utils.gpg.trust_keys(fingerprint, 'TRUST_ULTIMATE')
                logging.info(f"Imported private key {fingerprint} into GPG")
    
        if alert_event.alert.name == 'omitted' and 'data' in alert_event.alert.metadata.keys():
            base64_encoded_string = alert_event.alert.metadata['data']
            logging.info(f"Decrypting alert. Data length of base64 value: {len(base64_encoded_string)}. Private key length {len(private_key)}")

            #base64 decode
            encrypted_finding_ascii = base64.b64decode(base64_encoded_string).decode('utf-8')
            logging.info(f"Decrypting finding. Data length: {len(encrypted_finding_ascii)}. Private key length {len(private_key)}")
            
            decrypted_finding_json = Utils.gpg.decrypt(encrypted_finding_ascii)
            logging.info(f"Decrypted finding. Data length: {len(str(decrypted_finding_json))}")
            if len(str(decrypted_finding_json)) > 0:
                finding_dict = json.loads(str(decrypted_finding_json))
                logging.info(finding_dict)

                finding_dict['severity'] = FindingSeverity(finding_dict['severity'])
                finding_dict['type'] = FindingType(finding_dict['type'])
                finding_dict['alert_id'] = finding_dict['alertId']

                # this is all blocksec specific; if additional partners are onboarded this needs to be refactored
                addresses = set()
                tx_hash = ''
                if 'txhash' in finding_dict['metadata'].keys():
                    tx_hash = finding_dict['metadata']['txhash']
                    tx_receipt = w3.eth.get_transaction_receipt(tx_hash)
                    if 'logs' in tx_receipt.keys():
                        for log in tx_receipt['logs']:
                            if 'address' in log.keys():
                                logging.info(f"adding address {log['address']} to addresses")
                                addresses.add(log['address'])

               
                if 'addresses' in finding_dict.keys():
                    for address in finding_dict['addresses']:
                        addresses.add(address)
                for val in finding_dict['metadata'].values():
                    if len(val) == 42 and val.startswith('0x'):
                        addresses.add(val)

                finding = Finding(finding_dict)
                alert_event.alert.name = finding.name
                alert_event.alert.description = finding.description
                alert_event.alert.severity = FindingSeverity(finding.severity)
                alert_event.alert.finding_type = FindingType(finding.type)
                alert_event.alert.metadata = finding.metadata
                alert_event.alert.alert_id = finding.alert_id
                alert_event.alert.addresses = list(addresses)
                alert_event.alert.labels = finding.labels
    
        return alert_event

    @staticmethod
    def is_contract(w3, addresses) -> bool:
        """
        this function determines whether address/ addresses is a contract; if all are contracts, returns true; otherwise false
        :return: is_contract: bool
        """
        if addresses is None:
            return True

        if Utils.CONTRACT_CACHE.get(addresses) is not None:
            return Utils.CONTRACT_CACHE[addresses]
        else:
            is_contract = True
            try:
                for address in addresses.split(','):
                    code = w3.eth.get_code(Web3.toChecksumAddress(address))
                    is_contract = is_contract & (code != HexBytes('0x'))
                Utils.CONTRACT_CACHE[addresses] = is_contract
            except Exception as e:
                error_finding = Utils.alert_error(str(e), "Utils.is_contract", f"{traceback.format_exc()}")
                Utils.ERROR_CACHE.add(error_finding)
                logging.error(f"Exception in assessing is_contract for address(es) {addresses}: {e}")

            return is_contract
        
    @staticmethod
    def is_address(addresses: str) -> bool:
        """
        this function determines whether address is a valid address
        :return: is_address: bool
        """
        if addresses is None:
            return True

        is_address = True
        for address in addresses.split(','):
            if re.search(r'([a-f0-9])\1{8}', address.lower()):
                is_address = False

        return is_address

    @staticmethod
    def get_etherscan_label(address: str):
        if address is None:
            return ""
            
        try:
            res = requests.get(etherscan_label_api + address.lower())
            if res.status_code == 200:
                labels = res.json()
                if labels and len(labels.get('events', [])) > 0:
                     return labels['events'][0]['label']['label']
        except Exception as e:
            error_finding = Utils.alert_error(str(e), "Utils.get_etherscan_label", f"{traceback.format_exc()}")
            Utils.ERROR_CACHE.add(error_finding)
            logging.error(f"Exception in get_etherscan_label {e}")
        return ""

    @staticmethod
    def get_total_shards(CHAIN_ID: int) -> int:
        if Utils.TOTAL_SHARDS is None:
            logging.debug("getting total shards")
            package = json.load(open("package.json"))
            logging.debug("loaded package.json")
            logging.debug(f"getting shard count for chain id {CHAIN_ID}")
            if str(CHAIN_ID) in package["chainSettings"]:   
                logging.debug(f"have specific shard count value for chain id {CHAIN_ID}")
                total_shards = package["chainSettings"][str(CHAIN_ID)]["shards"]
            else:
                logging.debug("have specific shard count value for default")
                total_shards = package["chainSettings"]["default"]["shards"]
            logging.debug(f"total shards: {total_shards}")
            Utils.TOTAL_SHARDS = total_shards
        return Utils.TOTAL_SHARDS
    
    @staticmethod
    def is_beta() -> str:
        if Utils.IS_BETA is None:
            logging.debug("getting bot version from package.json")
            package = json.load(open("package.json"))
            logging.debug("loaded package.json")
            Utils.IS_BETA = 'beta' in package["name"]
        return Utils.IS_BETA
    
    @staticmethod
    def sanitize(msg: str) -> str:
        # replace any key value pairs where key contains 'key' with 'X'ex for the value
        # e.g. description&apiKey=foobar&test=foo to description&apiKey=XXXXXX&test=foo

        msg_arr = msg.split('&')
        for i in range(len(msg_arr)):
            if 'key' in msg_arr[i].lower() and '=' in msg_arr[i]:
                msg_arr[i] = msg_arr[i].split('=')[0] + '=XXXXXX'
        msg_sanatized = '&'.join(msg_arr)
        return msg_sanatized
    
    @staticmethod
    def alert_error(error_description: str, error_source: str, error_stacktrace: str) -> Finding:

        labels = []
        
        return Finding({
            'name': 'Attack detector encountered a recoverable error.',
            'description': f'Error: {Utils.sanitize(error_description)}',
            'alert_id': 'DEBUG-ERROR',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {
                'error_source': Utils.sanitize(error_source),
                'error_stacktrace': Utils.sanitize(error_stacktrace)
            },
            'labels': labels
        })
    

    @staticmethod
    def get_max_tx_count(w3, cluster: str) -> int:
        max_transaction_count = 0
        for address in cluster.split(','):
            transaction_count = w3.eth.get_transaction_count(Web3.toChecksumAddress(address))
            if transaction_count > max_transaction_count:
                max_transaction_count = transaction_count
        return max_transaction_count
    
    @staticmethod
    def is_fp_reactive(w3, du, dynamo, cluster: str) -> bool:
        global ERROR_CACHE
    
        etherscan_label = (Utils.get_etherscan_label(cluster)).lower()
        if not ('attack' in etherscan_label
                or 'phish' in etherscan_label
                or 'hack' in etherscan_label
                or 'heist' in etherscan_label
                or 'exploit' in etherscan_label
                or 'drainer' in etherscan_label
                or 'scam' in etherscan_label
                or 'fraud' in etherscan_label
                or '.eth' in etherscan_label
                or etherscan_label == ''):
            logging.info(f"Cluster {cluster} etherscan label: {etherscan_label}")
            return True

        
        if cluster in du.read_fp_mitigation_clusters(dynamo):
            logging.info(f"Cluster {cluster} is in FP mitigation clusters")
            return True

        return False
    
    @staticmethod
    def process_past_alerts(alerts, reactive_likely_fps: dict):
        unique_attackers = set()
        try:
            for alert in alerts:
                if alert.alert_id not in ["FP-MITIGATED-ATTACK", "ATTACK-DETECTOR-FALSE-POSITIVE"]:
                    attacker_address = alert.metadata.get('attackerAddress')
                    if attacker_address is not None and attacker_address not in reactive_likely_fps:
                        unique_attackers.add(attacker_address)
        except Exception as e:
            logging.warning(f"process_past_alerts (attacker address missing): {e} - {traceback.format_exc()}")
            Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "agent.process_past_alerts", traceback.format_exc()))
        return list(unique_attackers)
    
    
    @staticmethod
    def fetch_labels(unique_attackers_list, source_id, get_labels_created_since_timestamp_ms):
        labels = []
        starting_cursor = None
        should_retry_from_error = False
        labels_response = None
        batch_size = 200
        page_size = 1000

        for i in range(0, len(unique_attackers_list), batch_size):
            batch = unique_attackers_list[i:i + batch_size]

            while True:
                if labels_response and labels_response.page_info and labels_response.page_info.has_next_page:
                    starting_cursor = labels_response.page_info.end_cursor
                    should_retry_from_error = False

                try:
                    query = {
                        "entities": batch,
                        "source_ids": [source_id],
                        "labels": ["attacker-eoa", "attacker-contract"],
                        "created_since": get_labels_created_since_timestamp_ms,
                        "state": True,
                        "first": page_size,
                        "starting_cursor": starting_cursor
                    }

                    labels_response = get_labels(query)
                    labels.extend(labels_response.labels)
                except Exception as e:
                    if (isinstance(e, AttributeError) and 'NoneType' in str(e)) or (isinstance(e, Exception) and "Internal server error" in str(e)):
                        # Reduce the page size in order to reduce the response size and try again
                        page_size = math.floor(page_size / 2)
                        should_retry_from_error = page_size > 1
                    else:
                        logging.warning("update reactive likely fps (get_labels error): {e} - {traceback.format_exc()}")
                        Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "agent.update_reactive_likely_fps.internal3", traceback.format_exc()))
                        raise e

                if not should_retry_from_error and not labels_response.page_info.has_next_page:
                    break

        return labels
    
    @staticmethod
    def fetch_alerts(source_id, start_milliseconds_ago, end_milliseconds_ago, CHAIN_ID):
        response = None
        starting_cursor = None
        should_retry_from_error = False
        page_size = 1200
        alerts = []

        while True:
                if response and response.page_info and response.page_info.has_next_page:
                    starting_cursor = {
                        'alertId': response.page_info.end_cursor.alert_id,
                        'blockNumber': response.page_info.end_cursor.block_number
                    }
                    should_retry_from_error = False
                try:
                    query = {
                        "bot_ids": [source_id],
                        "created_since": start_milliseconds_ago,
                        "created_before": end_milliseconds_ago,
                        "starting_cursor": starting_cursor,
                        "chain_id": CHAIN_ID,
                        "first": page_size
                    }
                    response = get_alerts(query)
                    alerts.extend(response.alerts)
                except Exception as e:
                    if  (isinstance(e, AttributeError) and 'NoneType' in str(e)) or (isinstance(e, Exception) and "Internal server error" in str(e)):
                        # Reduce the page size in order to reduce the response size and try again
                        page_size = math.floor(page_size / 2)
                        should_retry_from_error = page_size > 1
                    else:
                        logging.warning(f"fetch_alerts (get_alerts error): {e} - {traceback.format_exc()}")
                        Utils.ERROR_CACHE.add(Utils.alert_error(str(e), "agent.fetch_alerts", traceback.format_exc()))
                if (not should_retry_from_error and response.page_info.end_cursor.alert_id == ""):
                    break

        return alerts
         
    @staticmethod
    def is_fp(w3, scammer_address_lower=None, fp_mitigator: FPMitigator = None) -> (bool, float):
        if FPMitigator is not None and scammer_address_lower is not None :
            predicted_value_fp = fp_mitigator.mitigate_fp(scammer_address_lower)
            logging.info(f"FP Mitigation for address {scammer_address_lower}: {predicted_value_fp}")
            if predicted_value_fp is not None and predicted_value_fp > FP_THRESHOLD:
                return True, predicted_value_fp 
        return False, None
