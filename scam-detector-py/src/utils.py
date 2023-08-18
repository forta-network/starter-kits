
from web3 import Web3
from hexbytes import HexBytes
from forta_agent import get_labels, Label, Finding, FindingSeverity, FindingType, AlertEvent
import requests
import logging
import io
import rlp
import base64
import gnupg
import pandas as pd
import json
import os
import traceback
from web3 import Web3
from forta_agent import get_json_rpc_url

from src.constants import TX_COUNT_FILTER_THRESHOLD
from src.error_cache import ErrorCache
from src.storage import get_secrets

class Utils:
    ERROR_CACHE = ErrorCache

    ETHERSCAN_LABEL_SOURCE_IDS = ['etherscan','0x6f022d4a65f397dffd059e269e1c2b5004d822f905674dbf518d968f744c2ede']
    FP_MITIGATION_ADDRESSES = set()
    CONTRACT_CACHE = dict()
    BOT_VERSION = None
    TOTAL_SHARDS = None
    IS_BETA = None

    RPC_ENDPOINT = None
    TEST_STATE = False

    @staticmethod
    def in_test_state() -> bool:
        return Utils.TEST_STATE


    @staticmethod
    def get_fp_list() -> pd.DataFrame:
        content = open('fp_list_test.csv', 'r').read() if Utils.in_test_state() else open('fp_list.csv', 'r').read()
        if not Utils.in_test_state():
            res = requests.get('https://raw.githubusercontent.com/forta-network/starter-kits/main/scam-detector-py/fp_list.csv')
            logging.info(f"Manual finding: made request to fetch manual fp list: {res.status_code}")
            content = res.content.decode('utf-8') if res.status_code == 200 else open('fp_list.csv', 'r').read()

        df_fps = pd.read_csv(io.StringIO(content), sep=',')
        return df_fps

    @staticmethod
    def get_manual_list() -> pd.DataFrame:
        content = open('manual_alert_list_test.tsv', 'r').read() if Utils.in_test_state() else open('manual_alert_list.tsv', 'r').read()
        if not Utils.in_test_state():
            res = requests.get('https://raw.githubusercontent.com/forta-network/starter-kits/main/scam-detector-py/manual_alert_list.tsv')
            logging.info(f"Manual finding: made request to fetch manual alerts: {res.status_code}")
            content = res.content.decode('utf-8') if res.status_code == 200 else open('manual_alert_list.tsv', 'r').read()

        df_manual_findings = pd.read_csv(io.StringIO(content), sep='\t')
        return df_manual_findings

    @staticmethod
    def get_metamask_phishing_list() -> list:
        if Utils.in_test_state():
            with open('test_phishing_list.json', 'r') as file:
                return json.load(file).get('blacklist', [])
            
        res = requests.get('https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/config.json')
        logging.info(f"Metamask phishing list: made request to fetch metamask phishing list: {res.status_code}")
        if res.status_code == 200:
            config_json = json.loads(res.content)
            if 'blacklist' in config_json:
                return config_json['blacklist']
        return []


    @staticmethod
    def get_rpc_endpoint():
        if Utils.RPC_ENDPOINT is None:
            web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))

            chain_id = -1
            try:
                chain_id_temp = os.environ.get('FORTA_CHAIN_ID')
                if chain_id_temp is None:
                    chain_id = web3.eth.chain_id
                else:
                    chain_id = int(chain_id_temp)
            except Exception as e:
                raise e

            secrets = get_secrets()
            if chain_id == 1:
                url = secrets['jsonRpc']['ethereum']
            elif chain_id == 137:
                url = secrets['jsonRpc']['polygon']
            elif chain_id == 10:
                url = secrets['jsonRpc']['optimism']
            elif chain_id == 42161:
                url = secrets['jsonRpc']['arbitrum']
            # elif chain_id == 43114:
            #     url = secrets['jsonRpc']['avalanche']
            else:
                url = get_json_rpc_url()

            Utils.RPC_ENDPOINT = Web3(Web3.HTTPProvider(url))

        return Utils.RPC_ENDPOINT

    @staticmethod
    def get_code(w3, address) -> str:
        code = w3.eth.get_code(Web3.toChecksumAddress(address))
        return code.hex()

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
            for address in addresses.split(','):
                code = w3.eth.get_code(Web3.toChecksumAddress(address))
                is_contract = is_contract & (code != HexBytes('0x'))
            Utils.CONTRACT_CACHE[addresses] = is_contract
            return is_contract
        
    @staticmethod
    def is_address(w3, addresses: str) -> bool:
        """
        this function determines whether address is a valid address
        :return: is_address: bool
        """
        if addresses is None:
            return True

        is_address = True
        for address in addresses.split(','):
            for c in ['a', 'b', 'c', 'd', 'e', 'f', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']:
                test_str = c + c + c + c + c + c + c + c + c  # make a string of length 9; I know this is ugly, but regex didnt work
                if test_str in address.lower():
                    is_address = False

        return is_address

    @staticmethod
    def get_etherscan_label(cluster: str) -> list:
        if cluster is None:
            return ""

        labels_str = []

        response = get_labels({'entities': [cluster],
                    'sourceIds': Utils.ETHERSCAN_LABEL_SOURCE_IDS,
                    'state': True})
        labels = response.labels
        for label in labels:
            if label.source.bot is None or label.source.bot.id in Utils.ETHERSCAN_LABEL_SOURCE_IDS:
                logging.info(f"retreived label for {cluster}: {label.label}")
                labels_str.append(label.label)
        
        return labels_str

    @staticmethod
    def get_max_tx_count(w3, cluster: str) -> int:
        max_transaction_count = 0
        for address in cluster.split(','):
            transaction_count = w3.eth.get_transaction_count(Web3.toChecksumAddress(address))
            if transaction_count > max_transaction_count:
                max_transaction_count = transaction_count
        return max_transaction_count

    @staticmethod
    def update_fp_list(CHAIN_ID: int):
        df_fp = Utils.get_fp_list()
        for index, row in df_fp.iterrows():
            chain_id = int(row['chain_id'])
            if chain_id != CHAIN_ID:
                continue
            cluster = row['address'].lower()
            Utils.FP_MITIGATION_ADDRESSES.add(cluster)

    @staticmethod
    def alert_error(error_description: str, error_source: str, error_stacktrace: str) -> Finding:

        labels = []
        
        return Finding({
            'name': 'Scam detector encountered a recoverable error.',
            'description': f'{error_description}',
            'alert_id': 'DEBUG-ERROR',
            'type': FindingType.Info,
            'severity': FindingSeverity.Info,
            'metadata': {
                'error_source': error_source,
                'error_stacktrace': error_stacktrace
            },
            'labels': labels
        })

    @staticmethod
    def is_fp(w3, cluster: str) -> bool:
        global ERROR_CACHE

        etherscan_label = ','.join(Utils.get_etherscan_label(cluster)).lower()
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

        tx_count = 0
        try:
            tx_count = Utils.get_max_tx_count(w3, cluster)
        except BaseException as e:
            error_finding = Utils.alert_error(str(e), "Utils.get_max_tx_count", f"{traceback.format_exc()}")
            Utils.ERROR_CACHE.add(error_finding)
            logging.error(f"Exception in assessing get_transaction_count for cluster {cluster}: {e}")

        if tx_count > TX_COUNT_FILTER_THRESHOLD:
            logging.info(f"Cluster {cluster} transacton count: {tx_count}")
            return True

        if Utils.is_in_fp_mitigation_list(cluster):
            logging.info(f"Cluster {cluster} is in fp mitigation list")
            return True

        return False

    @staticmethod
    def is_in_fp_mitigation_list(cluster: str) -> bool:
        if cluster in Utils.FP_MITIGATION_ADDRESSES:
            logging.info(f"Cluster {cluster} in FP mitigation list")
            return True

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
    def get_bot_version() -> str:
        if Utils.BOT_VERSION is None:
            logging.debug("getting bot version from package.json")
            package = json.load(open("package.json"))
            logging.debug("loaded package.json")
            Utils.BOT_VERSION = package["version"]
        return Utils.BOT_VERSION
    
    @staticmethod
    def is_beta() -> str:
        if Utils.IS_BETA is None:
            logging.debug("getting bot version from package.json")
            package = json.load(open("package.json"))
            logging.debug("loaded package.json")
            Utils.IS_BETA = 'beta' in package["name"]
        return Utils.IS_BETA
        
    @staticmethod
    def get_shard(CHAIN_ID: int, timestamp: int) -> int:
        logging.debug(f"getting shard for timestamp {timestamp}")
        total_shards = Utils.get_total_shards(CHAIN_ID)
        shard = int(timestamp % total_shards)
        logging.debug(f"shard: {shard}")
        return shard
    
    @staticmethod
    def calc_contract_address(w3, address, nonce) -> str:
        """
        this function calculates the contract address from sender/nonce
        :return: contract address: str
        """

        address_bytes = bytes.fromhex(address[2:].lower())
        return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])

    gpg = None

    @staticmethod
    def decrypt_alert(encrypted_finding_ascii:str, private_key:str) -> Finding:
        if Utils.gpg is None:
            Utils.gpg =  gnupg.GPG(gnupghome='.')
            import_result = Utils.gpg.import_keys(private_key)
            for fingerprint in import_result.fingerprints:
                Utils.gpg.trust_keys(fingerprint, 'TRUST_ULTIMATE')
    
        decrypted_finding_json = Utils.gpg.decrypt(encrypted_finding_ascii)
        finding_dict = json.loads(str(decrypted_finding_json))

        finding_dict['severity'] = FindingSeverity(finding_dict['severity'])
        finding_dict['type'] = FindingType(finding_dict['type'])
        finding_dict['alert_id'] = finding_dict['alertId']

        labels_new = []
        labels = finding_dict['labels']
        for label in labels:
            if label['entity'] != '':
                labels_new.append(label)
        finding_dict['labels'] = labels_new
        
        return Finding(finding_dict)

    @staticmethod
    def decrypt_alert_event(alert_event: AlertEvent, private_key:str) -> AlertEvent:
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
            encrypted_finding_ascii = alert_event.alert.metadata['data']
            logging.info(f"Decrypting finding. Data length: {len(encrypted_finding_ascii)}. Private key length {len(private_key)}")
            
            decrypted_finding_json = Utils.gpg.decrypt(encrypted_finding_ascii)
            logging.info(f"Decrypted finding. Data length: {len(str(decrypted_finding_json))}")
            if len(str(decrypted_finding_json)) > 0:
                finding_dict = json.loads(str(decrypted_finding_json))

                finding_dict['severity'] = FindingSeverity(finding_dict['severity'])
                finding_dict['type'] = FindingType(finding_dict['type'])
                finding_dict['alert_id'] = finding_dict['alertId']

                labels_new = []
                labels = finding_dict['labels']
                for label in labels:
                    if label['entity'] != '':
                        labels_new.append(label)
                finding_dict['labels'] = labels_new
            
                finding = Finding(finding_dict)

                alert_event.alert.name = finding.name
                alert_event.alert.description = finding.description
                alert_event.alert.severity = FindingSeverity(finding.severity)
                alert_event.alert.finding_type = FindingType(finding.type)
                alert_event.alert.metadata = finding.metadata
                alert_event.alert.alert_id = finding.alert_id
                alert_event.alert.labels = finding.labels
        
        return alert_event