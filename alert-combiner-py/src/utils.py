from web3 import Web3
from hexbytes import HexBytes
import requests
import re
import logging
import json

etherscan_label_api = "https://api.forta.network/labels/state?sourceIds=etherscan,0x6f022d4a65f397dffd059e269e1c2b5004d822f905674dbf518d968f744c2ede&entities="

class Utils:
    CONTRACT_CACHE = dict()
    TOTAL_SHARDS = None
    IS_BETA = None

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
                if len(labels) > 0:
                    return labels['events'][0]['label']['label']
        except Exception as e:
            logging.warning(f"Exception in get_etherscan_label {e}")
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
         
