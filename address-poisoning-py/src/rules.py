from hexbytes import HexBytes
from forta_agent import Web3
from src.constants import *
import logging


class AddressPoisoningRules:

    @staticmethod
    def is_contract(w3, address):
        """
        this function determines whether address is a contract
        :return: is_contract: bool
        """
        if address is None:
            return True
        code = w3.eth.get_code(Web3.toChecksumAddress(address))
        return code != HexBytes('0x')


    @staticmethod
    def have_addresses_been_detected(transaction_event, zero_value_contracts, low_value_contracts, fake_token_contracts):
        """
        check if sender and receiver have previously been identified as phishing addresses
        :return: have_addresses_been_detected: bool
        """
        if transaction_event.to in zero_value_contracts:
            return "ADDRESS-POISONING-ZERO-VALUE"
        elif transaction_event.to in low_value_contracts:
            return "ADDRESS-POISONING-LOW-VALUE"
        elif transaction_event.to in fake_token_contracts:
            return "ADDRESS-POISONING-FAKE-TOKEN"
        else:
            return ""


    @staticmethod
    def are_all_logs_stablecoins(logs, chain_id):
        stablecoin_count = 0

        if len(logs) == 0:
            return 0

        for log in logs:
            if str.lower(log['address']) in STABLECOIN_CONTRACTS[chain_id]:
                stablecoin_count += 1

        return (1.0 * stablecoin_count) / len(logs)


    @staticmethod    
    def are_all_logs_transfers_or_approvals(logs):
        approval_hash = HexBytes("0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925")
        transfer_hash = HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")

        approval_logs = [log for log in logs if log['topics'][0] == approval_hash]
        transfer_logs = [log for log in logs if log['topics'][0] == transfer_hash]

        if (
            len(approval_logs) + len(transfer_logs) == len(logs)
            and len(transfer_logs) > 0
        ):
            return True
        else:
            return False

    
    @staticmethod
    def is_zero_value_tx(logs, chain_id):

        for log in logs:
            if (str.lower(log['address']) in STABLECOIN_CONTRACTS[chain_id]
                and log['data'] == "0x0000000000000000000000000000000000000000000000000000000000000000"):
                continue
            else:
                return False
        return True

    
    @staticmethod
    def is_data_field_repeated(logs):
        data_fields = [log['data'] for log in logs]

        if (len(set(data_fields)) > (len(data_fields)/2)
        or "0x0000000000000000000000000000000000000000000000000000000000000000" in data_fields):
            return False
        
        return True


    @staticmethod
    def are_tokens_using_known_symbols(w3, logs, chain_id):
        contracts = set([log['address'] for log in logs])
        valid_contracts = 0

        for address in contracts:
            if str.lower(address) in STABLECOIN_CONTRACTS[chain_id] or address in BASE_TOKENS:
                valid_contracts += 1
            else:
                try:
                    contract = w3.eth.contract(address=Web3.toChecksumAddress(address), abi=SYMBOL_CALL_ABI)
                    symbol = contract.functions.symbol().call()
                    if chain_id == 1:
                        ord_symbol = [ord(char) for char in symbol]
                        if ord_symbol in CHAIN_ORDINAL_SYMBOL_MAP[1]:
                            continue
                        else:
                            logging.info("Exiting because failed to match ordinal")
                            return False
                    else:
                        if symbol in OFFICIAL_SYMBOLS[chain_id]:
                            continue
                        else:
                            logging.info("Exiting because failed to match symbol")
                            return False
                except Exception as e:
                    logging.warn(f"Failed to retrieve symbol info for {address} with exception {e}")
                    return False


        if valid_contracts == len(contracts):
            logging.info("Exiting because all contracts are valid")
            return False

        return True


    @staticmethod
    def are_tokens_minted(logs):
        null_hash = HexBytes('0x0000000000000000000000000000000000000000000000000000000000000000')

        for log in logs:
            if null_hash in log["topics"]:
                logging.info("Detected null address in logs...")
                return True
            else:
                continue
        
        return False