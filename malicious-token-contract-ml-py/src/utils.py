from expiring_dict import ExpiringDict
from hexbytes import HexBytes
import requests
from web3 import Web3


from src.constants import (
    CONTRACT_SLOT_ANALYSIS_DEPTH,
    ERC721_SIGHASHES,
    ERC20_SIGHASHES,
    ERC1155_SIGHASHES,
    ERC777_SIGHASHES,
)
from src.logger import logger

GLOBAL_TOTAL_CONTRACT_DEPLOYMENT_COUNTER = ExpiringDict(ttl=86_400)
BOT_ID = "0x887678a85e645ad060b2f096812f7c71e3d20ed6ecf5f3acde6e71baa4cf86ad"


def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = w3.eth.get_code(Web3.toChecksumAddress(address))
    return code != HexBytes("0x")


def get_storage_addresses(w3, address) -> set:
    """
    this function returns the addresses that are references in the storage of a contract (first CONTRACT_SLOT_ANALYSIS_DEPTH slots)
    :return: address_list: list (only returning contract addresses)
    """
    if address is None:
        return set()

    address_set = set()
    for i in range(CONTRACT_SLOT_ANALYSIS_DEPTH):
        mem = w3.eth.get_storage_at(Web3.toChecksumAddress(address), i)
        if mem != HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        ):
            # looking at both areas of the storage slot as - depending on packing - the address could be at the beginning or the end.
            addr_on_left = mem[0:20].hex()
            addr_on_right = mem[12:].hex()
            if is_contract(w3, addr_on_left):
                address_set.add(Web3.toChecksumAddress(addr_on_left))
            if is_contract(w3, addr_on_right):
                address_set.add(Web3.toChecksumAddress(addr_on_right))

    return address_set


def get_contract_type(opcodes: str, function_sighashes: set) -> str:
    """
    this function determines contract type based on available sighashes.
    :return: contract_type: str
    """
    if function_sighashes.intersection(ERC777_SIGHASHES):
        return "erc777"
    elif function_sighashes.intersection(ERC1155_SIGHASHES):
        return "erc1155"
    elif function_sighashes.intersection(ERC721_SIGHASHES):
        return "erc721"
    elif function_sighashes.intersection(ERC20_SIGHASHES):
        return "erc20"
    elif "DELEGATECALL" in opcodes:
        return "proxy"
    else:
        return "non-token-or-proxy"


def get_features(w3, opcodes) -> list:
    """
    this function returns the opcodes + function hashes contained in the contract
    :return: features: list
    """
    features = []
    function_sighashes = set()
    opcode_addresses = set()

    for i, opcode in enumerate(opcodes):
        opcode_name = opcode.name
        # treat unique unknown and invalid opcodes as UNKNOWN OR INVALID
        if opcode_name.startswith("UNKNOWN") or opcode_name.startswith("INVALID"):
            opcode_name = opcode.name.split("_")[0]
        features.append(opcode_name)
        if len(opcode.operand) == 40 and is_contract(w3, opcode.operand):
            opcode_addresses.add(Web3.toChecksumAddress(f"0x{opcode.operand}"))

        if i < (len(opcodes) - 3):
            if (
                opcodes[i].name == "PUSH4"
                and opcodes[i + 1].name == "EQ"
                and opcodes[i + 2].name == "PUSH2"
                and opcodes[i + 3].name == "JUMPI"
            ):  # add function sighashes
                features.append(opcode.operand)
                function_sighashes.add(opcode.operand)
    features = " ".join(features)
    contract_type = get_contract_type(features, function_sighashes)

    return features, opcode_addresses, contract_type


def update_contract_deployment_counter(date_hour: str):
    # Total number of contract deployments in the last 24 hrs
    global GLOBAL_TOTAL_CONTRACT_DEPLOYMENT_COUNTER
    GLOBAL_TOTAL_CONTRACT_DEPLOYMENT_COUNTER[date_hour] = (
        GLOBAL_TOTAL_CONTRACT_DEPLOYMENT_COUNTER.get(date_hour, 0) + 1
    )


def alert_count(chain_id) -> int:
    alert_stats_url = (
        f"https://api.forta.network/stats/bot/{BOT_ID}/alerts?chainId={chain_id}"
    )
    alert_count = 0
    try:
        result = requests.get(alert_stats_url).json()
        alert_count = result["total"]["count"]
    except Exception as err:
        logger.error(f"Error obtaining alert counts: {err}")

    return alert_count


def get_anomaly_score(chain_id: int) -> float:
    total_alerts = alert_count(chain_id)
    total_tx_count = sum(GLOBAL_TOTAL_CONTRACT_DEPLOYMENT_COUNTER.values())
    return total_alerts / total_tx_count
