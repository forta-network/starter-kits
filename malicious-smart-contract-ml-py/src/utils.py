from expiring_dict import ExpiringDict
from hexbytes import HexBytes
import requests
from web3 import Web3


from src.constants import CONTRACT_SLOT_ANALYSIS_DEPTH

from src.logger import logger

GLOBAL_TOTAL_CONTRACT_DEPLOYMENT_COUNTER = ExpiringDict(ttl=86_400)
BOT_ID = "0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91"


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


def get_opcode_addresses(w3, opcodes) -> set:
    """
    this function returns the addresses that are references in the opcodes of a contract
    :return: address_list: list (only returning contract addresses)
    """
    address_set = set()
    for op in opcodes.splitlines():
        for param in op.split(" "):
            if param.startswith("0x") and len(param) == 42:
                if is_contract(w3, param):
                    address_set.add(Web3.toChecksumAddress(param))

    return address_set


def get_features(opcodes) -> list:
    """
    this function returns the opcodes contained in the contract
    :return: features: list
    """
    features = []
    for op in opcodes.splitlines():
        opcode = op.split(" ")[0].strip() if op else ""
        if opcode:
            # treat unique unknown and invalid opcodes as UNKNOWN OR INVALID
            if opcode.startswith("UNKNOWN") or opcode.startswith("INVALID"):
                opcode = opcode.split("_")[0]
            features.append(opcode)

    return " ".join(features)


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
