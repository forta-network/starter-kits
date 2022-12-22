from cachetools import cached, TTLCache
from hexbytes import HexBytes
import requests
from web3 import Web3


from src.constants import (
    CONTRACT_SLOT_ANALYSIS_DEPTH,
    ERC721_SIGHASHES,
    ERC20_SIGHASHES,
    ERC1155_SIGHASHES,
    ERC777_SIGHASHES,
    CHAIN_ID_METADATA_MAPPING,
    LUABASE_SUPPORTED_CHAINS,
)
from src.luabase_constants import (
    LUABASE_API_KEY,
    LUABASE_URL,
    ANOMALY_SCORE_QUERY_ID,
    ALERT_COUNT_QUERY_ID,
    BOT_ID,
)
from src.logger import logger


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


def luabase_request(chain_name, bot_id, query_uuid):
    headers = {"content-type": "application/json"}
    payload = {
        "api_key": LUABASE_API_KEY,
        "block": {
            "data_uuid": query_uuid,
            "details": {
                "parameters": {
                    "chain": {"type": "value", "value": chain_name},
                    "bot_id": {"type": "value", "value": bot_id},
                }
            },
        },
    }
    data = None
    try:
        response = requests.request("POST", LUABASE_URL, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()["data"][0]
    except requests.exceptions.HTTPError as err:
        logger.info(f"Luabase error: {err}")
    return data


# cache anomaly scores for no longer than 30 minutes
@cached(cache=TTLCache(maxsize=10, ttl=1800))
def get_anomaly_score(chain_id):
    anomaly_score = 0
    alert_count = 0
    (
        chain_name,
        default_alert_count,
        default_contract_deployment,
    ) = CHAIN_ID_METADATA_MAPPING[chain_id]
    if chain_id in LUABASE_SUPPORTED_CHAINS:
        result = luabase_request(chain_name, BOT_ID, ANOMALY_SCORE_QUERY_ID)
        if result is not None:
            anomaly_score = round(result["anomaly_score"], 3)

    if anomaly_score == 0:
        result = luabase_request(chain_name, BOT_ID, ALERT_COUNT_QUERY_ID)
        if result is not None:
            alert_count = round(result["alert_count"], 3)
        alert_count = alert_count if alert_count > 0 else default_alert_count
        anomaly_score = round(alert_count / default_contract_deployment, 5)

    return anomaly_score
