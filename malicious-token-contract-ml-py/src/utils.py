from hexbytes import HexBytes
from web3 import Web3


from constants import CONTRACT_SLOT_ANALYSIS_DEPTH, MASK
from logger import logger

BOT_ID = "0xf0490edadc1cd6eb2cc02e78508fbbcd6e08ea835a8fef0e399b336017fee3c8"


async def is_contract(w3, address) -> bool:
    """
    this function determines whether address is a contract
    :return: is_contract: bool
    """
    if address is None:
        return True
    code = await w3.eth.get_code(w3.to_checksum_address(address))
    return code != HexBytes("0x")


async def get_storage_addresses(w3, address) -> set:
    """
    this function returns the addresses that are references in the storage of a contract (first CONTRACT_SLOT_ANALYSIS_DEPTH slots)
    :return: address_list: list (only returning contract addresses)
    """
    if address is None:
        return set()

    address_set = set()
    for i in range(CONTRACT_SLOT_ANALYSIS_DEPTH):
        mem = await w3.eth.get_storage_at(w3.to_checksum_address(address), i)
        if mem != HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        ):
            # looking at both areas of the storage slot as - depending on packing - the address could be at the beginning or the end.
            addr_on_left = mem[0:20].hex()
            addr_on_right = mem[12:].hex()
            if await is_contract(w3, addr_on_left):
                address_set.add(w3.to_checksum_address(addr_on_left))
            if await is_contract(w3, addr_on_right):
                address_set.add(w3.to_checksum_address(addr_on_right))

    return address_set


async def get_features(w3, opcodes, contract_creator) -> list:
    """
    this function returns the contract opcodes
    :return: features: list
    """
    features = []
    opcode_addresses = set()

    for i, opcode in enumerate(opcodes):
        opcode_name = opcode.name
        # treat unique unknown and invalid opcodes as UNKNOWN OR INVALID
        if opcode_name.startswith("UNKNOWN") or opcode_name.startswith("INVALID"):
            opcode_name = opcode.name.split("_")[0]
        features.append(opcode_name)
        if len(opcode.operand) == 40 and await is_contract(w3, opcode.operand):
            opcode_addresses.add(w3.to_checksum_address(f"0x{opcode.operand}"))

        if opcode_name == "PUSH20":
            if opcode.operand == contract_creator:
                features.append("creator")
            elif opcode.operand == MASK:
                features.append(MASK)
            else:
                features.append("addr")

    features = " ".join(features)

    return features, opcode_addresses
