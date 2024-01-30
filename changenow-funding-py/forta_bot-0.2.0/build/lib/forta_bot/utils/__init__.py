from web3 import Web3
from .assertions import assert_is_non_empty_string, assert_is_from_enum, assert_exists, assert_is_string_key_to_string_value_map
from .get_bot_id import GetBotId, provide_get_bot_id
from .get_chain_id import GetChainId, provide_get_chain_id
from .get_bot_owner import GetBotOwner, provide_get_bot_owner
from .get_forta_config import GetFortaConfig, FortaConfig, provide_get_forta_config
from .file_system import FileSystem
from .get_json_file import provide_get_json_file
from .sleep import Sleep
from .get_forta_api_url import GetFortaApiUrl, provide_get_forta_api_url
from .get_forta_api_headers import GetFortaApiHeaders, provide_get_forta_api_headers
from .bloom_filter import BloomFilter
from .sleep import Sleep, provide_sleep
from .get_aiohttp_session import provide_get_aiohttp_session, GetAioHttpSession
from .get_network_id import provide_get_network_id, GetNetworkId

def format_address(address) -> str:
    return address.lower() if type(address) == str else address

def hex_to_int(strVal: str) -> int:
    if not strVal or type(strVal) == int:
        return strVal
    return int(strVal, 16) if type(strVal) == str and strVal.startswith('0x') else int(strVal, 10)

def keccak256(val: str) -> str:
    return Web3.keccak(text=val).hex()

def snake_to_camel_case(val: str) -> str:
    if len(val) == 0 or "_" not in val:
        return val
    
    new_val = []
    should_capitalize = False
    for char in val:
        if char == "_":
            should_capitalize = True
            continue
        elif should_capitalize:
            new_val.append(char.capitalize())
            should_capitalize = False
        else:
            new_val.append(char)
    return ''.join(new_val)