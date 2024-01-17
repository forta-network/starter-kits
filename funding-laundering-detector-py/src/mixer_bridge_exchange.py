import re
import requests


def check_is_mixer_bridge_exchange(address, is_eoa, chain_id):
    """
    This function is used to parse the explorer and check if address is mixer, bridge, cex, dex
    :param address:
    :param is_eoa:
    :param chain_id:
    :return:
    """
    if chain_id == 1:
        base_url = "https://etherscan.io/address/"
    elif chain_id == 137:
        base_url = "https://polygonscan.com/address/"
    elif chain_id == 10:
        base_url = "https://optimistic.etherscan.io/address/"
    elif chain_id == 56:
        base_url = "https://bscscan.com/address/"
    elif chain_id == 250:
        base_url = "https://ftmscan.com/address/"
    elif chain_id == 42161:
        base_url = "https://arbiscan.io/address/"
    else:
        base_url = "https://etherscan.io/address/"

    headers_etherscan = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-GB,en;q=0.5',
        'Referer': 'https://etherscan.io/txs',
        'Alt-Used': 'etherscan.io',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
    }

    try:
        response = requests.get(f'{base_url}{address.lower()}', headers=headers_etherscan)
        re_exchange = re.compile(r"\b(?:exchange|Exchange)\b")
        number_of_word_exchange = len(re_exchange.findall(response.text))
        re_bridge = re.compile(r"\b(?:bridge|Bridge)\b")
        number_of_word_bridge = len(re_bridge.findall(response.text))
        re_dex = re.compile(r"\b(?:Decentralized Exchange|decentralized exchange|dex|DEX)\b")
        number_of_word_dex = len(re_dex.findall(response.text))

        if number_of_word_bridge > number_of_word_exchange and not is_eoa:
            return 'bridge'
        elif is_eoa:
            return 'exchange'
        elif not is_eoa and number_of_word_dex > 2:
            return 'dex'
        else:
            return 'mixer'

    except Exception as e:
        print(f"Unable to check the type of the address ({address}): {e}")
        return 'unknown'
