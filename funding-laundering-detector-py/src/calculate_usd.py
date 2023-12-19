import requests
from web3 import Web3
import json

global top_currencies_info
global top_currencies_info_back

with open("./src/gecko_tokens.json", 'r') as file:
    gecko_tokens = json.load(file)


def update_top_currencies_info(initial_values=None):
    """
    Request latest prices from Gecko API
    :return:
    """
    global top_currencies_info
    global top_currencies_info_back

    try:
        headers = {
            'accept': 'application/json',
        }

        params = {
            'vs_currency': 'usd',
            'order': 'market_cap_desc',
            'per_page': '250',
            'page': '1',
            'sparkline': 'false',
        }

        response = requests.get('https://api.coingecko.com/api/v3/coins/markets', params=params, headers=headers)
        top_currencies_info = response.json()
        for tci in top_currencies_info:
            if tci['id'] == 'bitcoin':
                with open("./src/gecko_initial.json", 'w') as gecko_initial_file:  # get abi from the file
                    json.dump(top_currencies_info, gecko_initial_file)
                break

    except Exception as e:
        if initial_values:
            top_currencies_info = initial_values
        else:
            print(f"Error trying to get the tokens using Gecko API: {e}")
            top_currencies_info = top_currencies_info_back
    top_currencies_info_back = top_currencies_info


def calculate_usd_and_get_symbol(web3, token_address, erc20_abi, amount):
    """
    This function is responsible for calling erc20 functions like symbols and decimals to be able to calculate the price
    using data from Gecko
    :param web3:
    :param token_address:
    :param erc20_abi:
    :param amount:
    :return:
    """
    try:
        global top_currencies_info

        token_contract = web3.eth.contract(address=Web3.toChecksumAddress(token_address), abi=erc20_abi)
        symbol = token_contract.functions.symbol().call().lower()
        decimals = token_contract.functions.decimals().call()
        amount = amount / 10 ** decimals

        token_price = None
        # Search the token in the top 250
        for tci in top_currencies_info:
            if tci['symbol'] == symbol:
                token_price = tci['current_price']
                break

        total_in_usd = 0

        # If the token is hidden gem then we need advanced search...
        if token_price:
            total_in_usd = amount * token_price
        else:
            for token in gecko_tokens:
                if token['symbol'] == symbol:
                    id_ = token['id']

                    headers = {
                        'accept': 'application/json',
                    }

                    params = {
                        'ids': id_,
                        'vs_currencies': 'usd',
                    }

                    response = requests.get('https://api.coingecko.com/api/v3/simple/price', params=params,
                                            headers=headers)

                    token_price = response.json().get(id_, {}).get('usd', 0)
                    total_in_usd = amount * token_price

        return total_in_usd, symbol
    except Exception as e:
        return 0, 'NOT_ERC20'


def calculate_usd_for_base_token(amount, chain_id):
    """
    Calculate tx value in USD for the native token
    :param amount:
    :param chain_id:
    :return:
    """
    global top_currencies_info

    if chain_id == 1:
        symbol = 'eth'
        decimals = 18
    elif chain_id == 137:
        symbol = 'matic'
        decimals = 18
    elif chain_id == 10:
        symbol = 'eth'
        decimals = 18
    elif chain_id == 56:
        symbol = 'bnb'
        decimals = 18
    elif chain_id == 250:
        symbol = 'ftm'
        decimals = 18
    elif chain_id == 42161:
        symbol = 'eth'
        decimals = 18
    else:
        symbol = 'eth'
        decimals = 18

    token_price = 0
    try:
        for tci in top_currencies_info:
            if tci['symbol'] == symbol:
                token_price = tci['current_price']
                break
    except:
        print("Something was wrong with gecko API")

    amount = amount / 10 ** decimals
    total_in_usd = amount * token_price
    return total_in_usd, symbol
