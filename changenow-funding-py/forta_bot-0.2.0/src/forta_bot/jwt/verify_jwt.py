import json
import base64
from datetime import datetime
from web3 import Web3, AsyncWeb3
from typing import Callable, Optional


VerifyJwt = Callable[[str, Optional[str]], bool]

DISPATCH_CONTRACT = "0xd46832F3f8EA8bDEFe5316696c0364F01b31a573"
DISPATCH_CONTRACT_ABI = [{"inputs": [{"internalType": "uint256", "name": "agentId", "type": "uint256"}, {"internalType": "uint256", "name": "scannerId", "type": "uint256"}],
                    "name": "areTheyLinked", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "view", "type": "function"}]

def provide_verify_jwt() -> VerifyJwt:

  async def verify_jwt(token: str, polygon_url: str = 'https://polygon-rpc.com') -> bool:
    split_jwt = token.split('.')
    raw_header = split_jwt[0]
    raw_payload = split_jwt[1]
    raw_signature = split_jwt[2]

    header = json.loads(base64.urlsafe_b64decode(raw_header + '==').decode('utf-8'))
    payload = json.loads(base64.urlsafe_b64decode(raw_payload + '==').decode('utf-8'))
    signature = base64.urlsafe_b64decode(f'{raw_signature}=').hex()

    alg = header['alg']
    bot_id = payload['bot-id']
    expires_at = payload['exp']
    scanner_address = payload['sub']

    if scanner_address is None or bot_id is None:
        print('invalid claim')
        return False

    if alg != 'ETH':
        print('unexpected signing method: {alg}'.format(alg=alg))
        return False

    now = int(datetime.now().timestamp())
    if expires_at < now:
        print('jwt expired')
        return False

    msg = f'{raw_header}.{raw_payload}'
    recovered_address = Web3().eth.account.recover_message(msg, signature=signature)
    if recovered_address != scanner_address:
        print(f'signature invalid: expected={scanner_address}, got={recovered_address}')
        return False

    w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(polygon_url))
    contract = w3.eth.contract(address=DISPATCH_CONTRACT, abi=DISPATCH_CONTRACT_ABI)
    is_bot_and_scanner_linked = await contract.functions.areTheyLinked(int(bot_id, 0), int(scanner_address, 0)).call()
    return is_bot_and_scanner_linked

  return verify_jwt