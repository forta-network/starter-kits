from typing import Optional
from ..utils import hex_to_int, format_address


class Transaction:
    def __init__(self, dict):
        self.hash: str = dict.get('hash')
        self.from_: str = format_address(dict.get('from'))
        self.to: Optional[str] = format_address(dict.get('to')) if dict.get('to') is not None else None
        self.nonce: int = dict.get('nonce')
        self.gas: int = hex_to_int(dict.get('gas'))
        self.gas_price: int = hex_to_int(dict.get('gasPrice', dict.get('gas_price')))
        self.value: int = hex_to_int(dict.get('value'))
        self.data: str = dict.get('data', dict.get('input'))
        self.r: str = dict.get('r')
        self.s: str = dict.get('s')
        self.v: str = dict.get('v')
