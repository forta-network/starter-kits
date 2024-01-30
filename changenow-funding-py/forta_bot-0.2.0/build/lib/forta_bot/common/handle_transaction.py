from typing import Callable
from web3 import AsyncWeb3
from ..findings import Finding
from ..transactions import TransactionEvent

HandleTransaction = Callable[[TransactionEvent, AsyncWeb3.AsyncHTTPProvider], list[Finding]]