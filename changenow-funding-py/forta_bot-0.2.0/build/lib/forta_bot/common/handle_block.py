from typing import Callable
from web3 import AsyncWeb3
from ..blocks import BlockEvent
from ..findings import Finding

HandleBlock = Callable[[BlockEvent, AsyncWeb3.AsyncHTTPProvider], list[Finding]]