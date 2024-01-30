from typing import Optional, TypedDict


class FindingSourceChain(TypedDict):
    chain_id: int

class FindingSourceBlock(TypedDict):
    chain_id: int
    hash: str
    number: int

class FindingSourceTransaction(TypedDict):
    chain_id: int
    hash: str

class FindingSourceUrl(TypedDict):
    url: str

class FindingSourceAlert(TypedDict):
    id: str

class FindingSourceCustom(TypedDict):
    name: str
    value: str

class FindingSource(TypedDict):
    chains: Optional[list[FindingSourceChain]]
    blocks: Optional[list[FindingSourceBlock]]
    transactions: Optional[list[FindingSourceTransaction]]
    urls: Optional[list[FindingSourceUrl]]
    alerts: Optional[list[FindingSourceAlert]]
    custom_sources: Optional[list[FindingSourceCustom]]