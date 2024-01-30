from typing import Optional, TypedDict
from .handle_block import HandleBlock
from .handle_transaction import  HandleTransaction

class ScanEvmOptions(TypedDict):
  rpc_url: str
  rpc_key_id: Optional[str]
  rpc_jwt_claims: Optional[dict]
  rpc_headers: Optional[dict]
  local_rpc_url: Optional[str]
  use_trace_data: Optional[bool]
  handle_block: Optional[HandleBlock]
  handle_transaction: Optional[HandleTransaction]