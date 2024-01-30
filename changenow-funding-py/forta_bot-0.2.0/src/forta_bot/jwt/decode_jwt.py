import base64
import json
from typing import Any, Callable, TypedDict

class DecodedJwt(TypedDict):
    header: dict
    payload: dict

DecodeJwt = Callable[[str], DecodedJwt]

def provide_decode_jwt() -> DecodeJwt:
    
  def decode_jwt(token):
      # Add 4 bytes for pythons b64decode
      header = json.loads(base64.urlsafe_b64decode(
          token.split('.')[0] + '==').decode('utf-8'))
      payload = json.loads(base64.urlsafe_b64decode(
          token.split('.')[1] + '==').decode('utf-8'))

      return {
          "header": header,
          "payload": payload
      }
  
  return decode_jwt