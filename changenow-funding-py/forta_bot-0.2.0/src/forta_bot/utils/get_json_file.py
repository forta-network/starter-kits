import os
from typing import Callable
from jsonc_parser.parser import JsoncParser


GetJsonFile = Callable[[str], dict]

def provide_get_json_file() -> GetJsonFile:

  def get_json_file(path: str) -> dict:
    if path.startswith(f'.{os.sep}'):
      path = path.replace(f'.{os.sep}', f'{os.getcwd()}{os.sep}')
    return JsoncParser.parse_file(path)
  
  return get_json_file