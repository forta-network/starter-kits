from os import path
from typing import Callable, TypedDict, Optional
from .file_system import FileSystem
from .get_json_file import GetJsonFile

class FortaConfig(TypedDict):
  botId: Optional[str]
  agentId: Optional[str]
  ipfsGatewayUrl: Optional[str]
  ipfsGatewayAuth: Optional[str]
  imageRepositoryUrl: Optional[str]
  imageRepositoryUsername: Optional[str]
  imageRepositoryPassword: Optional[str]
  botRegistryAddress: Optional[str]
  polygonJsonRpcUrl: Optional[str]
  debug: Optional[bool]
  keyfile: Optional[str]
  keyfilePassword: Optional[str]
  fortaApiUrl: Optional[str]
  fortaApiKey: Optional[str]
  fortTokenAddress: Optional[str]
  stakingAddress: Optional[str]
  tokenExchangeUrl: Optional[str]
  shouldStopOnErrors: Optional[str]
  localRpcUrls: Optional[dict]

GetFortaConfig = Callable[[], FortaConfig]

def provide_get_forta_config(
    file_system: FileSystem,
    is_prod: bool,
    config_filename: str,
    local_config_filename: str,
    forta_global_root: str,
    get_json_file: GetJsonFile,
    context_path: str
) -> GetFortaConfig:

  def get_forta_config() -> FortaConfig:
    config = {}
    global_config_path = path.join(forta_global_root, config_filename)
    global_config_exists = file_system.exists(global_config_path)
    local_config_path = path.join(context_path, local_config_filename)
    local_config_exists = file_system.exists(local_config_path)
    no_config_exists = not global_config_exists and not local_config_exists

    # config file will not exist when running "init" or when running in production
    if no_config_exists or is_prod: return config

    # try to read global config file
    if global_config_exists:
      try:
        config = {**config, **get_json_file(global_config_path)}
      except Exception as e:
        raise Exception(f'unable to parse config file {config_filename}: {e}')
    
    # try to read from local (project-specific) config file
    if local_config_exists:
      try:
        config = {**config, **get_json_file(local_config_path)}
      except Exception as e:
        raise Exception(f'unable to parse project config file {local_config_filename}: {e}')
    
    return config
  return get_forta_config