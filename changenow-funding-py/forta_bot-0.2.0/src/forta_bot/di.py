import os
from os import path
from dependency_injector import containers, providers
from .jwt import JwtContainer
from .utils import FileSystem, provide_get_forta_config, provide_get_json_file, provide_get_bot_id, provide_get_forta_api_url, provide_get_forta_api_headers, provide_sleep, provide_get_aiohttp_session, provide_get_chain_id, provide_get_bot_owner, provide_get_network_id
from .scanning import ScanningContainer
from .cli import CliContainer
from .alerts import AlertsContainer
from .blocks import BlocksContainer
from .transactions import TransactionsContainer
from .handlers import HandlersContainer
from .traces import TracesContainer
from .logs import LogsContainer
from .health import HealthContainer


class CommonContainer(containers.DeclarativeContainer):
  forta_global_root = providers.Object(path.expanduser('~/.forta'))
  is_prod = providers.Object(True if os.environ.get('FORTA_ENV') == 'production' or os.environ.get('NODE_ENV') == 'production' else False)
  is_running_cli_command = providers.Object(True if 'FORTA_CLI' in os.environ else False)
  config_filename = providers.Object('forta.config.json')
  local_config_filename = providers.Object(os.environ['FORTA_CONFIG'] if 'FORTA_CONFIG' in os.environ else config_filename())
  context_path = providers.Object(os.environ['FORTA_CONTEXT_PATH'] if 'FORTA_CONTEXT_PATH' in os.environ else os.getcwd())
  args = providers.Object({})# TODO
  get_aiohttp_session = providers.Callable(provide_get_aiohttp_session)
  file_system = providers.Factory[FileSystem](FileSystem)
  get_json_file = providers.Callable(provide_get_json_file)
  sleep = providers.Callable(provide_sleep)
  get_forta_config = providers.Callable(provide_get_forta_config,
                                        file_system=file_system,
                                        is_prod=is_prod,
                                        config_filename=config_filename,
                                        local_config_filename=local_config_filename,
                                        forta_global_root=forta_global_root,
                                        get_json_file=get_json_file,
                                        context_path=context_path)
  forta_config = providers.Object(get_forta_config()())
  forta_chain_id = providers.Object[int](int(os.environ['FORTA_CHAIN_ID']) if 'FORTA_CHAIN_ID' in os.environ else None)
  forta_bot_owner = providers.Object(os.environ.get('FORTA_BOT_OWNER'))
  forta_shard_id = providers.Object(int(os.environ['FORTA_SHARD_ID']) if 'FORTA_SHARD_ID' in os.environ else None)
  forta_shard_count = providers.Object(int(os.environ['FORTA_SHARD_COUNT']) if 'FORTA_SHARD_COUNT' in os.environ else None)

  get_bot_id = providers.Callable(provide_get_bot_id, args=args, forta_config=forta_config)
  get_chain_id = providers.Callable(provide_get_chain_id, forta_chain_id=forta_chain_id)
  get_bot_owner = providers.Callable(provide_get_bot_owner, forta_bot_owner=forta_bot_owner)
  get_forta_api_url = providers.Callable(provide_get_forta_api_url, forta_config=forta_config)
  get_forta_api_headers = providers.Callable(provide_get_forta_api_headers, forta_config=forta_config)
  get_network_id = providers.Callable(provide_get_network_id)


class RootContainer(containers.DeclarativeContainer):
  common = providers.Container(CommonContainer)
  transactions = providers.Container(TransactionsContainer)
  traces = providers.Container(TracesContainer)
  logs = providers.Container(LogsContainer)
  blocks = providers.Container(BlocksContainer, traces=traces, logs=logs, transactions=transactions)
  jwt = providers.Container(JwtContainer, common=common)
  alerts = providers.Container(AlertsContainer, common=common)
  handlers = providers.Container(HandlersContainer, blocks=blocks, transactions=transactions, alerts=alerts, traces=traces, logs=logs)
  cli = providers.Container(CliContainer, common=common, transactions=transactions, handlers=handlers)
  scanning = providers.Container(ScanningContainer, common=common, jwt=jwt, cli=cli, alerts=alerts, blocks=blocks, transactions=transactions, handlers=handlers)
  health = providers.Container(HealthContainer)