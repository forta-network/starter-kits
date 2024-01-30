from dependency_injector import containers, providers
from .evm.get_provider import provide_get_provider
from .evm.scan_evm import provide_scan_evm
from .alerts.get_alerts_for_subscriptions import provide_get_alerts_for_subscriptions
from .alerts.scan_alerts import provide_scan_alerts
from .should_submit_findings import provide_should_submit_findings
from .should_stop_on_errors import provide_should_stop_on_errors

class ScanningContainer(containers.DeclarativeContainer):
  common = providers.DependenciesContainer()
  jwt = providers.DependenciesContainer()
  cli = providers.DependenciesContainer()
  alerts = providers.DependenciesContainer()
  blocks = providers.DependenciesContainer()
  transactions = providers.DependenciesContainer()
  handlers = providers.DependenciesContainer()

  should_submit_findings = providers.Callable(provide_should_submit_findings, is_prod=common.is_prod)
  should_stop_on_errors = providers.Callable(provide_should_stop_on_errors, is_prod=common.is_prod, forta_config=common.forta_config)

  # evm module
  get_provider = providers.Callable(provide_get_provider, 
                                    get_rpc_jwt=jwt.get_rpc_jwt, 
                                    decode_jwt=jwt.decode_jwt,
                                    forta_config=common.forta_config,
                                    is_prod=common.is_prod)
  scan_evm = providers.Callable(provide_scan_evm,
                                get_bot_id=common.get_bot_id,
                                get_provider=get_provider,
                                get_network_id=common.get_network_id,
                                is_running_cli_command=common.is_running_cli_command,
                                run_cli_command=cli.run_cli_command,
                                get_latest_block_number=blocks.get_latest_block_number,
                                run_handlers_on_block=handlers.run_handlers_on_block,
                                send_alerts=alerts.send_alerts,
                                should_submit_findings=should_submit_findings,
                                should_stop_on_errors=should_stop_on_errors,
                                sleep=common.sleep,
                                forta_chain_id=common.forta_chain_id,
                                forta_shard_id=common.forta_shard_id,
                                forta_shard_count=common.forta_shard_count)

  # alerts module
  get_alerts_for_subscriptions = providers.Callable(provide_get_alerts_for_subscriptions,
                                                    get_alerts=alerts.get_alerts)
  scan_alerts = providers.Callable(provide_scan_alerts,
                                   is_running_cli_command=common.is_running_cli_command,
                                   run_cli_command=cli.run_cli_command,
                                   get_bot_id=common.get_bot_id,
                                   get_alerts_for_subscriptions=get_alerts_for_subscriptions,
                                   run_handlers_on_alert=handlers.run_handlers_on_alert,
                                   send_alerts=alerts.send_alerts,
                                   should_submit_findings=should_submit_findings,
                                   should_stop_on_errors=should_stop_on_errors,
                                   sleep=common.sleep,
                                   forta_shard_id=common.forta_shard_id,
                                   forta_shard_count=common.forta_shard_count)
  