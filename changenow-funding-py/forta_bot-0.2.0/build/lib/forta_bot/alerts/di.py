from dependency_injector import containers, providers
from .send_alerts import provide_send_alerts
from .get_alerts import provide_get_alerts
from .create_alert_event import provide_create_alert_event
from .get_alert import provide_get_alert

class AlertsContainer(containers.DeclarativeContainer):
  common = providers.DependenciesContainer()

  create_alert_event = providers.Callable(provide_create_alert_event)
  send_alerts = providers.Callable(provide_send_alerts,
                                   get_aiohttp_session=common.get_aiohttp_session,
                                   get_forta_api_url=common.get_forta_api_url,
                                   get_forta_api_headers=common.get_forta_api_headers)
  get_alerts = providers.Callable(provide_get_alerts,
                                  get_aiohttp_session=common.get_aiohttp_session,
                                  get_forta_api_url=common.get_forta_api_url,
                                  get_forta_api_headers=common.get_forta_api_headers)
  get_alert = providers.Callable(provide_get_alert, get_alerts=get_alerts)