import os
from dependency_injector import containers, providers
from .decode_jwt import provide_decode_jwt
from .verify_jwt import provide_verify_jwt
from .get_scanner_jwt import provide_get_scanner_jwt
from .get_rpc_jwt import provide_get_rpc_jwt
from .get_token_exchange_url import provide_get_token_exchange_url


class JwtContainer(containers.DeclarativeContainer):
  common = providers.DependenciesContainer()
  
  forta_jwt_provider_host = providers.Object(
    os.environ['FORTA_JWT_PROVIDER_HOST'] if 'FORTA_JWT_PROVIDER_HOST' in os.environ else "forta-jwt-provider"
  )
  forta_jwt_provider_port = providers.Object(os.environ['FORTA_JWT_PROVIDER_PORT'] if 'FORTA_JWT_PROVIDER_PORT' in os.environ else 8515)

  get_token_exchange_url = providers.Callable(provide_get_token_exchange_url, forta_config=common.forta_config)
  decode_jwt = providers.Callable(provide_decode_jwt)
  verify_jwt = providers.Callable(provide_verify_jwt)
  get_scanner_jwt = providers.Callable(provide_get_scanner_jwt, 
                                       get_aiohttp_session=common.get_aiohttp_session, 
                                       is_prod=common.is_prod, 
                                       forta_jwt_provider_host=forta_jwt_provider_host,
                                       forta_jwt_provider_port=forta_jwt_provider_port)
  get_rpc_jwt = providers.Callable(provide_get_rpc_jwt,  
                                   get_aiohttp_session=common.get_aiohttp_session,
                                   get_scanner_jwt=get_scanner_jwt, 
                                   get_token_exchange_url=get_token_exchange_url)