from typing import Optional
import json
from ..utils import BloomFilter
from ..labels import Label


class Alert:
    def __init__(self, dict):
        self.addresses: list[str] = dict.get('addresses')
        self.alert_id: str = dict.get('alertId')
        self.contracts: list[AlertContract] = dict.get('contracts', [])
        self.created_at: str = dict.get('createdAt')
        self.description: str = dict.get('description')
        self.finding_type: str = dict.get('findingType')
        self.name: str = dict.get('name')
        self.hash: str = dict.get('hash')
        self.protocol: str = dict.get('protocol')
        self.severity: str = dict.get('severity')
        self.source: AlertSource = dict.get('source')
        self.metadata: dict = dict.get('metadata')
        self.projects: list[AlertProject] = dict.get('projects')
        self.scan_node_count: int = dict.get('scanNodeCount')
        self.alert_document_type: str = dict.get('alertDocumentType')
        self.related_alerts: list[str] = dict.get('relatedAlerts')
        self.chain_id: int = dict.get('chainId')
        self.labels: list[Label] = list(map(lambda t: Label(t), dict.get('labels', [])))
        self.address_filter: Optional[BloomFilter] = BloomFilter(dict.get('addressBloomFilter')) if dict.get(
            'addressBloomFilter') is not None else None

    def has_address(self, address):
        if self.address_filter is not None:
            return self.address_filter.has(address)
        elif self.addresses is not None:
            return address in self.addresses
        return False

    def __repr__(self):
        return json.dumps({k: v for k, v in self.__dict__.items() if v}, indent=4, default=str)


class AlertSource:
    def __init__(self, dict):
        self.transaction_hash = dict.get('transactionHash')
        self.block = AlertSourceBlock(dict.get('block')) if dict.get(
            'block') is not None else None
        self.bot = AlertSourceBot(dict.get('bot')) if dict.get(
            'bot') is not None else None
        self.source_alert = AlertSourceAlert(dict.get('sourceAlert')) if dict.get(
            'sourceAlert') is not None else None


class AlertSourceBlock:
    def __init__(self, dict):
        self.timestamp = dict.get('timestamp')
        self.chain_id = dict.get('chainId')
        self.hash = dict.get('hash')
        self.number = dict.get('number')


class AlertSourceBot:
    def __init__(self, dict):
        self.id = dict.get('id')
        self.reference = dict.get('reference')
        self.image = dict.get('image')


class AlertSourceAlert:
    def __init__(self, dict):
        self.hash = dict.get('hash')
        self.bot_id = dict.get('botId')
        self.timestamp = dict.get('timestamp')
        self.chain_id = dict.get('chainId')


class AlertContract:
    def __init__(self, dict):
        self.address = dict.get('address')
        self.name = dict.get('name')
        self.project_id = dict.get('projectId')


class AlertProject:
    def __init__(self, dict):
        self.id = dict.get('id')
        self.name = dict.get('name')
        self.contacts = AlertProjectContacts(dict.get('contacts')) if dict.get(
            'contacts') is not None else None
        self.website = dict.get('website')
        self.token = AlertProjectToken(dict.get('token')) if dict.get(
            'token') is not None else None
        self.social = ProjectSocial(dict.get('social')) if dict.get(
            'social') is not None else None


class AlertProjectContacts:
    def __init__(self, dict):
        self.security_email_address = dict.get('securityEmailAddress')
        self.general_email_address = dict.get('generalEmailAddress')


class AlertProjectToken:
    def __init__(self, dict):
        self.symbol = dict.get('symbol')
        self.name = dict.get('name')
        self.decimals = dict.get('decimals')
        self.chain_id = dict.get('chainId')
        self.address = dict.get('address')


class ProjectSocial:
    def __init__(self, dict):
        self.twitter = dict.get('twitter')
        self.github = dict.get('github')
        self.everest = dict.get('everest')
        self.coingecko = dict.get('coingecko')
