import json
from datetime import datetime
from typing import Optional, TypedDict
from ..utils import assert_is_non_empty_string, assert_is_from_enum, assert_is_string_key_to_string_value_map
from ..labels import Label
from .finding_severity import FindingSeverity
from .finding_type import FindingType
from .finding_source import FindingSource

class FindingInput(TypedDict):
    name: str
    description: str
    alert_id: str
    severity: FindingSeverity
    type: FindingType
    protocol: Optional[str]
    metadata: Optional[dict]
    addresses: Optional[list[str]]
    labels: Optional[list[Label]]
    unique_key: Optional[str]
    source: Optional[FindingSource]
    timestamp: datetime

class Finding:
    def __init__(self, dict: FindingInput):
        self.name = assert_is_non_empty_string(dict.get('name'), 'name')
        self.description = assert_is_non_empty_string(dict.get('description'), 'description')
        self.alert_id = assert_is_non_empty_string(dict.get('alert_id'), 'alert_id')
        self.severity = assert_is_from_enum(dict.get('severity'), FindingSeverity, 'severity')
        self.type = assert_is_from_enum(dict.get('type'), FindingType, 'type')
        self.metadata = assert_is_string_key_to_string_value_map(dict.get('metadata'), 'metadata')
        self.addresses = dict.get('addresses')
        self.labels = list(map(lambda l: l if isinstance(
            l, Label) else Label(l), dict.get('labels', [])))
        self.unique_key = dict.get('unique_key')
        self.source = dict.get('source')
        self.timestamp = dict.get('timestamp', datetime.now())
    
    def __repr__(self):
        return json.dumps({k: v for k, v in self.__dict__.items() if v}, indent=4, default=str)