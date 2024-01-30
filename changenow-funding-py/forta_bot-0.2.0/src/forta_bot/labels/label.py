import json
from ..utils import assert_is_non_empty_string, assert_is_from_enum
from .label_entity_type import EntityType
from .label_source import LabelSource

class Label:
    def __init__(self, dict):
        entityTypeVal = dict.get('entity_type', dict.get('entityType'))
        self.entity_type = EntityType[entityTypeVal.title()] if type(
            entityTypeVal) == str else EntityType(entityTypeVal)
        assert_is_from_enum(self.entity_type, EntityType, 'entityType')
        self.entity = assert_is_non_empty_string(dict.get('entity'), 'entity')
        self.confidence = dict['confidence']
        self.label = dict['label']
        self.remove = dict.get('remove', False)
        self.unique_key = dict.get('unique_key', dict.get('uniqueKey'))
        self.metadata = dict.get('metadata') if dict.get(
            'metadata') is not None else {}
        # if metadata is array, convert to map
        if type(self.metadata) is list:
            self.metadata_array_to_map()
        self.id = dict.get('id')
        self.source = LabelSource(dict.get('source')) if dict.get(
            'source') is not None else None
        self.created_at = dict.get('createdAt', dict.get('created_at'))
        self.embedding = dict.get('embedding')

    def metadata_array_to_map(self):
        # convert string array to string key/value map using first '=' character as separator
        # (label metadata is received as string array from API)
        metadata_map = {}
        for item in self.metadata:
            separator_index = item.find('=')
            key = item[0:separator_index]
            value = item[separator_index+1:len(item)]
            metadata_map[key] = value
        self.metadata = metadata_map

    def __repr__(self):
        return json.dumps({k: v for k, v in self.__dict__.items() if v}, indent=4, default=str)
