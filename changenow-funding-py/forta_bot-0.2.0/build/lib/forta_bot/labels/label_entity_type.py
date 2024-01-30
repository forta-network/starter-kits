from enum import IntEnum

class EntityType(IntEnum):
    Unknown = 0
    Address = 1
    Transaction = 2
    Block = 3
    Url = 4