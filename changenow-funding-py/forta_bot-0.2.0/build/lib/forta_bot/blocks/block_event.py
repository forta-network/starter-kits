from .block import Block


class BlockEvent:
    def __init__(self, dict):
        self.network: int = dict.get('network')
        self.block = Block(dict.get('block', {}))

    @property
    def block_hash(self):
        return self.block.hash

    @property
    def block_number(self):
        return self.block.number
