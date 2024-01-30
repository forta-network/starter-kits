from .alert import Alert


class AlertEvent:
    def __init__(self, obj):
        self.alert = obj if isinstance(obj, Alert) else Alert(obj.get('alert'))

    @property
    def alert_id(self):
        return self.alert.alert_id

    @property
    def name(self):
        return self.alert.name

    @property
    def hash(self):
        return self.alert_hash

    @property
    def alert_hash(self):
        return self.alert.hash

    @property
    def bot_id(self):
        return self.alert.source.bot.id

    @property
    def transaction_hash(self):
        return self.alert.source.transaction_hash

    @property
    def block_hash(self):
        return self.alert.source.block.hash

    @property
    def block_number(self):
        return self.alert.source.block.number

    @property
    def chain_id(self):
        return self.alert.chain_id

    def has_address(self, address):
        return self.alert.has_address(address)
