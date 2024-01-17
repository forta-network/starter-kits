class DBUtils:
    def __init__(self):
        self.addresses = None
        self.base = None

    def get_addresses(self):
        return self.addresses

    def set_tables(self, addresses):
        self.addresses = addresses

    def set_base(self, base):
        self.base = base


db_utils = DBUtils()
