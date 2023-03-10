class DBUtils:
    def __init__(self):
        self.features = None
        self.base = None

    def get_features(self):
        return self.features

    def set_tables(self, features):
        self.features = features

    def set_base(self, base):
        self.base = base


db_utils = DBUtils()
