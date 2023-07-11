class ErrorCache:
    def __init__(self):
        self.errors = []

    def add(self, error):
        self.errors.append(error)

    def get_all(self):
        return self.errors

    def clear(self):
        self.errors = []

    def len(self):
        return len(self.errors)