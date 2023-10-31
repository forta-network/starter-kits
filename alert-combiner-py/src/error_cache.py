class ErrorCache:
    errors = []

    @staticmethod
    def add(error):
        ErrorCache.errors.append(error)

    @staticmethod
    def get_all():
        return ErrorCache.errors

    @staticmethod
    def clear():
        ErrorCache.errors = []

    @staticmethod
    def len():
        return len(ErrorCache.errors)