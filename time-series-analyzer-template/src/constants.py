BOT_ID = ""
ALERT_NAME = ""

CONTRACT_ADDRESS = ""

BUCKET_WINDOW_IN_MINUTES = 5
TRAINING_WINDOW_IN_BUCKET_SIZE = 12 * 24 * 7  # recommended to cover training period during which the periodicity can be observed, so in case of a bucket_window_in_minutes, 12 * 24 * 7 = 1 week period. This is the lookback period the time series model will be built on. It is recommended to at least have 7 days so weekly periodicity can be taken into account.
INTERVAL_WIDTH = 0.80

TIMESTAMP_QUEUE_SIZE = 100  # the number of timestamps that are held in the queue
