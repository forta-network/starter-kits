import pytest
from models import AlertRateModel
import pandas as pd
from prophet import Prophet
from datetime import datetime

class TestUtils:
    def test_alert_rate_model(self):
        # Initialize AlertRateModel
        alert_rate_model = AlertRateModel()

        # Create sample timestamps
        timestamp_1 = datetime(2021, 1, 1, 0, 0)
        timestamp_2 = datetime(2021, 1, 1, 1, 0)
        timestamp_3 = datetime(2021, 1, 1, 2, 0)
        timestamp_4 = datetime(2021, 1, 1, 3, 0)

        # Update the model with the sample timestamps
        alert_rate_model.update(timestamp_1)
        alert_rate_model.update(timestamp_2)
        alert_rate_model.update(timestamp_2)
        alert_rate_model.update(timestamp_3)
        alert_rate_model.update(timestamp_3)
        alert_rate_model.update(timestamp_4)
        alert_rate_model.update(timestamp_4)
        alert_rate_model.update(timestamp_4)

        last_hour = timestamp_4.replace(minute=0, second=0, microsecond=0)
        assert not alert_rate_model.is_outside_normal_range(last_hour)

    def test_alert_rate_model_missing_value(self):
        # Initialize AlertRateModel
        alert_rate_model = AlertRateModel()

        # Create sample timestamps
        timestamp_1 = datetime(2021, 1, 1, 0, 0)
        timestamp_3 = datetime(2021, 1, 1, 2, 0)
        timestamp_4 = datetime(2021, 1, 1, 3, 0)

        # Update the model with the sample timestamps
        alert_rate_model.update(timestamp_1)
        alert_rate_model.update(timestamp_3)
        alert_rate_model.update(timestamp_3)
        alert_rate_model.update(timestamp_4)
        alert_rate_model.update(timestamp_4)

        last_hour = timestamp_4.replace(minute=0, second=0, microsecond=0)
        assert not alert_rate_model.is_outside_normal_range(last_hour)