from .check_chainalysis_oracle import handle_transaction as check_chainalysis_oracle
from os import environ
from src.storage import get_secrets

SECRETS_JSON = get_secrets()


def initialize():
    environ["ZETTABLOCK_API_KEY"] = SECRETS_JSON['apiKeys']['ZETTABLOCK']


def provide_handle_transaction(check_chainalysis_oracle):
    def handle_transaction(transaction_event):
        findings = (check_chainalysis_oracle(transaction_event))

        return findings
    return handle_transaction


real_handle_transaction = provide_handle_transaction(
    check_chainalysis_oracle)


def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
