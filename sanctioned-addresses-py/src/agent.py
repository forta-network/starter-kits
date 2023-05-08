from .check_chainalysis_oracle import handle_transaction as check_chainalysis_oracle
from src.keys import ZETTABLOCK_KEY
from os import environ


def initialize():
    environ["ZETTABLOCK_API_KEY"] = ZETTABLOCK_KEY


def provide_handle_transaction(check_chainalysis_oracle):
    def handle_transaction(transaction_event):
        findings = (check_chainalysis_oracle(transaction_event))

        return findings
    return handle_transaction


real_handle_transaction = provide_handle_transaction(
    check_chainalysis_oracle)


def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
