from xmlrpc.client import Transport
from .check_chainalysis_blocklist import handle_transaction as check_chainalysis_blocklist
from .check_etherscan_blocklist import handle_transaction as check_etherscan_blocklist
from .check_usdt_blocklist import handle_transaction as check_usdt_blocklist
from .check_usdc_blocklist import handle_transaction as check_usdc_blocklist


def provide_handle_transaction(check_etherscan_blocklist,
                               check_usdt_blocklist,
                               check_usdc_blocklist,
                               check_chainalysis_blocklist):
    def handle_transaction(transaction_event):
        findings = (check_etherscan_blocklist(transaction_event) +
                    check_usdt_blocklist(transaction_event) +
                    check_usdc_blocklist(transaction_event) +
                    check_chainalysis_blocklist(transaction_event))


        return findings
    return handle_transaction

real_handle_transaction = provide_handle_transaction(check_etherscan_blocklist,
                                                     check_usdt_blocklist,
                                                     check_usdc_blocklist,
                                                     check_chainalysis_blocklist)

def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
