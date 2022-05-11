from .constants import USDC_TOKEN_ADDRESS, USDC_BLOCKLISTED_EVENT_ABI, USDC_UNBLOCKLISTED_EVENT_ABI
from .utils import create_finding, get_blocklist, update_blocklist

USDC_BLOCKLIST_PATH = './usdc_blocklist.txt'


def provide_handle_transaction():
    def handle_transaction(transaction_event):
        findings = []

        blocklist = get_blocklist(USDC_BLOCKLIST_PATH)

        usdc_blocklist_events = transaction_event.filter_log(
            [USDC_BLOCKLISTED_EVENT_ABI, USDC_UNBLOCKLISTED_EVENT_ABI],
            USDC_TOKEN_ADDRESS)

        if usdc_blocklist_events:
            blocklisted_addresses = set()
            unblocklisted_addresses = set()

            for event in usdc_blocklist_events:
                account = event['args']['_account'].lower()
                if event.event == 'Blacklisted':
                    blocklisted_addresses.add(account)
                elif event == 'UnBlacklisted':
                    unblocklisted_addresses.add(account)

            update_blocklist(blocklist, USDC_BLOCKLIST_PATH,
                             blocklisted_addresses, unblocklisted_addresses)

        addresses = set(transaction_event.addresses)

        matched_addresses = blocklist.intersection(addresses)

        for address in matched_addresses:
            description_msg = f'Transaction involving a blocklisted address: {address}'

            finding = create_finding(address, description_msg, '', 'USDC-blocklist')
            findings.append(finding)

        return findings
    return handle_transaction

real_handle_transaction = provide_handle_transaction()

def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
