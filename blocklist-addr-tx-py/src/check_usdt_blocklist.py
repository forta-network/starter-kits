from .constants import USDT_TOKEN_ADDRESS, USDT_ADDED_BLOCKLIST_EVENT_ABI, USDT_REMOVED_BLOCKLIST_EVENT_ABI
from .utils import create_finding, get_blocklist, update_blocklist

USDT_BLOCKLIST_PATH = './usdt_blocklist.txt'


def provide_handle_transaction():
    def handle_transaction(transaction_event):
        findings = []

        blocklist = get_blocklist(USDT_BLOCKLIST_PATH)

        usdt_blocklist_events = transaction_event.filter_log(
            [USDT_ADDED_BLOCKLIST_EVENT_ABI, USDT_REMOVED_BLOCKLIST_EVENT_ABI],
            USDT_TOKEN_ADDRESS)

        if usdt_blocklist_events:
            blocklisted_addresses = set()
            unblocklisted_addresses = set()

            for event in usdt_blocklist_events:
                account = event['args']['_user'].lower()
                if event.event == 'AddedBlackList':
                    blocklisted_addresses.add(account)
                elif event == 'RemovedBlackList':
                    unblocklisted_addresses.add(account)

            update_blocklist(blocklist, USDT_BLOCKLIST_PATH,
                             blocklisted_addresses, unblocklisted_addresses)

        addresses = set(transaction_event.addresses)

        matched_addresses = blocklist.intersection(addresses)

        for address in matched_addresses:
            description_msg = f'Transaction involving a blocklisted address: {address}'

            finding = create_finding(address, description_msg, '', 'USDT-blocklist')
            findings.append(finding)

        return findings
    return handle_transaction

real_handle_transaction = provide_handle_transaction()

def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
