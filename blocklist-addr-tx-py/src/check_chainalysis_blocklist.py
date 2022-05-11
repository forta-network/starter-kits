from .constants import CHAINALYSIS_SANCTIONS_LIST_ADDRESS, CHAINALYSIS_SANCTIONED_ADDRESS_ADDED_EVENT_ABI, CHAINALYSIS_SANCTIONED_ADDRESS_REMOVED_EVENT_ABI
from .utils import create_finding, get_blocklist, update_blocklist

CHAINALYSIS_BLOCKLIST_PATH = './chainalysis_blocklist.txt'


def provide_handle_transaction():
    def handle_transaction(transaction_event):
        findings = []

        blocklist = get_blocklist(CHAINALYSIS_BLOCKLIST_PATH)

        chainalysis_blocklist_events = transaction_event.filter_log(
            [CHAINALYSIS_SANCTIONED_ADDRESS_ADDED_EVENT_ABI, CHAINALYSIS_SANCTIONED_ADDRESS_REMOVED_EVENT_ABI],
            CHAINALYSIS_SANCTIONS_LIST_ADDRESS)

        if chainalysis_blocklist_events:
            blocklisted_addresses = set()
            unblocklisted_addresses = set()

            for event in chainalysis_blocklist_events:
                accounts = [addr.lower() for addr in event['args']['addrs']]
                if event.event == 'SanctionedAddressesAdded':
                    blocklisted_addresses.update(accounts)
                elif event == 'SanctionedAddressesRemoved':
                    unblocklisted_addresses.update(accounts)

            update_blocklist(blocklist, CHAINALYSIS_BLOCKLIST_PATH,
                             blocklisted_addresses, unblocklisted_addresses)

        addresses = set(transaction_event.addresses)

        matched_addresses = blocklist.intersection(addresses)

        for address in matched_addresses:
            description_msg = f'Transaction involving a blocklisted address: {address}'

            finding = create_finding(address, description_msg, '', 'Chainalysis-blocklist')
            findings.append(finding)

        return findings
    return handle_transaction

real_handle_transaction = provide_handle_transaction()

def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
