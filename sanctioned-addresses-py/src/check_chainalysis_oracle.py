from .constants import CHAINALYSIS_SANCTIONS_LIST_ADDRESS, CHAINALYSIS_SANCTIONED_ADDRESS_ADDED_EVENT_ABI, CHAINALYSIS_SANCTIONED_ADDRESS_REMOVED_EVENT_ABI
from .utils import get_blocklist, update_blocklist
from .findings import SanctionedAddressTx, SanctionedAddressesEvent, UnsanctionedAddressesEvent

CHAINALYSIS_BLOCKLIST_PATH = './chainalysis_blocklist.txt'


def provide_handle_transaction():
    def handle_transaction(transaction_event):
        findings = []

        blocklist = get_blocklist(CHAINALYSIS_BLOCKLIST_PATH)

        chainalysis_sanction_events = transaction_event.filter_log(
            [CHAINALYSIS_SANCTIONED_ADDRESS_ADDED_EVENT_ABI, CHAINALYSIS_SANCTIONED_ADDRESS_REMOVED_EVENT_ABI],
            CHAINALYSIS_SANCTIONS_LIST_ADDRESS)

        if chainalysis_sanction_events:
            sanctioned_addresses = set()
            unsanctioned_addresses = set()

            for event in chainalysis_sanction_events:
                accounts = [addr.lower() for addr in event['args']['addrs']]
                if event.event == 'SanctionedAddressesAdded':
                    sanctioned_addresses.update(accounts)
                    findings.append(SanctionedAddressesEvent(list(sanctioned_addresses)).emit_finding())
                elif event == 'SanctionedAddressesRemoved':
                    unsanctioned_addresses.update(accounts)
                    findings.append(UnsanctionedAddressesEvent(list(unsanctioned_addresses)).emit_finding())

            update_blocklist(blocklist, CHAINALYSIS_BLOCKLIST_PATH,
                             sanctioned_addresses, unsanctioned_addresses)

        addresses = set(transaction_event.addresses)

        matched_addresses = blocklist.intersection(addresses)

        for address in matched_addresses:
            findings.append(SanctionedAddressTx(address).emit_finding())

        return findings
    return handle_transaction

real_handle_transaction = provide_handle_transaction()

def handle_transaction(transaction_event):
    return real_handle_transaction(transaction_event)
