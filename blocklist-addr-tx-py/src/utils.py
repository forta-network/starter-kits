import json

from forta_agent import Finding, FindingType, FindingSeverity

def create_finding(address, description: str, wallet_tag: str, data_source: str) -> Finding:
    return Finding({
        'name': 'Blocklisted Address',
        'description': description,
        'alert_id': 'FORTA-BLOCKLIST-ADDR-TX',
        'severity': FindingSeverity.High,
        'type': FindingType.Suspicious,
        'metadata': {
            'blocklisted_address': address,
            'wallet_tag': wallet_tag,
            'data_source': data_source
        }
    })


def get_blocklist(filepath: str):
    with open(filepath, 'r') as f:
        blocklist = json.load(f)
    return set(blocklist)


def update_blocklist(current_blocklist: set,
                     filepath: str,
                     blocklisted_addresses: set,
                     unblocklisted_addresses: set):
    print(f'updating blocklist: {filepath}')
    blocklist = current_blocklist.union(blocklisted_addresses).difference(unblocklisted_addresses)

    with open(filepath, 'w') as f:
        json.dump(list(blocklist), f)
