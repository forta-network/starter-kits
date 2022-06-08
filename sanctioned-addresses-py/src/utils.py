import json


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
