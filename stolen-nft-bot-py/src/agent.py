from forta_agent import Finding, FindingType, FindingSeverity, get_labels, Label, EntityType
import forta_agent

SCAM_DETECTOR_BOT_ID = "0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23"
ERC721_TRANSFER_EVENT = '{"name":"Transfer","type":"event","anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":true,"name":"tokenId","type":"uint256"}]}'
findings_count = 0


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> [Finding]:
    findings = []

    # filter the transaction logs for any Tether transfers
    transfer_events = transaction_event.filter_log(
        ERC721_TRANSFER_EVENT)

    for transfer_event in transfer_events:
        nft_token_contract = transfer_event['address']
        to = transfer_event['args']['to']
        tokenId = transfer_event['args']['tokenId']

        print(f"{transaction_event.hash} Got NFT transfer to {to} with tokenId {tokenId}")

        if is_scammer(to):
            labels = []
            labels.append(Label({
                'entity': nft_token_contract + "," + str(tokenId),
                'entity_type': EntityType.Address,
                'label': 'stolen-nft',
                'confidence': 0.8,
            }))


            findings.append(Finding({
                'name': 'Potentially Stolen NFT Transfer',
                'description': f'NFT (tokenId: {tokenId}, contract: {nft_token_contract}) transferred to a known scammer {to}',
                'alert_id': 'POTENTIALLY-STOLEN-NFT-TRANSFER',
                'severity': FindingSeverity.Info,
                'type': FindingType.Info,
                'metadata': {
                    'scammer': to,
                    'nft_contract': nft_token_contract,
                    'nft_token_id': tokenId,
                },
                'labels': labels
            }))

    return findings

def is_scammer(address: str) -> bool:
    label_response = get_labels({
        'source_ids': [SCAM_DETECTOR_BOT_ID],
        'entities': [address.lower()],
        'state': True
    })

    for label in label_response.labels:
        print(label.label)
        if 'scammer' in label.label:
            return True

    return False