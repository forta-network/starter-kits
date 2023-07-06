from unittest.mock import Mock
from forta_agent import FindingSeverity, FindingType, create_transaction_event, EntityType
from agent import handle_transaction, ERC721_TRANSFER_EVENT

mock_tx_event = create_transaction_event({})
mock_tx_event.filter_log = Mock()


class TestStolenNFTTransferBot:
    def test_returns_finding_if_nft_transfer_to_scammer(self):
        mock_tx_event.filter_log.reset_mock()

        known_scammer = '0xFB4d3EB37bDe8FA4B52c60AAbE55B3Cd9908EC73'.lower()

        mock_transfer_event = {
            'args': {'from': '0x123', 'to': known_scammer, 'tokenId': 123}, 'address': '0xfff'}
        mock_tx_event.filter_log.return_value = [mock_transfer_event]

        findings = handle_transaction(mock_tx_event)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.name == "Potentially Stolen NFT Transfer"
        assert finding.description == f'NFT (tokenId: 123, contract: 0xfff) transferred to a known scammer {known_scammer}'
        assert finding.alert_id == "POTENTIALLY-STOLEN-NFT-TRANSFER"
        assert finding.severity == FindingSeverity.Info
        assert finding.type == FindingType.Info

        assert len(finding.labels) == 1
        label = finding.labels[0]
        assert label.entity == '0xfff,123'
        assert label.entity_type == EntityType.Address
        assert label.label == 'stolen-nft'

    def test_returns_no_finding_if_not_scammer(self):
        mock_tx_event.filter_log.reset_mock()

        not_scammer = '0xFB4d3EB37bDe8FA4B52c60AAbE55B3Cd9908EC74'.lower()

        mock_transfer_event = {
            'args': {'from': '0x123', 'to': not_scammer, 'tokenId': 123}, 'address': '0xfff'}
        mock_tx_event.filter_log.return_value = [mock_transfer_event]

        findings = handle_transaction(mock_tx_event)

        assert len(findings) == 0
