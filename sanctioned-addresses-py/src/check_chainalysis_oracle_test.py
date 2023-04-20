from forta_agent import FindingSeverity, FindingType, create_transaction_event
from .check_chainalysis_oracle import provide_handle_transaction

mock_chain_id = 1

handle_transaction = provide_handle_transaction(mock_chain_id)


class TestChainalysissanctionedAddressBot:
    def test_returns_empty_findings_if_no_sanctioned_address(self):
        tx_event = create_transaction_event(
            {'addresses': {'0x9c1aec4fa72b7c3ff135999b2087868ec85d9ee2': True}})

        findings = handle_transaction(tx_event)

        assert len(findings) == 0

    def test_returns_finding_if_sanctioned_address_in_tx(self):
        sanctioned_address = '0x19aa5fe80d33a56d56c78e82ea5e50e5d80b4dff'
        wallet_tag = ''
        expected_description = f'Transaction involving a sanctioned address: {sanctioned_address}'
        tx_event = create_transaction_event(
            {'addresses': {f'{sanctioned_address}': True}})

        findings = handle_transaction(tx_event)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.name == "Sanctioned Address"
        assert finding.description == expected_description
        assert finding.alert_id == 'CHAINALYSIS-SANCTIONED-ADDR-TX'
        assert finding.type == FindingType.Suspicious
        assert finding.severity == FindingSeverity.High
        assert finding.metadata['sanctioned_address'] == sanctioned_address
        assert finding.metadata['data_source'] == 'Chainalysis'
