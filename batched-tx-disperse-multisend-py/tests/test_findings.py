"""Test the formating of alerts / findings"""

import forta_agent
import pytest

import src.findings as findings

# FIXTURES ####################################################################

ORIGIN = '0x3360a4e0eb33161da911b85f7c343e02ea41bbbd' # random
CONTRACT = '0x22bc0693163ec3cee5ded3c2ee55ddbcb2ba9bbe' # Multisend
TOKEN = 'b23a19d28a7e9bdec030782346b0d9ace11530f5' # BUYBACK token

# FORMAT ######################################################################

def test_format():
	_f = findings.FormatBatchTxFinding(origin=ORIGIN, contract=CONTRACT, token=TOKEN, transactions=[], chain_id=1)
	assert type(_f) == forta_agent.Finding
	assert len(_f.name) > 0
	assert len(_f.description) > 0
	assert len(_f.alert_id) > 0
	assert _f.type == forta_agent.FindingType.Info
	assert _f.severity == forta_agent.FindingSeverity.Info

# IDS #########################################################################

def test_alert_ids():
	_f_erc20 = findings.FormatBatchTxFinding(origin=ORIGIN, contract=CONTRACT, token=TOKEN, transactions=[], chain_id=1)
	_f_native = findings.FormatBatchTxFinding(origin=ORIGIN, contract=CONTRACT, token='', transactions=[], chain_id=1)
	assert _f_erc20.alert_id == 'BATCHED-ERC20-TX'
	assert _f_native.alert_id == 'BATCHED-ETH-TX'
