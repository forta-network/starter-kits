"""Test the formating of alerts / findings"""

import forta_agent
import pytest

import src.findings as findings

# FIXTURES ####################################################################

SENDER = '0x3360a4e0eb33161da911b85f7c343e02ea41bbbd' # random
RECEIVER = '0x22bc0693163ec3cee5ded3c2ee55ddbcb2ba9bbe' # Multisend

# FORMAT ######################################################################

def test_format():
    _f = findings.FormatBatchTxFinding(sender=SENDER, receiver=RECEIVER, token='ERC20', transfers=[], chain_id=1, confidence_score=0.5, malicious_score=0.5)
    assert type(_f) == forta_agent.Finding
    assert len(_f.name) > 0
    assert len(_f.description) > 0
    assert len(_f.alert_id) > 0
    assert _f.type == forta_agent.FindingType.Info
    assert _f.severity == forta_agent.FindingSeverity.Info or forta_agent.FindingSeverity.Low

# IDS #########################################################################

def test_alert_ids():
    _f_erc20 = findings.FormatBatchTxFinding(sender=SENDER, receiver=RECEIVER, token='ERC20', transfers=[], chain_id=1, confidence_score=0.5, malicious_score=0.5)
    _f_native = findings.FormatBatchTxFinding(sender=SENDER, receiver=RECEIVER, token='ETH', transfers=[], chain_id=1, confidence_score=0.5, malicious_score=0.5)
    assert _f_erc20.alert_id == 'BATCH-ERC20-TX'
    assert _f_native.alert_id == 'BATCH-ETH-TX'

# CRITICITY ###################################################################

def test_severity_increases_when_malicious_score_increases():
    _f_erc20 = findings.FormatBatchTxFinding(sender=SENDER, receiver=RECEIVER, token='ERC20', transfers=[], chain_id=1, confidence_score=0.9, malicious_score=0.7)
    assert _f_erc20.severity == forta_agent.FindingSeverity.Low
