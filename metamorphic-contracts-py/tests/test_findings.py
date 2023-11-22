"""Test the formating of alerts / findings"""

import forta_agent
import forta_toolkit
import pytest

import src.findings as findings
import tests.test_data as data

# FIXTURES ####################################################################

# FORMAT ######################################################################

def test_format():
    __log = data.TRANSACTIONS['evasion']['metamorphism'][0]
    __tx = forta_toolkit.parsing.transaction.parse_transaction_data(transaction=__log.transaction)
    __traces = [forta_toolkit.parsing.traces.parse_trace_data(trace=__t) for __t in __log.traces]
    _f = findings.format_finding(
        chain_id=1,
        alert_id=(findings.EvasionTechnique.Metamorphism, findings.MetamorphismAlert.FactoryDeployment),
        transaction=__tx,
        log={},
        trace=__traces[0],
        confidence=0.8)
    assert type(_f) == forta_agent.Finding
    assert len(_f.name) > 0
    assert len(_f.description) > 0
    assert len(_f.alert_id) > 0
    assert _f.type == forta_agent.FindingType.Suspicious
    assert _f.severity == forta_agent.FindingSeverity.Info
