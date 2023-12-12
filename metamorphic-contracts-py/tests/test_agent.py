"""Test the agent on a fork"""

import pytest
import web3

import forta_agent

import src.agent as agent
import tests.test_data as data

# FIXTURES ####################################################################

@pytest.fixture
def provider():
    return web3.Web3(web3.EthereumTesterProvider())

@pytest.fixture
def handle_transaction(provider):
    return agent.handle_transaction_factory(provider=provider)

# METAMORPHISM ################################################################

def test_detects_metamorphic_contract_creations(handle_transaction):
    assert all([
        len(handle_transaction(__t)) > 0
        for __t in data.TRANSACTIONS['evasion']['metamorphism']])

# RED-PILL ####################################################################

# def test_detects_red_pill_contract_creations(handle_transaction):
#     assert all([
#         len(handle_transaction(__t)) > 0
#         for __t in data.TRANSACTIONS['evasion']['red-pill']])
