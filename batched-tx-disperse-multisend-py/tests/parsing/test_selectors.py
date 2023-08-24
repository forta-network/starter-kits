"""Test the selectors & signatures wordlist for the batching method."""

import pytest

import src.parsing.selectors as selectors
import tests.test_data as data

# FIXTURES ####################################################################

KNOWN_SIGNATURES = [
    'multisendEther(address[],uint256[])',
    'multisendToken(address,address[],uint256[])',
    'disperseEther(address[],uint256[])',
    'disperseToken(address,address[],uint256[])',]

KNOWN_SELECTORS = [
    '0xe63d38ed',
    '0xc73a2d60',
    '0xab883d28',
    '0x0b66f3f5',]

@pytest.fixture
def signature_wordlist():
    return (
        selectors.generate_signature_wordlist(pattern=selectors.PATTERNS[0])
        + selectors.generate_signature_wordlist(pattern=selectors.PATTERNS[1]))

@pytest.fixture
def selector_wordlist(signature_wordlist):
    return [selectors.selector(_s) for _s in signature_wordlist]

# SIGNATURES ##################################################################

def test_known_signatures_included_in_wordlist(signature_wordlist):
    assert all([_s in signature_wordlist for _s in KNOWN_SIGNATURES])

# SELECTORS ###################################################################

def test_known_selectors_included_in_wordlist(selector_wordlist):
    assert all([_s in selector_wordlist for _s in KNOWN_SELECTORS])
