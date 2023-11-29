"""Forta agent scanning for batched transactions."""

import functools

import ioseeth.metrics.evasion.morphing.logic_bomb as imeml

import src.findings as sf

# TRACES ######################################################################

is_trace_red_pill_contract_creation = functools.lru_cache(maxsize=128)(imeml.is_trace_red_pill_contract_creation)

def score_trace(trace: dict, **kwargs) -> dict:
    """Estimate the probabilities that the contract performs evasion techniques."""
    # scores each evasion technique
    __scores = {(sf.EvasionTechnique.LogicBomb, sf.LogicBombAlert.RedPill): 0.5}
    # update scores
    __scores[(sf.EvasionTechnique.LogicBomb, sf.LogicBombAlert.RedPill)] = is_trace_red_pill_contract_creation(action=trace['action_type'], runtime_bytecode=trace['result_code'])
    return __scores
