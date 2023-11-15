"""Forta agent scanning for batched transactions."""

import functools

import ioseeth.indicators.events as iie
import ioseeth.metrics.evasion.morphing.logic_bomb as imeml
import ioseeth.metrics.evasion.morphing.metamorphism as imemm

import src.findings as sf

# TRACES ######################################################################

is_trace_factory_contract_creation = functools.lru_cache(maxsize=128)(imemm.is_trace_factory_contract_creation)
is_trace_mutant_contract_creation = functools.lru_cache(maxsize=128)(imemm.is_trace_mutant_contract_creation)
is_trace_red_pill_contract_creation = functools.lru_cache(maxsize=128)(imeml.is_trace_red_pill_contract_creation)

def score_trace(trace: dict, **kwargs) -> dict:
    """Estimate the probabilities that the contract performs evasion techniques."""
    # scores each evasion technique
    __scores = {(sf.EvasionTechnique.Metamorphism, sf.MetamorphismAlert.FactoryDeployment): 0.5, (sf.EvasionTechnique.Metamorphism, sf.MetamorphismAlert.MutantDeployment): 0.5, (sf.EvasionTechnique.LogicBomb, sf.LogicBombAlert.RedPill): 0.5}
    # update scores
    # __scores[(sf.EvasionTechnique.Metamorphism, sf.MetamorphismAlert.FactoryDeployment)] = is_trace_factory_contract_creation(action=trace['type'], creation_bytecode=trace['input'], runtime_bytecode=trace['output'])
    # __scores[(sf.EvasionTechnique.Metamorphism, sf.MetamorphismAlert.MutantDeployment)] = is_trace_mutant_contract_creation(action=trace['type'], creation_bytecode=trace['input'], runtime_bytecode=trace['output'])
    __scores[(sf.EvasionTechnique.LogicBomb, sf.LogicBombAlert.RedPill)] = is_trace_red_pill_contract_creation(action=trace['type'], runtime_bytecode=trace['output'])
    return __scores

# EVENT LOGS ##################################################################

def score_log(log: dict, **kwargs) -> dict:
    """Estimate the probabilities that the contract performs evasion techniques."""
    # scores each evasion technique
    __scores = {(sf.EvasionTechnique.EventPoisoning, iie.EventIssue.ERC20_TransferNullAmount): 0.5,}
    # check constraints on each event
    __issues = iie.check_event_constraints(log=log)
    # alert on broken constraints
    if __issues == iie.EventIssue.ERC20_TransferNullAmount:
        __scores[(sf.EvasionTechnique.EventPoisoning, iie.EventIssue.ERC20_TransferNullAmount)] = 1.
    # update scores
    return __scores
