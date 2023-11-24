"""Quantify the probability of a finding."""

import functools

import ioseeth.metrics.evasion.morphing.metamorphism as imemm

import src.findings as sf

# TRACES ######################################################################

is_trace_factory_contract_creation = functools.lru_cache(maxsize=128)(imemm.is_trace_factory_contract_creation)
is_trace_mutant_contract_creation = functools.lru_cache(maxsize=128)(imemm.is_trace_mutant_contract_creation)

def score_trace(trace: dict, **kwargs) -> dict:
    """Estimate the probabilities that the contract performs evasion techniques."""
    # scores each evasion technique
    __scores = {(sf.EvasionTechnique.Metamorphism, sf.MetamorphismAlert.FactoryDeployment): 0.5, (sf.EvasionTechnique.Metamorphism, sf.MetamorphismAlert.MutantDeployment): 0.5,}
    # update scores
    __scores[(sf.EvasionTechnique.Metamorphism, sf.MetamorphismAlert.FactoryDeployment)] = is_trace_factory_contract_creation(action=trace['type'], creation_bytecode=trace['input'], runtime_bytecode=trace['output'])
    __scores[(sf.EvasionTechnique.Metamorphism, sf.MetamorphismAlert.MutantDeployment)] = is_trace_mutant_contract_creation(action=trace['type'], creation_bytecode=trace['input'], runtime_bytecode=trace['output'])
    return __scores
