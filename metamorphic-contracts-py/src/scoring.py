"""Quantify the probability of a finding."""

import functools
import logging

import forta_toolkit.indexing.parquet as fip
import ioseeth.metrics.evasion.morphing.metamorphism as imemm

import src.findings as sf

# HISTORY #####################################################################

def has_contract_runtime_bytecode_changed(trace: dict, chain_id: int=1, dataset: 'pyarrow.dataset.FileSystemDataset'=None, **kwargs) -> bool:
    """Query the database and assess whether a contract changed its bytecode."""
    __changed = False
    __row = fip.cast_trace_to_contracts_dataset_row(trace=trace, chain_id=chain_id, compress=False)
    __address = __row.get('contract_address', b'')
    __hash = __row.get('code_hash', b'')
    if 'create' in trace.get('action_type', ''):
        __past = fip.list_contracts_deployed_at(address=__address, dataset=dataset)
        __hashes = set([__r.get('code_hash', b'') for __r in __past])
        if (len(__hashes) > 0) and (__hash not in __hashes):
            __changed = True
    return __changed

# TRACES ######################################################################

is_trace_factory_contract_creation = functools.lru_cache(maxsize=128)(imemm.is_trace_factory_contract_creation)
is_trace_mutant_contract_creation = functools.lru_cache(maxsize=128)(imemm.is_trace_mutant_contract_creation)

def score_trace(trace: dict, chain_id: int=1, dataset: 'pyarrow.dataset.FileSystemDataset'=None, **kwargs) -> dict:
    """Estimate the probabilities that the contract performs evasion techniques."""
    # scores each evasion technique
    __scores = {(sf.EvasionTechnique.Metamorphism, sf.MetamorphismAlert.FactoryDeployment): 0.5, (sf.EvasionTechnique.Metamorphism, sf.MetamorphismAlert.MutantDeployment): 0.5,}
    # update scores
    __scores[(sf.EvasionTechnique.Metamorphism, sf.MetamorphismAlert.FactoryDeployment)] = is_trace_factory_contract_creation(action=trace['action_type'], creation_bytecode=trace['action_init'], runtime_bytecode=trace['result_code'])
    __scores[(sf.EvasionTechnique.Metamorphism, sf.MetamorphismAlert.MutantDeployment)] = is_trace_mutant_contract_creation(action=trace['action_type'], creation_bytecode=trace['action_init'], runtime_bytecode=trace['result_code'])
    # double-check against past records
    if dataset:
        __changed = has_contract_runtime_bytecode_changed(trace=trace, chain_id=chain_id, dataset=dataset)
        if __changed:
            __previous_score = __scores[(sf.EvasionTechnique.Metamorphism, sf.MetamorphismAlert.MutantDeployment)]
            __scores[(sf.EvasionTechnique.Metamorphism, sf.MetamorphismAlert.MutantDeployment)] = 1.
            if __previous_score < 0.7:
                logging.info('Metamorphism: runtime bytecode at {address} changed but dodged the current IOC detection'.format(address=trace.get('action_to'))) # result_address?
    return __scores
