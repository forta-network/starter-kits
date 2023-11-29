"""Format the agent findings into Forta alerts"""

import enum
import logging

import forta_agent
import forta_toolkit
import ioseeth.indicators.events

# TYPES #######################################################################

class EvasionTechnique(enum.IntEnum):
    Unknown = 0
    Metamorphism = enum.auto()
    EventPoisoning = enum.auto()
    LogicBomb = enum.auto()

class MetamorphismAlert(enum.IntEnum):
    Unknown = 0
    FactoryDeployment = enum.auto()
    MutantDeployment = enum.auto()

# ID ##########################################################################

ALERT_IDS = {
    (EvasionTechnique.Unknown, 0): '',
    (EvasionTechnique.Metamorphism, MetamorphismAlert.FactoryDeployment): 'METAMORPHISM-FACTORY-DEPLOYMENT',
    (EvasionTechnique.Metamorphism, MetamorphismAlert.MutantDeployment): 'METAMORPHISM-MUTANT-DEPLOYMENT',
}

def get_alert_id(alert_id: tuple, **kwargs) -> str:
    """Generate the alert id."""
    return ALERT_IDS.get(alert_id, '')

# NAME ########################################################################

ALERT_NAMES = {
    (EvasionTechnique.Unknown, 0): '',
    (EvasionTechnique.Metamorphism, MetamorphismAlert.FactoryDeployment): 'Metamorphism: factory contract deployment',
    (EvasionTechnique.Metamorphism, MetamorphismAlert.MutantDeployment): 'Metamorphism: mutant contract deployment',
}

def get_alert_name(alert_id: tuple, transaction: dict, log: dict, trace: dict, **kwargs) -> str:
    """Generate the alert name."""
    return ALERT_NAMES.get(alert_id, '')

# DESCRIPTION #################################################################

ALERT_DESCRIPTION_PATTERNS = {
    (EvasionTechnique.Unknown, 0): '',
    (EvasionTechnique.Metamorphism, MetamorphismAlert.FactoryDeployment): 'Metamorphism: {sender} is deploying a factory contract at {recipient}',
    (EvasionTechnique.Metamorphism, MetamorphismAlert.MutantDeployment): 'Metamorphism: {sender} is deploying a mutant contract at {recipient}',
}

def get_alert_description(alert_id: tuple, transaction: dict, log: dict, trace: dict, **kwargs) -> str:
    """Generate the alert description."""
    __pattern = ALERT_DESCRIPTION_PATTERNS.get(alert_id, '')
    __description = ''
    if alert_id[0] == EvasionTechnique.Metamorphism:
        __sender = trace.get('action_from', '0x')
        __recipient = trace.get('action_to', '0x')
        __description = __pattern.format(sender=__sender, recipient=__recipient)
    return __description

# TAXONOMY ####################################################################

def get_alert_type(**kwargs) -> str:
    """Generate the alert type."""
    return forta_agent.FindingType.Suspicious

def get_alert_severity(**kwargs) -> str:
    """Generate the alert type."""
    return forta_agent.FindingSeverity.Info

# LABELS ######################################################################

def get_alert_labels(chain_id: int, alert_id: tuple, transaction: dict, log: dict, trace: dict, confidence: float, **kwargs) -> str:
    """Generate the alert labels."""
    __labels = []
    __template = {
        'entityType': forta_agent.EntityType.Address,
        'label': '',
        'entity': '',
        'confidence': round(confidence, 1),
        'metadata': {'chain_id': chain_id}}
    # factory
    if alert_id == (EvasionTechnique.Metamorphism, MetamorphismAlert.FactoryDeployment):
        __l = __template.copy()
        __l['label'] = 'metamorphism-factory-contract'
        __l['entity'] = trace.get('action_to', '0x')
        __labels.append(forta_agent.Label(__l))
        __l = __template.copy()
        __l['label'] = 'metamorphism-eoa'
        __l['entity'] = transaction.get('from_address', '0x')
        __labels.append(forta_agent.Label(__l))
    # mutant
    if alert_id == (EvasionTechnique.Metamorphism, MetamorphismAlert.MutantDeployment):
        __l = __template.copy()
        __l['label'] = 'metamorphism-mutant-contract'
        __l['entity'] = trace.get('action_to', '0x')
        __labels.append(forta_agent.Label(__l))
        __l = __template.copy()
        __l['label'] = 'metamorphism-eoa'
        __l['entity'] = transaction.get('from_address', '0x')
        __labels.append(forta_agent.Label(__l))
    return __labels

# ACTUAL ######################################################################

def format_finding(**kwargs) -> forta_agent.Finding:
    """Structure all the metadata of the transaction in a Forta "Finding" object."""
    __format_finding = forta_toolkit.findings.format_finding_factory(
        get_alert_id=get_alert_id,
        get_alert_name=get_alert_name,
        get_alert_description=get_alert_description,
        get_alert_type=get_alert_type,
        get_alert_severity=get_alert_severity,
        get_alert_labels=get_alert_labels,
        get_alert_log=get_alert_description,)
    return forta_agent.Finding(__format_finding(**kwargs))
