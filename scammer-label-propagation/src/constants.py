# How many more labeled victims than scammers we want to label
VICTIM_SAMPLING = 3
# How many models we want to train with the sampled victims
N_FOLDS = 10
# How many of the folds need to be predicted positively for considering an attacker
MIN_FOLDS_ATTACKER = 7
# Threshold for the mean probability of the attackers to be labeled
PREDICTED_ATTACKER_CONFIDENCE = .9
# Confidence needed for an address to be labeled as attacker
ATTACKER_CONFIDENCE = 0.8
# List of attacker bots to subscribe
attacker_bots = [
    "0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23",  # Scam detector feed
]
# List of victim identifier bots to subscribe
victim_bots = [
    "0x441d3228a68bbbcf04e6813f52306efcaf1e66f275d682e62499f44905215250",  # victim-identifier
    "0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f",  # positive reputation
]
# Maximum number of addresses that we will query to graphql
SIMULTANEOUS_ADDRESSES = 30
# Maximum number of simultaneous processes
N_WORKERS = 8
# Minimum amount of neighbors to consider an address
MIN_NEIGHBORS = 5
# Maximum amount of neighbors to consider an address
MAX_NEIGHBORS = 2500
# Maximum number of findings that can be sent in one handle call
MAX_FINDINGS = 40
# Random seed for reproducibility
SEED = 1993
# Hours before an address can be re-analyzed
HOURS_BEFORE_REANALYZE = 48
# Path to the model
MODEL_PATH = 'model.pth'
# Percentage of nodes that can be labeled as attackers before we bring down the severity
PERCENTAGE_ATTACKERS = 0.15