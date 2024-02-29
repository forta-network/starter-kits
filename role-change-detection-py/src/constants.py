# Removed user as it produces too many false positives, and likely wouldn't be related to anything malicious
ROLE_CHANGE_KEYWORDS = [
    # 'manage',
    'role',
    'admin',
    'own',
    # 'root',
    # 'user',
    'member',
    'minter'
]

FUNCTION_PARAMETER_KEYWORDS = ['to', 'newOwner', '_newOwner', 'account', 'newAdmin']
