BASE_BOTS = [("0xabdeff7672e59d53c7702777652e318ada644698a9faf2e7f608ec846b07325b", "MEV-ACCOUNT", "Forta Foundation"),  # 0x2e37bb44bae115b4657e99608ce5afe0d5f8b436 seems to be engaged in MEV activity
             ("0xd6e19ec6dc98b13ebb5ec24742510845779d9caf439cadec9a5533f8394d435f", "POSITIVE-REPUTATION-1", "Forta Foundation"),  # 0xb393f2fa4c9df2da3e54d169d0561d9e5979dff1 has positive reputation
             ("0xe04b3fa79bd6bc6168a211bcec5e9ac37d5dd67a41a1884aa6719f8952fbc274", "VICTIM-NOTIFICATION-1", "Forta Foundation")  # 0x0d5550d52428e7e3175bfc9550207e4ad3859b17 was notified to be a victim by 0x100cd1ee88a75cbb0856d4dc4928c62aef6354db
             ]


ADDRESS_TO_SOURCE_BOT_MAPPING_KEY = "address_to_source_bot_mapping"
CONTRACT_CACHE_KEY = ""

CONTRACT_CACHE_MAX_QUEUE_SIZE = 10000

CACHE_VERSION = "V1"
