# SCAM NOTIFIER BOT

## Description

This bot monitors notification EOAs and emits an alert on the scam contract/EOA associated with the to address the scam notifier sends messages to, and create alerts for new possible notification EOAs by performing an analysis based on other notifications.

New possible notifiers are then checked manually and added if they are valid.

> Last Manual Update: Jul 10 3pm (UTC)

1. Checks transcations Input Data to see if there is a valid message
2. If so the from, to, hash, recipientAddressType, and text is saved in a Neo4j db.
3. Starts with some notifier address, but can be expanded to multiple
4. If the message is found, and was sent from the notifier address, it will create an alert

- If the message was sent to an EOA, it will create the alert SCAM-NOTIFIER-EOA
- If the message was sent to an Contract, it will create the alert SCAM-NOTIFIER-CONTRACT

4. The bot has logic to identify new notifier addresses:

- Checks if the sender address has any reports in common with known notifiers
- If the amount of shared reports is >= 2, the address is upgraded to notifier
- If a new notifier is identified, it will create the alert NEW-SCAM-NOTIFIER
- Then alerts are filtered from the explorer and new possible notifiers are checked and added

### New Address addition

- Only save messages that are sended to an address that has been previously flagged by a notifier
  - Check if msg Recipient exists in the db
  - If yes save the sender, tx, and connect
- When a regular address has at least 2 Transactions, create a new Notifier alert

## Supported Chains

- Ethereum
- BSC
- Polygon

## Alerts

- SCAM-NOTIFIER-EOA

  - Description: “{scammer_eoa} was flagged as a scam by {notifier_eoa} {notifier_name}”
  - Severity is always set to "high"
  - Type is always set to "suspicious"
  - Metadata
    - `scammer_eoa` - the address of the scammer EOA
    - `scammer_contracts` - [to be implemented [PERFORMANCE ISSUES]](https://docs.alchemy.com/docs/how-to-get-all-the-contracts-deployed-by-a-wallet)
    - `notifier_eoa` - the address of the notifier
    - `notifier_name` - the name of the notifier
    - `message`- the message sent
  - Labels
    - `notifier_EOA`:
      - entity address
      - metadata "ENS_NAME"
    - `scammer_EOA`:
      - entity address

- SCAM-NOTIFIER-CONTRACT

  - Description: “{scammer_contract} was flagged as a scam by {notifier_eoa} {notifier_name}”
  - Severity is always set to "high"
  - Type is always set to "suspicious"
  - Metadata
    - `scammer_contract` - the scammer contract
    - `scammer_eoa` - the address of the deployer EOA
    - `notifier_eoa` - the address of the notifier
    - `notifier_name` - the name of the notifier
    - `message`- the message sent
  - Labels
    - `notifier_EOA`:
      - entity address
      - metadata "ENS_NAME"
    - `scammer_Contract`:
      - entity address
    - `scammer_EOA`: ( not included on some cases )
      - entity address

- VICTIM-NOTIFIER-EOA

  - Description: “${notifierEoa} ${notifierName} alerted ${victimEoa} from a ${USDT/WETH/ETC} ${phishing approval/phishing transfer} to ${extraInfo.scammerEAO}”
  - Severity is always set to "high"
  - Type is always set to "Exploit"
  - Metadata
    - `victim_eoa` - the address of the victim EOA
    - `scammer_eoa` - the address of the scammer EOA
    - `notifier_eoa` - the address of the notifier
    - `notifier_name` - the name of the notifier
    - `message`- the message sent
  - Labels
    - `notifier_EOA`:
      - entity address
      - metadata "ENS_NAME"
    - `victim_EOA`:
      - entity address
    - `scammer_EOA`:
      - entity address

- NEW-SCAM-NOTIFIER

  - Description: “New scam notifier identified {notifier_eoa} {notifier_name}”
  - Severity is always set to "info"
  - Type is always set to "info"
  - Metadata
    - ‘similar_notifier_eoa’ - the address of the notifier that it is similar to (as in flags similar contracts/EOAs)
    - ‘similar_notifier_name’ - a human readable name/ ENS name of the notifier that it is similar to (as in flags similar contracts/EOAs)
  - ‘union_flagged’ - comma separated list of addresses both have flagged
  - `notifier_eoa` - the address of the notifier
  - `notifier_name` - a human readable name/ ENS name of the notifier

### Examples

#### SCAM-NOTIFIER-EOA

```bash
1 findings for transaction 1 findings for transaction 0x2bf5b6bdb4b68f8361ccba19437614edd7a98bf8f0d8fe8fe21a4f7cbfff1589 {
  "name": "Scam Notifier Alert",
  "description": "0x477aae186ec9a283ad225ba95ee959d15dbadc98 was flagged as a scam by 0xc574962311141cb505c09fd973c4630b8f7c4a81 🔴dev-will-dump-on-you🔴.eth",
  "alertId": "SCAM-NOTIFIER-EOA",
  "protocol": "ethereum",
  "severity": "High",
  "type": "Suspicious",
  "metadata": {
    "scammer_eoa": "0x477aae186ec9a283ad225ba95ee959d15dbadc98",
    "notifier_eoa": "0xc574962311141cb505c09fd973c4630b8f7c4a81",
    "notifier_name": "🔴dev-will-dump-on-you🔴.eth",
    "message": "42% of total supply was sent to caller.\n14% on uniswap\n20% locked from team\n24% hold by people.\n\nAvoid, unless you want get rugged by scam influencer that will dump on you. "
  },
  "addresses": [
    "0xc574962311141cb505c09fd973c4630b8f7c4a81",
    "0x477aae186ec9a283ad225ba95ee959d15dbadc98"
  ],
  "labels": [
    {
      "entityType": "Address",
      "entity": "0xc574962311141cb505c09fd973c4630b8f7c4a81",
      "label": "notifier_EOA",
      "confidence": 0.8,
      "remove": false,
      "metadata": {
        "ENS_NAME": "🔴dev-will-dump-on-you🔴.eth"
      }
    },
    {
      "entityType": "Address",
      "entity": "0x477aae186ec9a283ad225ba95ee959d15dbadc98",
      "label": "scammer_EOA",
      "confidence": 0.8,
      "remove": false,
      "metadata": {}
    }
  ]
}
```

#### SCAM-NOTIFIER-CONTRACT

```bash
1 findings for transaction 0x908446adf1cc7dbd99a24394bfb6fe3b36a80f1ce689848ab002d97e010a8259 {
  "name": "Scam Notifier Alert",
  "description": "0x579fa761387558cef6fee6e2548f74403a2cfa45 was flagged as a scam by 0xc574962311141cb505c09fd973c4630b8f7c4a81 🔴dev-will-dump-on-you🔴.eth",
  "alertId": "SCAM-NOTIFIER-CONTRACT",
  "protocol": "ethereum",
  "severity": "High",
  "type": "Suspicious",
  "metadata": {
    "scammer_contract": "0x579fa761387558cef6fee6e2548f74403a2cfa45",
    "scammer_eoa": "0xe01c1c3e575d7263a8674c7b3417200d9f4da7fb",
    "notifier_eoa": "0xc574962311141cb505c09fd973c4630b8f7c4a81",
    "notifier_name": "🔴dev-will-dump-on-you🔴.eth",
    "message": "Scam. Blacklisting "
  },
  "addresses": [
    "0xc574962311141cb505c09fd973c4630b8f7c4a81",
    "0x579fa761387558cef6fee6e2548f74403a2cfa45"
  ],
  "labels": [
    {
      "entityType": "Address",
      "entity": "0x579fa761387558cef6fee6e2548f74403a2cfa45",
      "label": "notifier_EOA",
      "confidence": 0.8,
      "remove": false,
      "metadata": {
        "ENS_NAME": "🔴dev-will-dump-on-you🔴.eth"
      }
    },
    {
      "entityType": "Address",
      "entity": "0x579fa761387558cef6fee6e2548f74403a2cfa45",
      "label": "scammer_Contract",
      "confidence": 0.8,
      "remove": false,
      "metadata": {}
    },
    {
      "entityType": "Address",
      "entity": "0xe01c1c3e575d7263a8674c7b3417200d9f4da7fb",
      "label": "scammer_EOA",
      "confidence": 0.8,
      "remove": false,
      "metadata": {}
    }
  ]
}
```

#### VICTIM-NOTIFIER-CONTRACT

```bash
[phishing approval]

1 findings for transaction 0x2b0e1f5d7d798c4c8e3e32741de44a83065ef2053252d9f0cdf0398e0bfb4870 {
  "name": "Scam Notifier Alert",
  "description": "0x666a3ce3f9438dccd4a885ba5b565f3035984793 metasleuth911.eth alerted 0xf143f21067e1271142a455d0df7d53c578800b21 from a MATIC phishing approval to 0xfb4d3eb37bde8fa4b52c60aabe55b3cd9908ec73",
  "alertId": "VICTIM-NOTIFIER-EOA",
  "protocol": "ethereum",
  "severity": "High",
  "type": "Exploit",
  "metadata": {
    "victim_eoa": "0xf143f21067e1271142a455d0df7d53c578800b21",
    "scammer_eoa": "0xfb4d3eb37bde8fa4b52c60aabe55b3cd9908ec73",
    "notifier_eoa": "0x666a3ce3f9438dccd4a885ba5b565f3035984793",
    "notifier_name": "metasleuth911.eth",
    "message": "Your token (MATIC) has been approved to the scammer (0xfb4d3eb37bde8fa4b52c60aabe55b3cd9908ec73). Please see the detailed report https://metasleuth.io/report?report_id=24850a6cf72a587a9a1ac0fe120845cf Revoke your approval to the scammer immediately to prevent further loss. Read this document on how to revoke your approval: https://docs.blocksec.com/metadock/features/approval-diagnosis "
  },
  "addresses": [
    "0x666a3ce3f9438dccd4a885ba5b565f3035984793",
    "0xf143f21067e1271142a455d0df7d53c578800b21"
  ],
  "labels": [
    {
      "entityType": "Address",
      "entity": "0x666a3ce3f9438dccd4a885ba5b565f3035984793",
      "label": "notifier_EOA",
      "confidence": 0.8,
      "remove": false,
      "metadata": {
        "ENS_NAME": "metasleuth911.eth"
      }
    },
    {
      "entityType": "Address",
      "entity": "0xf143f21067e1271142a455d0df7d53c578800b21",
      "label": "victim_EOA",
      "confidence": 0.8,
      "remove": false,
      "metadata": {}
    },
    {
      "entityType": "Address",
      "entity": "0xfb4d3eb37bde8fa4b52c60aabe55b3cd9908ec73",
      "label": "scammer_EOA",
      "confidence": 0.8,
      "remove": false,
      "metadata": {}
    }
  ]
}

[phishing transfer]

1 findings for transaction 0x73224d4846913a29964b243f4b1d73bd3ef1052f20130ba996e3d6bc8ee626ac {
  "name": "Scam Notifier Alert",
  "description": "0x666a3ce3f9438dccd4a885ba5b565f3035984793 metasleuth911.eth alerted 0x85f8ccb7aa80bd38a20ca1992cdc479707ee4c5b from a USDT phishing transfer to 0xf6728c9c78d3a794770960c37b4708e395fae079",
  "alertId": "VICTIM-NOTIFIER-EOA",
  "protocol": "ethereum",
  "severity": "High",
  "type": "Exploit",
  "metadata": {
    "victim_eoa": "0x85f8ccb7aa80bd38a20ca1992cdc479707ee4c5b",
    "scammer_eoa": "0xf6728c9c78d3a794770960c37b4708e395fae079",
    "notifier_eoa": "0x666a3ce3f9438dccd4a885ba5b565f3035984793",
    "notifier_name": "metasleuth911.eth",
    "extraInfo": "",
    "message": "Your token (USDT) has been transferred to 0xf6728c9c78d3a794770960c37b4708e395fae079. Since you have approved your token to a phishing address, we suspect this is a phishing attack. Please see the detailed report https://metasleuth.io/report?report_id=4f50fb859781cadb922c8e6ed90504ae Revoke your approval to the scammer immediately to prevent further loss. Read this document on how to revoke your approval: https://docs.blocksec.com/metadock/features/approval-diagnosis"
  },
  "addresses": [
    "0x666a3ce3f9438dccd4a885ba5b565f3035984793",
    "0x85f8ccb7aa80bd38a20ca1992cdc479707ee4c5b"
  ],
  "labels": [
    {
      "entityType": "Address",
      "entity": "0x666a3ce3f9438dccd4a885ba5b565f3035984793",
      "label": "notifier_EOA",
      "confidence": 0.8,
      "remove": false,
      "metadata": {
        "ENS_NAME": "metasleuth911.eth"
      }
    },
    {
      "entityType": "Address",
      "entity": "0x85f8ccb7aa80bd38a20ca1992cdc479707ee4c5b",
      "label": "victim_EOA",
      "confidence": 0.8,
      "remove": false,
      "metadata": {}
    },
    {
      "entityType": "Address",
      "entity": "0xf6728c9c78d3a794770960c37b4708e395fae079",
      "label": "scammer_EOA",
      "confidence": 0.8,
      "remove": false,
      "metadata": {}
    }
  ]
}

```

## Test Data

Given the challenge of identifying shared reports between known notifiers, a dataset has been created and tested against the database to ensure maximum accuracy. The method employed involved generating 10 reports from a single address and having another EOA create 2 reports that shared the same recipients.

On-Chain Testing was done to verify the ENS names and the address of the deployer EOA

Known Notifiers:

- 0xcd5496ef9d7fb6657c9f1a4a1753f645994fbfa9 (scamwarning.eth)
- 0xba6e11347856c79797af6b2eac93a8145746b4f9 (🛑scam-warning🛑.eth)
- 0xc574962311141cb505c09fd973c4630b8f7c4a81 (🔴dev-will-dump-on-you🔴.eth)

Special Case:

- 0x666a3ce3f9438dccd4a885ba5b565f3035984793 (metasleuth911.eth)
