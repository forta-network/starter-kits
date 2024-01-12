alertLabel.push({
  entityType: EntityType.Address,
  entity: `${record.fromAddr}`,
  label: "nft-phishing-victim",
  confidence: 0.8,
  remove: false,
  metadata: {}
})
alertLabel.push({
  entityType: EntityType.Address,
  entity: `${record.toAddr}`,
  label: "nft-phishing-attacker",
  confidence: 0.8,
  remove: false,
  metadata: {}
})
alertLabel.push({
  entityType: EntityType.Address,
  entity: `${tokenKey},${record.contractAddress}`,
  label: "nft-phising-transfer",
  confidence: 0.9,
  remove: false,
  metadata: {}
})


contract
  - id
    - from
    - to
  - id
    - from
    - to

if find has nft-sale-record push to info:
* const [tokenId, contractAddress] = label.entity.split(",");
contract and under it:
- token id

next label extract sender from entity on nft-sender
next label extract to from entity on nft-receiver

and add under local token id

 info['0x87'] = {
   '615': {
     from: '0xf',
     to: '0x3'
   },
   '7412': {
     from: '0x3',
     to: '0xf'
   }



if find has nft-sale-record push to info contract, ids, and parties

alertLabel.push({
  entityType: EntityType.Address,
  entity: `${tokenKey},${record.contractAddress}`,
  label: "nft-sale-record",
  confidence: 0.9,
  remove: false,
  metadata: {}
})
alertLabel.push({
  entityType: EntityType.Address,
  entity: `${record.fromAddr}`,
  label: "nft-sender",
  confidence: 0.8,
  remove: false,
  metadata: {}
})
alertLabel.push({
  entityType: EntityType.Address,
  entity: `${record.toAddr}`,
  label: "nft-receiver",
  confidence: 0.8,
  remove: false,
  metadata: {}
})