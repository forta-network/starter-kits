# Stolen NFT Transfer Bot

## Description

This bot will raise an alert/ set a label whenever a NFT is transferred to a known scammer

## Supported Chains

- Ethereum

## Alerts

- POTENTIALLY-STOLEN-NFT-TRANSFER
  - Fired when a NFT transfer to a known scammer occurs
  - Severity is always set to "info"
  - Type is always set to "info" 
  - Meta data will contain information about the scammer the NFT is being transferred to.

## Label
For each stolen NFT, the bot will emit 'stolen-nft' ADDRESS label of id,address of the potentially stolen NFT. 


## Test Data

The agent behaviour can be verified with the following transactions:

- 0xadf57322c98922bf1a7607681bc71c6c1114196ce9fbc96ad4ce76da66a2fb53 
