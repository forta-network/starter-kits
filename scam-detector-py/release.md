# Scam Detector Bot Release Notes

## v0.1.26 (June 27th 2023 - prod)
- disable allium

## v0.1.25 (May 16th 2023 - beta; June 1st 2023 - prod)
- add manual alerting capability
- restricted the contract similarity bot to only operate on scams where a contract is essential:
    - SCAM-DETECTOR-SOCIAL-ENG-NATIVE-ICE-PHISHING
    - SCAM-DETECTOR-ADDRESS-POISONER


## v0.1.19 (May 9th 2023 - prod; May 1st 2023 - beta)
- refactored bot from utilizing graphQL library to handleAlert. This speeds up alerts.
- added sharding support to ensure no alerts are being dropped due to processing time of the alerts
- added persistence of findings/alerts cache, so no findings/alerts are lost upon a reassignment or restart
- fixes various parsing issues of base bot alerts

