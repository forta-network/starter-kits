Scam Detector has three deployments on the network:
- Scam Detector Beta (0x47c45816807d2eac30ba88745bf2778b61bc106bc76411b520a5289495c76db8) - this is usually the version to test out new features and threat categories. It usually resides on a beta branch named after the version of the bot (e.g. scam_detector_2_19)
- Scam Detector Prod Test (0xb27524b92bf27e6aa499a3a7239232ad425219b400d3c844269f4a657a4adf03) - this is temporary optional deployment to deploy a test production version. 
- Scam Detector (0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23) - this is the production version. It should map to the code that is checked into main. 

The deployment account for the Scam Detector is ad7547d09015664943d0a7c1bea47f28df298ec0. 

Deployment should happen through the following steps:
- If a new clone of the github repo has been done, one needs to obtain the secrets.json and put it into the local directory.
- Start docker locally
- deploy the scam detector to beta:
    - set the bot id in forta.config.json to 0x47c45816807d2eac30ba88745bf2778b61bc106bc76411b520a5289495c76db8
    - modify the package and package-lock.json to "name": "scam-detector-feed-beta" and "displayName": "Scam Detector Feed (beta)"
    - increase the version in package and package-lock.json
    - check release.md on which features are enabled/disabled for the beta version. This can be configured in constants.py by setting flags or commenting out bot subscriptions (note, disabling features may cause some unit tests to fail)
    - open a cmd prompt and set your environment:
        - conda activate forta
        - source $(brew --prefix nvm)/nvm.sh
        - nvm install 16
    - run the unit tests using 'npm run test'. all tests should pass. If they do not, run them within VS and debug.
    - run npm run start to ensure the bot runs locally without any crashes. Look for emitted findings in the output.
    - deploy the bot using npm run publish
    - capture this new version and deployment in release.md (including information on what features were disabled)
    - once deployed on the network, review the info alerts (for the beta version, recoverable errors are output that way) as well as alerts being raised for all chains. Review the bot logs for any errors. 
    - review the drop rate on the bot health page; review bot starts on the bot health page. Overall, those rates should be equivalent to previous rates
- deploy the scam detector to prod:
    - assuming the beta version is running properly without any errors, one can deploy the production version. note, some base bots may be disabled due to low precision. Those are noted in the release.md as specifically disabled and would need to be disabled in the constants.py
    - set the bot id in forta.config.json to 0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23 
    - modify the package and package-lock.json to "name": "scam-detector-feed" and "displayName": "Scam Detector Feed" (once set, the unit tests will not succeed, which is OK)
    - check release.md on which features are enabled/disabled for the prod version. This can be configured in constants.py by setting flags or commenting out bot subscriptions
    - open a cmd prompt and set your environment:
        - conda activate forta
        - source $(brew --prefix nvm)/nvm.sh
        - nvm install 16
    - run npm run start to ensure the bot runs locally without any crashes. Look for emitted findings in the output.
    - deploy the bot using npm run publish
    - capture this new version and deployment in release.md (including information on what features were disabled)
    - once deployed on the network, review alerts being raised for all chains. Review the bot logs for any errors. 
    - review the drop rate on the bot health page; review bot starts on the bot health page. Overall, those rates should be equivalent to previous rates

