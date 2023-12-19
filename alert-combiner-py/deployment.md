Attack Detector has three deployments on the network:
- Attack Detector Beta (0xac82fb2a572c7c0d41dc19d24790db17148d1e00505596ebe421daf91c837799) - this is usually the version to test out new features and threat categories. It usually resides on a beta branch named after the version of the bot (e.g. Attack_detector_2_19)
- Attack Detector Beta Alt (0x3172685467b021a6e6b9b0080edbf26e98d37eecd1ac90e89a8fa73b26e04e51) - this is an alternate beta version if multiple branches are in development. 
- Attack Detector (0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1) - this is the production version. It should map to the code that is checked into main. 

The deployment account for the Attack Detector is ad7547d09015664943d0a7c1bea47f28df298ec0. 

Deployment should happen through the following steps:
- If a new clone of the github repo has been done, one needs to obtain the secrets.json and put it into the local directory.
- Start docker locally
- deploy the Attack detector to beta:
    - set the bot id in forta.config.json to beta: 0xac82fb2a572c7c0d41dc19d24790db17148d1e00505596ebe421daf91c837799
    - modify the package and package-lock.json to "name": "Attack-detector-feed-beta" and "displayName": "Attack Detector Feed (beta)"
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
- deploy the Attack detector to prod:
    - assuming the beta version is running properly without any errors, one can deploy the production version. note, some base bots may be disabled due to low precision. Those are noted in the release.md as specifically disabled and would need to be disabled in the constants.py
    - set the bot id in forta.config.json to 0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1 
    - modify the package and package-lock.json to "name": "Attack-detector-feed" and "displayName": "Attack Detector Feed" (once set, the unit tests will not succeed, which is OK)
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

