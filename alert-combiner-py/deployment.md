# Attack Detector Deployment Guide

The Attack Detector has three deployments on the network:

- **Attack Detector Beta** (0xac82fb2a572c7c0d41dc19d24790db17148d1e00505596ebe421daf91c837799): This version is usually used to test new features and threat categories. It typically resides on a beta branch named after the bot's version (e.g. Attack_detector_2_19).

- **Attack Detector Beta Alt** (0x3172685467b021a6e6b9b0080edbf26e98d37eecd1ac90e89a8fa73b26e04e51): This serves as an alternate beta version, when multiple branches are in development.

- **Attack Detector** (0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1): This is the production version that should map to the code checked into the `main` branch.

The deployment account for the Attack Detector is `0xad7547d09015664943d0a7c1bea47f28df298ec0`.

## Deployment Steps

Deployment involves the following steps:

### Beta Deployment

1. Clone the GitHub repository and obtain `secrets.json`, placing it in the local directory.
2. Start Docker locally.
3. Deploy the Attack Detector to beta by:

   - Setting the bot ID in `forta.config.json` to beta: `0xac82fb2a572c7c0d41dc19d24790db17148d1e00505596ebe421daf91c837799`.
   - Setting the `fortaApiKey` in `forta.config.json` (Required to run/test the bot locally)
   - Modify `package` and `package-lock.json` to `"name": "attack-detector-feed-beta"` and `"displayName": "Attack Detector Feed (beta)"`.
   - Increase the version in `package` and `package-lock.json`.
   - Check `release.md` on which features are enabled/disabled for the beta version. This can be configured in `constants.py` by setting flags or commenting out bot subscriptions (note, disabling features may cause some unit tests to fail)
   - Open a cmd prompt and set your environment:

     ```bash
     conda activate forta
     source $(brew --prefix nvm)/nvm.sh
     nvm install 16
     ```

   - Run the unit tests using `npm run test` to ensure all tests pass. If they do not, run them within VS and debug.
   - Run `npm run start` to ensure the bot runs locally without any crashes. Look for emitted findings in the output.
   - Deploy the bot using `npm run publish`.
   - Update `release.md` with the new version and deployment details (including information on what features were disabled)
   - Once deployed on the network, review info alerts (for the beta version, recoverable errors are output that way) and raised alerts for all chains, checking bot logs for any errors.
   - Review drop rates and bot starts on the bot health page, ensuring they align with previous rates.

### Production Deployment

1. Assuming the beta version is running properly without any errors, one can deploy the production version. Note, some base bots may be disabled due to low precision. Those are noted in the `release.md` as specifically disabled and would need to be disabled in the `constants.py`
2. Configure the production deployment by:

   - Setting the bot ID in `forta.config.json` to `0x80ed808b586aeebe9cdd4088ea4dea0a8e322909c0e4493c993e060e89c09ed1`.
   - Setting the `fortaApiKey` in `forta.config.json` (Required to run/test the bot locally)
   - Modify the `package.json` and `package-lock.json` to `"name": "attack-detector-feed"` and `"displayName": "Attack Detector Feed"` (once set, the unit tests will not succeed, which is OK)
   - Check `release.md` on which features are enabled/disabled for the prod version. This can be configured in `constants.py` by setting flags or commenting out bot subscriptions
   - Open a cmd prompt and set your environment:

     ```bash
     conda activate forta
     source $(brew --prefix nvm)/nvm.sh
     nvm install 16
     ```

   - Run `npm run start` to ensure the bot runs locally without any crashes. Look for emitted findings in the output.
   - Deploy the bot using `npm run publish`.
   - Update `release.md` with the new version and deployment details (including information on what features were disabled)

   - Review drop rates and bot starts on the bot health page, ensuring they align with previous rates.
