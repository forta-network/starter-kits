# Beta Analysis Process

When developing features for the Attack Detector, those ought to be tested (after unit tests and local testing) on the network on one of the beta version of the Attack Detector. 

Features of course will influence how the Attack Detector behaves, but a side by side comparison between the Attack Detector prod and beta version will ensure it is behaving as expected. For instance, if FP mitigaiton features are added, one would expect an overall decrease in alerts emitted; if a new alert ID is introduced, one should observe this alert ID in the beta version.

This document outlines the process and type of checks that should be performed before elevating a beta version to production.

## Performance
As the network is sensitive to processing times of alerts, the bot health page ought to be reviewed across all networks between the two version. As nodes operate differently (e.g. different hardware), the charts may look different; however, one node should generally operate without errors/dropped alerts/transactions.

## Alerts
Given the beta and prod version behave differently by design (the beta emits, for instance, FP suppressed alerts and error alerts), alerts can't be simply compared using overall volume. Data needs to be obtained using the pullAlertsGraphQL.ipynb notebook and further analyzed in a spreadsheet. 

1. Ensure the Attack Detector Beta produces all the expected alert IDs (S2Beta - alertID Chain Distribu)
2. Ensure the alert ID/chain distribution between the beta and prod version is similar (S2 Beta vs Prod)
3. Ensure the overlap between the Attack Detector Beta alerts is at least 75% (some discrepancy is explainable given caching) to the prod version
4. Review the INFO alerts for the beta and ensure that the majority of errors are related to temporary network issues.

An example spreadsheet can be found at