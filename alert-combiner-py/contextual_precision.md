Contextual precision is the percentage of protocols that receive no false positives in the last 60 days from the attack detector. It is crucial to understand in context of threat protection/ automated incident response. A low contextual precision would cause protocols to unnecessarily kick off incident response processes, which eventually would lead to loosing confidence in the Attack Detector. 

To meadure contextual precision, involves the following steps:
1. Obtain a random list of protocols and their addresses (using DefiLamaProtocols.ipynb)
2. Assess whether they received any attack detector alerts (protocol addresses from #1 are matched up with addresses listed in the alert) (Ayoola's tool located at https://github.com/Olugbenga2000/forta-attack-detector-analysis can be utilized)
3. Load results in spreadsheet and validate the following:
    a. Do the matched addresses indeed map to the protocol. If not, that alert can be removed as it doesnt pertain to the protocol assessed.
    b. Assess remaining alerts on whether they are false positives

    Results should look like:
    - protocol name, chain, IsFP 
4. Summarize the results per chain counting all the IsFP=False over all entries per chain.

Early contextual precision only takes into account alerts where the alertID is set to ATTACK-DETECTOR-PREPARATION. Repeat the above exercise, but filter out all other alertIDs. This will result in early contextual precision.