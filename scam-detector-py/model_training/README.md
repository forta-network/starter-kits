The Scam Detector utilizes a machine learning model for base bots whose precision is under the target of 80%. The model takes advantage of the fact that scammers are usually engaged in multiple scam techniques, which are all individually detected by various base bots. For instance, assume two bots whose precision is 60%: fraudulent nft trades and ice phishing. If we observe an account engaged in one of these and raise an alert, the precision is 60%. However, if that account is alerted to by both, an alert with higher precision can be emitted. This is the premise of the machine learning model. 

The machine learning model is trained on known scammers and randomly selected accounts. The feature vector consists of a count of alerts observed in the previous 7 days. 

Once a model has been trained, it needs to be added to the bot. The name, threshold, and feature vector are specified in the constants.py. In addition to specifying the feature vector, each bot/ alert ID needs to be specified in the BASEBOT parameter with the 'Combination' value. This will direct the Scam Detector to subscribe to the bots, but not raise an alert once an alert has been observed. 

Training of the model has been done a few months ago; it is likely that the training scripts will need to get adjusted as certain services are no longer available (e.g. allium was used in the past and need to be switched to Zettablock; some of these modifications have been tagged with TODOs in the notebooks)

The notebooks consist of:
1. Data collection (end_user_attack_model account_focused_allium_step1.ipynb)
2. Creating training data set (end_user_attack_model create_dataset_step2.ipynb)
3. Training the model (end_attack_model_step3.ipynb)

After a satisfactory model has been created, it should be deployed and evaluated on the beta version of the Scam Detector. Note, overall, the model threshold is set to achieve high precision; as a result, volume of alerts raised by the model is fairly small. 