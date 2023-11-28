import {
  Finding,
  Initialize,
  HandleTransaction,
  TransactionEvent,
  ethers,
  getEthersProvider,
} from "forta-agent";
import {
  createDriver,
  storeTransactionData,
  numberOfRecipients,
  recipientExists,
  checkNotifier,
} from "./db";
import {
  containsWords,
  logs,
  getAddressType,
  createScamNotifierAlert,
  extractData,
} from "./utils";
import { Driver } from "neo4j-driver";
import { getSecrets, secrets } from "./storage";

let neo4jDriver: Driver;
let keys: secrets;

const handleTransaction: HandleTransaction = async (
  txEvent: TransactionEvent
) => {
  const findings: Finding[] = [];
  const provider: ethers.providers.JsonRpcProvider = getEthersProvider();

  if (
    !txEvent.to ||
    !txEvent.transaction.data ||
    txEvent.to === ethers.constants.AddressZero
  ) {
    return findings;
  }

  try {
    // Check if the transaction has a valid message
    const decodedData = containsWords(txEvent);

    if (decodedData.isValid) {
      // check for metasleuth911.eth
      const extraData = extractData(decodedData.text);

      // Get the type and of the recipient address
      const recipientAddressType = await getAddressType(txEvent.to, provider);

      // Check if the sender is a notifier
      const isNotifier = await checkNotifier(
        neo4jDriver,
        txEvent.from.toLowerCase()
      );

      let newFinding: Finding | undefined = undefined;

      if (isNotifier) {
        // All Notifiers transactions are saved in the DB
        const storeRes = await storeTransactionData(
          neo4jDriver,
          txEvent.from,
          txEvent.to,
          txEvent.hash,
          recipientAddressType,
          decodedData.text,
          isNotifier
        );
        logs(
          txEvent,
          storeRes,
          `[Notifier] Saved transaction data ${txEvent.hash} msg: ${decodedData.text}`
        );

        // If the sender is alerting a victim
        if (extraData) {
          newFinding = await createScamNotifierAlert(
            "VICTIM",
            txEvent,
            keys,
            extraData
          );
        }
        // If the recipient is an EOA, create the alert SCAM-NOTIFIER-EOA
        else if (recipientAddressType === "EOA") {
          newFinding = await createScamNotifierAlert("EOA", txEvent, keys);
        }
        // If the recipient is a contract, create the alert SCAM-NOTIFIER-CONTRACT
        else {
          newFinding = await createScamNotifierAlert("CONTRACT", txEvent, keys);
        }

        logs(
          txEvent,
          true,
          `ScamNotifierAlert Triggered ${txEvent.from} ` + txEvent.hash
        );
      } else {
        // Check that the recipient address is already in the DB
        const recipientExistsInDB = await recipientExists(
          neo4jDriver,
          txEvent.to
        );

        // If the recipient exists in the DB, save the transaction data
        // The sender is set to Regular User.
        // No unrelated data exists in the DB.
        if (recipientExistsInDB) {
          const storeRes = await storeTransactionData(
            neo4jDriver,
            txEvent.from,
            txEvent.to,
            txEvent.hash,
            recipientAddressType,
            decodedData.text,
            isNotifier
          );
          logs(
            txEvent,
            storeRes,
            `[Regular] Saved transaction data ${txEvent.hash} msg: ${decodedData.text}`
          );

          let recipientNums = await numberOfRecipients(
            neo4jDriver,
            txEvent.from
          );

          // Change sender type to notifier if the sender has sent more than 2 transactions
          // NOTE: The new notifier needs to be added manually as of the last update (Nov 2023)
          if (recipientNums.length >= 2) {
            //console.log("ADDRESS TYPE CHANGED TO NOTIFIER");
            //await setAddressTypeToNotifier(neo4jDriver, txEvent.from);
            logs(
              txEvent,
              true,
              `New Notifier Added ${txEvent.from} ` + txEvent.hash
            );

            const data = {
              sharingAddress: recipientNums[0],
              sharedRecipients: recipientNums,
            };
            newFinding = await createScamNotifierAlert(
              "NEW_NOTIFIER",
              txEvent,
              keys,
              extraData,
              data
            );
          }
        }
      }

      if (!newFinding) {
        return findings;
      }

      newFinding.metadata.message = decodedData.text;
      findings.push(newFinding);
    }
  } catch (error) {
    logs(txEvent, false, "Error in handleTransaction \n" + error);
  }

  return findings;
};

const initialize: Initialize = async (test?: boolean) => {
  keys = (await getSecrets()) as secrets;
  if (test) {
    neo4jDriver = createDriver(keys, "TEST");
  } else {
    neo4jDriver = createDriver(keys);
  }
};

export default {
  initialize,
  handleTransaction,
};
