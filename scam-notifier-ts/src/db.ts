import {
  Driver,
  Result,
  auth,
  driver as createDriverInstance,
} from "neo4j-driver";
import { secrets } from "./storage";

export function createDriver(keys: secrets, flag?: string): any {
  const {
    NEO4J_USERNAME: user,
    TEST_NEO4J_URI,
    TEST_NEO4J_PASSWORD,
    PROD_NEO4J_URI,
    PROD_NEO4J_PASSWORD,
  } = keys.apiKeys.scamNotifier;
  const uri = flag === "TEST" ? TEST_NEO4J_URI : PROD_NEO4J_URI;
  const password = flag === "TEST" ? TEST_NEO4J_PASSWORD : PROD_NEO4J_PASSWORD;

  const driver = createDriverInstance(uri, auth.basic(user, password));
  console[driver ? "log" : "error"](
    driver ? "Driver created successfully." : "Failed to create a driver."
  );

  return driver;
}

async function runQuery(
  driver: Driver,
  query: string,
  params: Record<string, any> = {}
): Promise<Result> {
  const session = driver.session();
  try {
    const result = await session.run(query, params);
    return result;
  } finally {
    await session.close();
  }
}

async function storeTransactionData(
  driver: Driver,
  from: string,
  to: string,
  hash: string,
  toType: string,
  data: string,
  isNotifier?: boolean
): Promise<boolean> {
  const session = driver.session();

  try {
    const checkQuery = `
        MATCH (tx:Transaction {hash: $hash})
        RETURN tx
      `;

    const checkResult = await session.run(checkQuery, { hash });

    if (checkResult.records.length > 0) {
      console.log("Transaction with the given hash already exists.");
      return false;
    }

    let query: string;
    if (isNotifier) {
      console.log("Adding tx to notifier node");
      query = `
          MERGE (from:Address {address: $from, type: 'Notifier'})
          MERGE (to:Recipient {address: $to, type: $toType})
          CREATE (tx:Transaction {hash: $hash, data: $data})
          CREATE (from)-[:SENT_BY]->(tx)
          CREATE (tx)-[:RECEIVED_BY]->(to)
          `;
    } else {
      query = `
          MERGE (from:Address {address: $from, type: 'Regular'})
          MERGE (to:Recipient {address: $to, type: $toType})
          CREATE (tx:Transaction {hash: $hash, data: $data})
          CREATE (from)-[:SENT_BY]->(tx)
          CREATE (tx)-[:RECEIVED_BY]->(to)
          `;
    }

    const result = await session.run(query, { from, to, hash, toType, data });

    if (result.summary.counters.updates()) {
      console.log("Transaction data saved successfully.");
      return true;
    } else {
      console.log("An error occurred while saving the transaction data.");
      return false;
    }
  } catch (error) {
    console.error(
      "An error occurred while saving the transaction data:",
      error
    );
    return false;
  } finally {
    await session.close();
  }
}

async function deleteAllData(driver: Driver): Promise<boolean> {
  const session = driver.session();

  try {
    const query = `
        MATCH (n)
        DETACH DELETE n
      `;

    await session.run(query);
    console.log("All data has been deleted from the database.");
    return true;
  } catch (error) {
    console.error("An error occurred while deleting the data:", error);
    return false;
  } finally {
    await session.close();
  }
}

export async function checkNotifier(
  driver: Driver,
  address: string
): Promise<boolean> {
  const query = `
      MATCH (a:Address {address: $address})
      WHERE a.type = 'Notifier'
      RETURN a
      LIMIT 1
    `;
  const params = { address };
  const result = await runQuery(driver, query, params);
  return result.records.length > 0;
}

export async function notifierCount(driver: Driver): Promise<number> {
  const query = `
    MATCH (from:Address)-[:SENT_BY]->(:Transaction)
    RETURN COUNT(DISTINCT from) as numberOfFromNodes
    `;
  const result = await runQuery(driver, query);
  const count = result.records[0].get("numberOfFromNodes").toNumber();
  return count;
}

export async function recipientExists(
  driver: Driver,
  address: string
): Promise<number> {
  const query = `
  MATCH (r:Recipient {address: "${address}"})
  RETURN COUNT(r) > 0 as recipientExists;  
  `;
  const result = await runQuery(driver, query);
  const count = result.records[0].get("recipientExists");
  return count;
}

export async function senderExists(
  driver: Driver,
  address: string
): Promise<number> {
  const query = `
  MATCH (r:Address {address: "${address}"})
  RETURN COUNT(r) > 0 as senderExists;  
  `;
  const result = await runQuery(driver, query);
  const count = result.records[0].get("senderExists");
  return count;
}

export async function numberOfRecipients(
  driver: Driver,
  address: string
): Promise<string[]> {
  const query = `
  MATCH (a:Address {address: '${address}'})-[:SENT_BY]->(tx:Transaction)-[:RECEIVED_BY]->(r:Recipient)
  WITH r, COUNT(r) AS numberOfRecipients
  MATCH (otherA:Address)-[:SENT_BY]->(:Transaction)-[:RECEIVED_BY]->(r)
  WHERE otherA.address <> '${address}'
  RETURN numberOfRecipients, COLLECT(DISTINCT otherA) AS otherAddresses
  `;
  const result = await runQuery(driver, query);
  const otherAddresses = result.records[0]
    ? result.records[0].get("otherAddresses")
    : [];
  const addressArray = otherAddresses.map(
    (node: any) => node.properties.address
  );
  return addressArray;
}

export async function sharedReportsCount(
  driver: Driver,
  address: string
): Promise<number> {
  const query = `
    MATCH (from1:Address)-[:SENT_BY]->(tx1:Transaction)-[:RECEIVED_BY]->(to:Recipient),
    (from2:Address)-[:SENT_BY]->(tx2:Transaction)-[:RECEIVED_BY]->(to)
    WHERE from1.address = "${address}" AND from1 <> from2 AND (to.type = 'EOA' OR to.type = 'CONTRACT')
    RETURN COUNT(DISTINCT to) as sharedReceivers

    `;
  const result = await runQuery(driver, query);
  const count = result.records[0].get("sharedReceivers").toNumber();
  return count;
}

export async function findMostCommonRecipient(
  driver: Driver,
  address: string
): Promise<{ sharingAddress: string; sharedRecipients: string }> {
  const query = `
      MATCH (from1:Address)-[:SENT_BY]->(tx1:Transaction)-[:RECEIVED_BY]->(to:Recipient),
            (from2:Address)-[:SENT_BY]->(tx2:Transaction)-[:RECEIVED_BY]->(to)
      WHERE from1.address = "${address}" AND from1 <> from2 AND (to.type = 'EOA' OR to.type = 'CONTRACT')
      WITH from2, COUNT(DISTINCT to) as sharedRecepients
      ORDER BY sharedRecepients DESC
      LIMIT 1
      MATCH (from2)-[:SENT_BY]->(:Transaction)-[:RECEIVED_BY]->(sharedRecipient:Recipient)
      WHERE (sharedRecipient.type = 'EOA' OR sharedRecipient.type = 'CONTRACT')
      AND sharedRecipient IN [(from1)-[:SENT_BY]->(:Transaction)-[:RECEIVED_BY]->(sr:Recipient) WHERE from1.address = "${address}" | sr]
      RETURN from2.address as sharingAddress, COLLECT(DISTINCT sharedRecipient.address) as sharedRecipients
    `;

  const result = await runQuery(driver, query);
  const sharingAddress = result.records[0].get("sharingAddress");
  const sharedRecipientsArray = result.records[0].get("sharedRecipients");
  const sharedRecipients = sharedRecipientsArray.join(", ");

  return { sharingAddress, sharedRecipients };
}

export async function setAddressTypeToNotifier(
  driver: Driver,
  address: string
): Promise<boolean> {
  const query = `
      MERGE (addr:Address {address: $address})
      ON CREATE SET addr.type = "Notifier"
      ON MATCH SET addr.type = "Notifier"
  `;

  try {
    const result = await runQuery(driver, query, { address });

    if (result.summary.counters.updates()) {
      console.log("Address type updated to Notifier.");
      return true;
    } else {
      console.log("An error occurred while updating the address type.");
      return false;
    }
  } catch (error) {
    console.error("An error occurred while updating the address type:", error);
    return false;
  }
}

export { storeTransactionData, deleteAllData, runQuery };
