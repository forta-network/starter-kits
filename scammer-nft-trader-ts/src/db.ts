import sqlite3 from "sqlite3";

// db.ts

const createTablesTest = (db: sqlite3.Database): Promise<void> => {
  const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      address TEXT PRIMARY KEY,
      tx_count INTEGER,
      recent_tx_count INTEGER,
      avg_holding_time REAL
    );
  `;

  const createTransactionsTable = `
    CREATE TABLE IF NOT EXISTS transactions (
      transaction_hash TEXT PRIMARY KEY,
      interacted_market TEXT,
      to_address TEXT,
      from_address TEXT,
      initiator TEXT,
      total_price REAL,
      avg_item_price REAL,
      contract_address TEXT,
      floor_price REAL,
      timestamp INTEGER,
      floor_price_diff TEXT,
      FOREIGN KEY (to_address) REFERENCES users (address),
      FOREIGN KEY (from_address) REFERENCES users (address)
    );
  `;

  const createNftsTable = `
    CREATE TABLE IF NOT EXISTS nfts (
    transaction_hash TEXT NOT NULL,
    token_id TEXT NOT NULL,
    name TEXT,
    price_value TEXT,
    price_currency_name TEXT,
    price_currency_decimals INTEGER,
    contract_address TEXT NOT NULL,
    FOREIGN KEY (transaction_hash) REFERENCES transactions (transaction_hash)
    );
  `;

  return Promise.all([
    new Promise<void>((resolve, reject) => {
      db.run(createUsersTable, (err) => {
        if (err) {
          console.error("Error creating users table:", err.message);
          reject(err);
        } else {
          console.log("Users table created or already exists");
          resolve();
        }
      });
    }),
    new Promise<void>((resolve, reject) => {
      db.run(createTransactionsTable, (err) => {
        if (err) {
          console.error("Error creating transactions table:", err.message);
          reject(err);
        } else {
          console.log("Transactions table created or already exists");
          resolve();
        }
      });
    }),
    new Promise<void>((resolve, reject) => {
      db.run(createNftsTable, (err) => {
        if (err) {
          console.error("Error creating nfts table:", err.message);
          reject(err);
        } else {
          console.log("Nfts table created or already exists");
          resolve();
        }
      });
    }),
  ]).then(() => {});
};

const initializeDb = async (): Promise<sqlite3.Database> => {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(":memory:", (err) => {
      if (err) {
        console.error(err.message);
        reject(err);
      } else {
        console.log("Connected to the in-memory SQLite database.");
        createTablesTest(db).then(() => resolve(db));
      }
    });
  });
};

export { initializeDb, createTablesTest };

const createTables = (db: sqlite3.Database) => {
  const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      address TEXT PRIMARY KEY,
      tx_count INTEGER,
      recent_tx_count INTEGER,
      avg_holding_time REAL
    );
  `;

  const createTransactionsTable = `
    CREATE TABLE IF NOT EXISTS transactions (
      transaction_hash TEXT PRIMARY KEY,
      interacted_market TEXT,
      to_address TEXT,
      from_address TEXT,
      initiator TEXT,
      total_price REAL,
      total_price_in_usd REAL,
      avg_item_price REAL,
      contract_address TEXT,
      floor_price REAL,
      currency TEXT,
      timestamp INTEGER,
      floor_price_diff TEXT,
      FOREIGN KEY (to_address) REFERENCES users (address),
      FOREIGN KEY (from_address) REFERENCES users (address)
    );
  `;

  const createNftsTable = `
    CREATE TABLE IF NOT EXISTS nfts (
    transaction_hash TEXT NOT NULL,
    token_id TEXT NOT NULL,
    name TEXT,
    price_value TEXT,
    price_currency_name TEXT,
    price_currency_decimals INTEGER,
    contract_address TEXT NOT NULL,
    FOREIGN KEY (transaction_hash) REFERENCES transactions (transaction_hash)
    );
  `;

  db.run(createUsersTable, (err) => {
    if (err) {
      console.error("Error creating users table:", err.message);
    } else {
      console.log("Users table created or already exists");
    }
  });

  db.run(createTransactionsTable, (err) => {
    if (err) {
      console.error("Error creating transactions table:", err.message);
    } else {
      console.log("Transactions table created or already exists");
    }
  });

  db.run(createNftsTable, (err) => {
    if (err) {
      console.error("Error creating nfts table:", err.message);
    } else {
      console.log("Nfts table created or already exists");
    }
  });
};

const db = new sqlite3.Database(":memory:", (err) => {
  if (err) {
    console.error(err.message);
  } else {
    console.log("Connected to the in-memory SQLite database.");
    createTables(db);
  }
});

export default db;
