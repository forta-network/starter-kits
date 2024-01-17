import { initializeDb, createTablesTest } from './db';

jest.setTimeout(10000);

test('Connect to in-memory SQLite database and create tables', async () => {
  const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});

  const db = await initializeDb();

  expect(logSpy).toHaveBeenCalledWith('Connected to the in-memory SQLite database.');

  const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

  await createTablesTest(db);

  expect(logSpy).toHaveBeenCalledWith('Users table created or already exists');
  expect(logSpy).toHaveBeenCalledWith('Transactions table created or already exists');
  expect(logSpy).toHaveBeenCalledWith('Nfts table created or already exists');

  expect(errorSpy).toHaveBeenCalledTimes(0);

  logSpy.mockRestore();
  errorSpy.mockRestore();
});
