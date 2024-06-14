import fs from 'fs';
import { parse, ParseRemoteConfig, ParseResult } from 'papaparse';
import { createAddress } from "forta-agent-tools";
import TruePositiveFetcher from "./truePositive.fetcher";
import { TruePositiveCsv } from "./types";

jest.mock('papaparse', () => ({
    parse: jest.fn(),
}));
jest.mock('fs');
jest.mock("node-fetch");

const mockTpListUrl = "https://mock.url.com//mock_tp_list.csv";
const mockTpListPath = "mock_tp_list_path.csv";

describe("TruePositiveFetcher Test Suite", () => {
    let mockFetch = jest.mocked(fetch, { shallow: true });
    let fetcher: TruePositiveFetcher;
    const mockAttackers = new Map<string, { origin: string; hops: number }>();
    const mockAttacker = createAddress("0x0123");

    beforeAll(() => {
      fetcher = new TruePositiveFetcher(mockTpListUrl, mockTpListPath);
    });

    afterEach(() => {
      jest.clearAllMocks();
      mockAttackers.clear();
    });
  

    it("should fetch True Positive List remotely", async () => {
        global.fetch = jest.fn(() =>
            Promise.resolve({
                ok: true,
                status: 200,
                text: () =>
                    Promise.resolve(JSON.stringify({ Attacker: mockAttacker })),
            }) as Promise<Response>
        );

        const mockResult: ParseResult<TruePositiveCsv> = {
            data: [{ Attacker: mockAttacker }],
            errors: [],
            // Mock values, since required
            meta: {
            delimiter: "",
            linebreak: "",
            aborted: false,
            truncated: false,
            cursor: 0
            },
        };

        // Mock `complete` inside of `parse()` from `papaparse`
        (parse as jest.Mock).mockImplementation((input: string, options: ParseRemoteConfig<TruePositiveCsv>) => {
            options.complete!(mockResult, mockTpListPath)
        });

        const spy = jest.spyOn(console, "log").mockImplementation(() => {});

        await fetcher.getTruePositiveList(mockAttackers);

        expect(mockAttackers.has(mockAttacker)).toBe(true);
        expect(mockAttackers.get(mockAttacker)).toEqual({
            origin: 'True Positive List',
            hops: 0,
        });
        expect(spy).toHaveBeenCalledTimes(0);
    });

    it("should fetch True Positive List locally, after failing to do so remotely - error in `fetch()`", async () => {
        global.fetch = jest.fn(() =>
            Promise.resolve({
                ok: false,
                status: 400,
            }) as Promise<Response>
        );

        const mockResult: ParseResult<TruePositiveCsv> = {
            data: [{ Attacker: mockAttacker }],
            errors: [],
            // Mock values, since required
            meta: {
            delimiter: "",
            linebreak: "",
            aborted: false,
            truncated: false,
            cursor: 0
            },
        };

        // Mock `complete` inside of `parse()` from `papaparse`
        (parse as jest.Mock).mockImplementation((input: string, options: ParseRemoteConfig<TruePositiveCsv>) => {
            options.complete!(mockResult, mockTpListPath)
        });

        const spy = jest.spyOn(console, "log").mockImplementation(() => {});

        await fetcher.getTruePositiveList(mockAttackers);

        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy).toHaveBeenCalledWith("'getTruePositiveListRemotely' failed. Error: Failed to fetch remote True Positive list");
        expect(mockAttackers.has(mockAttacker)).toBe(true);
        expect(mockAttackers.get(mockAttacker)).toEqual({
            origin: 'True Positive List',
            hops: 0,
        });
    });

    it("should fetch True Positive List locally, after failing to do so remotely - error in `complete()` fallback results", async () => {
        global.fetch = jest.fn(() =>
            Promise.resolve({
                ok: true,
                status: 200,
                text: () =>
                    Promise.resolve(JSON.stringify({ Attacker: mockAttacker })),
            }) as Promise<Response>
        );

        const mockErrorMessage = "Parse() returned error in results";
        // This result will cause the `getTruePositiveListRemotely` to error out,
        // then proceed to `getTruePositiveListLocally`.
        const mockResultOne: ParseResult<TruePositiveCsv> = {
            data: [],
            // `type` and `code` have legitimate values,
            // as required by `ParseError` type.
            errors: [{
                type: "Delimiter",
                code: "UndetectableDelimiter",
                message: mockErrorMessage,
                row: 0,
            }],
            // Mock values, since required
            meta: {
            delimiter: "",
            linebreak: "",
            aborted: false,
            truncated: false,
            cursor: 0
            },
        };
        const mockResultTwo: ParseResult<TruePositiveCsv> = {
            data: [{ Attacker: createAddress("0x0123") }],
            errors: [],
            // Mock values, since required
            meta: {
            delimiter: "",
            linebreak: "",
            aborted: false,
            truncated: false,
            cursor: 0
            },
        };

        (fs.readFileSync as jest.Mock).mockReturnValue("");

        // Mock `complete` inside of `parse()` from `papaparse`
        (parse as jest.Mock).mockImplementationOnce((input: string, options: ParseRemoteConfig<TruePositiveCsv>) => {
            options.complete!(mockResultOne, mockTpListPath)
        }).mockImplementationOnce((input: string, options: ParseRemoteConfig<TruePositiveCsv>) => {
            options.complete!(mockResultTwo, mockTpListPath)
        });

        const spy = jest.spyOn(console, "log").mockImplementation(() => {});

        await fetcher.getTruePositiveList(mockAttackers);

        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy).toHaveBeenCalledWith(`'getTruePositiveListRemotely' failed. Error: ${mockErrorMessage}`);
        expect(mockAttackers.has(mockAttacker)).toBe(true);
        expect(mockAttackers.get(mockAttacker)).toEqual({
            origin: 'True Positive List',
            hops: 0,
        });
    });

    it("should fetch True Positive List locally, after failing to do so remotely - `error()` fallback invoked", async () => {
        global.fetch = jest.fn(() =>
            Promise.resolve({
                ok: true,
                status: 200,
                text: () =>
                    Promise.resolve(JSON.stringify({ Attacker: mockAttacker })),
            }) as Promise<Response>
        );

        // This result will cause the `getTruePositiveListRemotely` to error out,
        // then proceed to `getTruePositiveListLocally`.
        const errorMessage = "Failure to fetch True Positive List remotely.";
        const mockError = {
            name: "error",
            message: errorMessage
        };
        const mockResult: ParseResult<TruePositiveCsv> = {
            data: [{ Attacker: createAddress("0x0123") }],
            errors: [],
            // Mock values, since required
            meta: {
            delimiter: "",
            linebreak: "",
            aborted: false,
            truncated: false,
            cursor: 0
            },
        };

        (fs.readFileSync as jest.Mock).mockReturnValue("");

        // Mock `error` and `complete` inside of `parse()` from `papaparse`
        (parse as jest.Mock).mockImplementationOnce((input: string, options: ParseRemoteConfig<TruePositiveCsv>) => {
            options.error!(mockError, mockTpListPath)
        }).mockImplementationOnce((input: string, options: ParseRemoteConfig<TruePositiveCsv>) => {
            options.complete!(mockResult, mockTpListPath)
        });

        const spy = jest.spyOn(console, "log").mockImplementation(() => {});

        await fetcher.getTruePositiveList(mockAttackers);

        expect(spy).toHaveBeenCalledTimes(1);
        expect(spy).toHaveBeenCalledWith(`'getTruePositiveListRemotely' failed. Error: ${errorMessage}`);
        expect(mockAttackers.has(mockAttacker)).toBe(true);
        expect(mockAttackers.get(mockAttacker)).toEqual({
            origin: 'True Positive List',
            hops: 0,
        });
    });

    it("will handle errors on both True Positive List fetching functions by not fetching anything - error in `fetch()`", async () => {
        global.fetch = jest.fn(() =>
            Promise.resolve({
                ok: false,
                status: 400,
            }) as Promise<Response>
        );

        const mockErrorMessage = "Parse() returned error in results";
        // This result will cause the `getTruePositiveListRemotely` to error out,
        // then proceed to `getTruePositiveListLocally`, which will also error out.
        const mockResult: ParseResult<TruePositiveCsv> = {
            data: [],
            // `type` and `code` have legitimate values,
            // as required by `ParseError` type.
            errors: [{
                type: "Delimiter",
                code: "UndetectableDelimiter",
                message: mockErrorMessage,
                row: 0,
            }],
            // Mock values, since required
            meta: {
            delimiter: "",
            linebreak: "",
            aborted: false,
            truncated: false,
            cursor: 0
            },
        };

        // Mock `complete` inside of `parse()` from `papaparse`
        (parse as jest.Mock).mockImplementation((input: string, options: ParseRemoteConfig<TruePositiveCsv>) => {
            options.complete!(mockResult, mockTpListPath)
        });

        const spy = jest.spyOn(console, "log").mockImplementation(() => {});

        await fetcher.getTruePositiveList(mockAttackers);

        // Confirm it registers `console.log`s inside of the nested `try/catch`s.
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy).toHaveBeenCalledWith("'getTruePositiveListRemotely' failed. Error: Failed to fetch remote True Positive list");
        expect(spy).toHaveBeenCalledWith(`Both True Positive List fetching functions failed. Error: ${mockErrorMessage}`);
        expect(mockAttackers.has(mockAttacker)).toBe(false);
        expect(mockAttackers.size).toBe(0)
    });

    it("will handle errors on both True Positive List fetching functions by not fetching anything - error in `complete()` fallback results", async () => {
        global.fetch = jest.fn(() =>
            Promise.resolve({
                ok: true,
                status: 200,
                text: () =>
                    Promise.resolve(JSON.stringify({ Attacker: mockAttacker })),
            }) as Promise<Response>
        );

        const mockErrorMessage = "Parse() returned error in results";
        // This result will cause the `getTruePositiveListRemotely` to error out,
        // then proceed to `getTruePositiveListLocally`, which will also error out.
        const mockResult: ParseResult<TruePositiveCsv> = {
            data: [],
            // `type` and `code` have legitimate values,
            // as required by `ParseError` type.
            errors: [{
                type: "Delimiter",
                code: "UndetectableDelimiter",
                message: mockErrorMessage,
                row: 0,
            }],
            // Mock values, since required
            meta: {
            delimiter: "",
            linebreak: "",
            aborted: false,
            truncated: false,
            cursor: 0
            },
        };

        // Mock `complete` inside of `parse()` from `papaparse`
        (parse as jest.Mock).mockImplementation((input: string, options: ParseRemoteConfig<TruePositiveCsv>) => {
            options.complete!(mockResult, mockTpListPath)
        });

        const spy = jest.spyOn(console, "log").mockImplementation(() => {});

        await fetcher.getTruePositiveList(mockAttackers);

        // Confirm it registers `console.log`s inside of the nested `try/catch`s.
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy).toHaveBeenCalledWith(`'getTruePositiveListRemotely' failed. Error: ${mockErrorMessage}`);
        expect(spy).toHaveBeenCalledWith(`Both True Positive List fetching functions failed. Error: ${mockErrorMessage}`);
        expect(mockAttackers.has(mockAttacker)).toBe(false);
        expect(mockAttackers.size).toBe(0)
    });

    it("will handle errors on both True Positive List fetching functions by not fetching anything - `error()` fallback invoked", async () => {
        global.fetch = jest.fn(() =>
            Promise.resolve({
                ok: true,
                status: 200,
                text: () =>
                    Promise.resolve(JSON.stringify({ Attacker: mockAttacker })),
            }) as Promise<Response>
        );

        // This result will cause the `getTruePositiveListRemotely` to error out,
        // then proceed to `getTruePositiveListLocally`, which will also error out.
        const errorMessage = "Failure to fetch True Positive List.";
        const mockError = {
            name: "error",
            message: errorMessage
        };

        // Mock `complete` inside of `parse()` from `papaparse`
        (parse as jest.Mock).mockImplementation((input: string, options: ParseRemoteConfig<TruePositiveCsv>) => {
            options.error!(mockError, mockTpListPath)
        });

        const spy = jest.spyOn(console, "log").mockImplementation(() => {});

        await fetcher.getTruePositiveList(mockAttackers);

        // Confirm it registers `console.log`s inside of the nested `try/catch`s.
        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy).toHaveBeenCalledWith(`'getTruePositiveListRemotely' failed. Error: ${errorMessage}`);
        expect(spy).toHaveBeenCalledWith(`Both True Positive List fetching functions failed. Error: ${errorMessage}`);
        expect(mockAttackers.has(mockAttacker)).toBe(false);
        expect(mockAttackers.size).toBe(0)
    });

    it("should properly filter out non-Ethereum addresses from the True Positive List", async () => {
        const solanaAddress = "AbspkW98TmLKL9y2Ce8cC1RqrQVjqW4ybe2UN6gqkhxE";
        const cosmosAddress = "cosmos1uwyd7q4ltgfty64w3u3mcy5y65ffxqcas2hz6d";

        global.fetch = jest.fn(() =>
            Promise.resolve({
                ok: true,
                status: 200,
                text: () =>
                    Promise.resolve(JSON.stringify([
                        { Attacker: mockAttacker },
                        { Attacker: solanaAddress },
                        { Attacker: cosmosAddress }
                    ])),
            }) as Promise<Response>
        );

        const mockResult: ParseResult<TruePositiveCsv> = {
            data: [
                { Attacker: mockAttacker },
                { Attacker: solanaAddress },
                { Attacker: cosmosAddress }
            ],
            errors: [],
            // Mock values, since required
            meta: {
            delimiter: "",
            linebreak: "",
            aborted: false,
            truncated: false,
            cursor: 0
            },
        };

        // Mock `complete` inside of `parse()` from `papaparse`
        (parse as jest.Mock).mockImplementation((input: string, options: ParseRemoteConfig<TruePositiveCsv>) => {
            options.complete!(mockResult, mockTpListPath)
        });

        const spy = jest.spyOn(console, "log").mockImplementation(() => {});

        await fetcher.getTruePositiveList(mockAttackers);

        expect(spy).toHaveBeenCalledTimes(2);
        expect(spy).toHaveBeenCalledWith(`Non-Ethereum address True Positive list entry found: ${solanaAddress}`);
        expect(spy).toHaveBeenCalledWith(`Non-Ethereum address True Positive list entry found: ${cosmosAddress}`);
        expect(mockAttackers.has(mockAttacker)).toBe(true);
        expect(mockAttackers.get(mockAttacker)).toEqual({
            origin: 'True Positive List',
            hops: 0,
        });
        expect(mockAttackers.has(solanaAddress)).toBe(false);
        expect(mockAttackers.has(cosmosAddress)).toBe(false);
        expect(mockAttackers.size).toBe(1)
    });
});