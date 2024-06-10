import { parse, ParseRemoteConfig, ParseResult } from 'papaparse';
import { createAddress } from "forta-agent-tools";
import TruePositiveFetcher from "./truePositive.fetcher";
import { TruePositiveCsv } from "./types";

// Mock the `papaparse` module
jest.mock('papaparse', () => ({
    parse: jest.fn(),
}));

const mockTpListUrl = "https://raw.testurl.com//tp_list.csv";
// Though empty, we need a valid csv file for `getTruePositiveListLocally`
const mockTpListPath = "../test_tp_list.csv";

describe("TruePositiveFetcher Test Suite", () => {
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

        // Mock `complete` inside of `parse()` from `papaparse`
        (parse as jest.Mock).mockImplementation((input: string, options: ParseRemoteConfig<TruePositiveCsv>) => {
            options.complete!(mockResult, mockTpListPath)
        });

        await fetcher.getTruePositiveList(mockAttackers);

        expect(mockAttackers.has(mockAttacker)).toBe(true);
        expect(mockAttackers.get(mockAttacker)).toEqual({
            origin: 'True Positive List',
            hops: 0,
        });
    });

    it("should fetch True Positive List locally, after failing to do so remotely", async () => {
        // This result will cause the `getTruePositiveListRemotely` to error out,
        // then proceed to `getTruePositiveListLocally`.
        const mockResultOne: ParseResult<TruePositiveCsv> = {
            data: [],
            // `type` and `code` have legitimate values,
            // as required by `ParseError` type.
            errors: [{
                type: "Delimiter",
                code: "UndetectableDelimiter",
                message: "",
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

        // Mock `complete` inside of `parse()` from `papaparse`
        (parse as jest.Mock).mockImplementationOnce((input: string, options: ParseRemoteConfig<TruePositiveCsv>) => {
            options.complete!(mockResultOne, mockTpListPath)
        }).mockImplementationOnce((input: string, options: ParseRemoteConfig<TruePositiveCsv>) => {
            options.complete!(mockResultTwo, mockTpListPath)
        });

        const spy = jest.spyOn(console, "log").mockImplementation(() => {});

        await fetcher.getTruePositiveList(mockAttackers);

        expect(spy).toHaveBeenCalledWith("'getTruePositiveListRemotely' failed. Error: getTruePositiveListRemotely() failed.");
        expect(mockAttackers.has(mockAttacker)).toBe(true);
        expect(mockAttackers.get(mockAttacker)).toEqual({
            origin: 'True Positive List',
            hops: 0,
        });
    });

    it("will handle errors on both True Positive List fetching functions by not fetching anything", async () => {
        // This result will cause the `getTruePositiveListRemotely` to error out,
        // then proceed to `getTruePositiveListLocally`.
        const mockResult: ParseResult<TruePositiveCsv> = {
            data: [],
            // `type` and `code` have legitimate values,
            // as required by `ParseError` type.
            errors: [{
                type: "Delimiter",
                code: "UndetectableDelimiter",
                message: "",
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

        expect(spy).toHaveBeenCalledWith("'getTruePositiveListRemotely' failed. Error: getTruePositiveListRemotely() failed.");
        expect(spy).toHaveBeenCalledWith("Both True Positive List fetching functions failed. Error: getTruePositiveListLocally() failed.");
        // Confirm it registers `console.log`s inside of the nested `try/catch`s.
        expect(spy).toHaveBeenCalledTimes(2);
        expect(mockAttackers.has(mockAttacker)).toBe(false);
        expect(mockAttackers.size).toBe(0)
    });

    it("should properly filter out non-Ethereum addresses from the True Positive List", async () => {
        const solanaAddress = "AbspkW98TmLKL9y2Ce8cC1RqrQVjqW4ybe2UN6gqkhxE";
        const cosmosAddress = "cosmos1uwyd7q4ltgfty64w3u3mcy5y65ffxqcas2hz6d";

        const mockResult: ParseResult<TruePositiveCsv> = {
            data: [
                { Attacker: createAddress("0x0123") },
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

        expect(mockAttackers.has(mockAttacker)).toBe(true);
        expect(mockAttackers.get(mockAttacker)).toEqual({
            origin: 'True Positive List',
            hops: 0,
        });
        expect(mockAttackers.has(solanaAddress)).toBe(false);
        expect(mockAttackers.has(cosmosAddress)).toBe(false);
        expect(mockAttackers.size).toBe(1)
        expect(spy).toHaveBeenCalledWith(`Non-Ethereum address True Positive list entry found: ${solanaAddress}`);
        expect(spy).toHaveBeenCalledWith(`Non-Ethereum address True Positive list entry found: ${cosmosAddress}`);
        expect(spy).toHaveBeenCalledTimes(2);
    });
});