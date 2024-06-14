import fs from 'fs';
import path from 'path';
import { parse, ParseResult } from "papaparse";
import { AttackerEntry, TruePositiveCsv } from "./types";

export default class TruePositiveFetcher {

  truePositiveListUrl: string;
  truePositiveListPath: string;

  constructor(truePositiveListUrl: string, truePositiveListPath: string) {
    this.truePositiveListUrl = truePositiveListUrl;
    this.truePositiveListPath = truePositiveListPath;
  }

  private isValidEthereumAddress = (address: string): boolean => {
      const ethAddressRegex = /^0x[a-fA-F0-9]{40}$/;
      return ethAddressRegex.test(address);
  }

  private processParseResults = (results: ParseResult<TruePositiveCsv>, tpAttackers: string[]) => {
    results.data.forEach((attackerEntry: AttackerEntry) => {
      const attackerArray: string[] = attackerEntry.Attacker.split(",");

      attackerArray.forEach((attacker: string) => {
        attacker = attacker.trim();
        if (this.isValidEthereumAddress(attacker)) {
          tpAttackers.push(attacker.toLowerCase());
        } else {
          console.log(`Non-Ethereum address True Positive list entry found: ${attacker}`);
        }
      });
    });
  }

  private parse = (tpListContent: string, tpAttackers: string[]) => {
    parse(tpListContent, {
      header: true,
      skipEmptyLines: true,
      complete: (results: ParseResult<TruePositiveCsv>) => {
        if(results.errors.length) throw new Error(`${results.errors[0].message}`);
        this.processParseResults(results, tpAttackers);
      },
      error: (error: Error) => {
        throw new Error(`${error.message}`);
      }
    });
  }

  private getTruePositiveListRemotely = async (tpListUrl: string, tpAttackers: string[]) => {
    const response = await fetch(tpListUrl);
    if (!response.ok) {
      throw new Error("Failed to fetch remote True Positive list");
    }
    const tpListContent = await response.text();
    this.parse(tpListContent, tpAttackers);
  }

  private getTruePositiveListLocally = (tpListPath: string, tpAttackers: string[]) => {
    const resolvedTpListPath = path.resolve(__dirname, tpListPath);
    const tpListContent = fs.readFileSync(resolvedTpListPath, 'utf8');
    this.parse(tpListContent, tpAttackers);
  }

  public getTruePositiveList = async (
    attackers: Map<string, { origin: string; hops: number }>
  ) => {
    let truePositiveAttackers: string[] = [];
  
    try {
      await this.getTruePositiveListRemotely(this.truePositiveListUrl, truePositiveAttackers);
    } catch(e) {
      console.log(`'getTruePositiveListRemotely' failed. ${e}`);
      try {
        this.getTruePositiveListLocally(this.truePositiveListPath, truePositiveAttackers);
      } catch (e) {
        console.log(`Both True Positive List fetching functions failed. ${e}`);
      }
    }
  
    truePositiveAttackers.forEach((attacker: string) => {
      const origin = "True Positive List";
      const hops = 0;

      if(!attackers.has(attacker)) attackers.set(attacker, { origin, hops });
    });
  }
}