import { fetchJwt } from "forta-agent";
import { readFileSync } from "fs";
import { DATABASE_URL, THIRTY_DAYS_IN_MS } from "./constants";
import { ApiKeys, ApiOptions } from "./types";
import * as dotenv from "dotenv";
dotenv.config();

const hasLocalNode = process.env.hasOwnProperty("LOCAL_NODE");

export async function fetchApiKey(): Promise<ApiKeys> {
  if (hasLocalNode) {
    const data = readFileSync("secrets.json", "utf8");
    return JSON.parse(data);
  } else {
    const token = await fetchJwt({});
    const headers = { Authorization: `Bearer ${token}` };
    try {
      const response = await fetch(`${DATABASE_URL}`, { headers });

      if (response.ok) {
        const apiKey: ApiKeys = await response.json();
        return apiKey;
      } else {
        return { apiKeys: { CHAINPATROL: "" } };
      }
    } catch (e) {
      console.log("Error in fetching API key.");
      throw e;
    }
  }
}

export function createAssetListApiOptions(
  apiKey: string,
  type: string,
  endDate: string,
  startDate: string
): ApiOptions {
  return {
    method: "POST",
    headers: { "X-API-KEY": apiKey, "Content-Type": "application/json" },
    body: `{"type":"${type}","status":"BLOCKED","endDate":"${endDate}","startDate":"${startDate}"}`,
  };
}

export function createAssetDetailsApiOptions(apiKey: string, assetContent: string): ApiOptions {
  return {
    method: "POST",
    headers: { "X-API-KEY": apiKey, "Content-Type": "application/json" },
    body: `{"content":"${assetContent}"}`,
  };
}

function getDateInYyyyMmDd(date: Date): string {
  const day = String(date.getDate()).padStart(2, "0");
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const year = date.getFullYear();
  return `${year}-${month}-${day}`;
}

export function getCurrentDateInYyyyMmDD(): string {
  const currentDate = new Date();

  return getDateInYyyyMmDd(currentDate);
}

export function getDateFourWeeksAgoInYyyyMmDD(): string {
  const currentDateInMs = Date.now();
  const dateThirtyDaysAgo = new Date(currentDateInMs - THIRTY_DAYS_IN_MS);

  return getDateInYyyyMmDd(dateThirtyDaysAgo);
}
