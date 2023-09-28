import { fetchJwt } from "forta-agent";
import { readFileSync } from "fs";
import { DATABASE_URL } from "./constants";
import { ApiInfo, ApiOptions } from "./types";
import * as dotenv from "dotenv";
dotenv.config();

const hasLocalNode = process.env.hasOwnProperty("LOCAL_NODE");

export async function fetchApiInfo(): Promise<ApiInfo> {
  if (hasLocalNode) {
    const data = readFileSync("secrets.json", "utf8");
    return JSON.parse(data);
  } else {
    const token = await fetchJwt({});
    const headers = { Authorization: `Bearer ${token}` };
    try {
      const response = await fetch(`${DATABASE_URL}`, { headers });

      if (response.ok) {
        const apiKey: ApiInfo = await response.json();
        return apiKey;
      } else {
        return { API_KEY: "" };
      }
    } catch (e) {
      console.log("Error in fetching data.");
      throw e;
    }
  }
}

export function createAssetListApiOptions(
  apiKey: string,
  type: string,
  status: string,
  endDate: string,
  startDate: string
): ApiOptions {
  return {
    method: "POST",
    headers: { "X-API-KEY": apiKey, "Content-Type": "application/json" },
    body: `{"type":"${type}","status":"${status}","endDate":"${endDate}","startDate":"${startDate}"}`,
  };
}

export function createAssetDetailsApiOptions(apiKey: string, assetContent: string): ApiOptions {
  return {
    method: "POST",
    headers: { "X-API-KEY": apiKey, "Content-Type": "application/json" },
    body: `{"content":"${assetContent}"}`,
  };
}

export function getCurrentDateInYyyyMmDD(): string {
  const currenDate = new Date();
  const currentDay = String(currenDate.getDate()).padStart(2, "0");
  const currentMonth = String(currenDate.getMonth() + 1).padStart(2, "0");
  const currentYear = currenDate.getFullYear();
  const currentDateInYyyyMmDD = `${currentYear}-${currentMonth}-${currentDay}`;

  return currentDateInYyyyMmDD;
}
