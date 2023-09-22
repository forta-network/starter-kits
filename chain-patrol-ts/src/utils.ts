import { fetchJwt } from "forta-agent";
import { DATABASE_URL } from "./constants";
import { ApiOptions } from "./types";

export async function fetchApiInfo(): Promise<string> {
  const token = await fetchJwt({});
  const headers = { Authorization: `Bearer ${token}` };
  try {
    const response = await fetch(`${DATABASE_URL}`, { headers });

    if (response.ok) {
      const apiKey: string = await response.json();
      return apiKey;
    } else {
      return "";
    }
  } catch (e) {
    console.log("Error in fetching data.");
    throw e;
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
    body: `{"type":${type},"status":${status},"endDate":${endDate},"startDate":${startDate}}`,
  };
}

export function createAssetDetailsApiOptions(apiKey: string, assetContent: string): ApiOptions {
  return {
    method: "POST",
    headers: { "X-API-KEY": apiKey, "Content-Type": "application/json" },
    body: `{"content":${assetContent}}`,
  };
}

export function getCurrentDateInYyyyMmDD(): string {
  const date = new Date();
  const currentDay = String(date.getDate()).padStart(2, "0");
  const currentMonth = String(date.getMonth() + 1).padStart(2, "0");
  const currentYear = date.getFullYear();
  const currentDate = `${currentYear}-${currentMonth}-${currentDay}`;

  return currentDate;
}
