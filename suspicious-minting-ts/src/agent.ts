import {
  Finding,
  TransactionEvent,
  FindingSeverity,
  ethers,
  getEthersProvider,
} from "forta-agent";
import Fetcher from "./fetcher";
import { createFinding } from "./findings";

export const ERC20_TRANSFER_EVENT =
  "event Transfer(address indexed from, address indexed to, uint256 value)";

const DEAD_ADDRESS = "0x000000000000000000000000000000000000dead";

export const provideHandleTransaction =
  (provider: ethers.providers.Provider, fetcher: Fetcher) =>
  async (txEvent: TransactionEvent) => {
    const findings: Finding[] = [];

    const mintEvents = txEvent
      .filterLog(ERC20_TRANSFER_EVENT)
      .filter((event) => event.args.from === ethers.constants.AddressZero)
      .filter(
        (event) =>
          ![ethers.constants.AddressZero, DEAD_ADDRESS].includes(
            event.args.to.toLowerCase()
          )
      );

    if (!mintEvents.length) {
      return findings;
    }
    console.log("THERE WAS A MINT!!!");
    const receivers = mintEvents.map((event) => event.args.to);
    const uniqueReceivers = Array.from(new Set(receivers));

    const isEoaMap = await Promise.all(
      uniqueReceivers.map(async (receiver) => [
        receiver,
        receiver.toLowerCase() === txEvent.from.toLowerCase() ||
          (await provider.getCode(receiver, txEvent.blockNumber)) === "0x",
      ])
    );

    const isEoaRecord = Object.fromEntries(isEoaMap);

    await Promise.all(
      mintEvents.map(async (event) => {
        if (isEoaRecord[event.args.to]) {
          const {
            address: token,
            args: { value: amount, to },
          } = event;
          const usdValue = await fetcher.getValueInUsd(
            txEvent.network,
            amount.toString(),
            token
          );

          if (usdValue > 50000) {
            findings.push(
              createFinding(
                token,
                usdValue.toFixed(2),
                txEvent.hash,
                to,
                FindingSeverity.High,
                txEvent.from
              )
            );
          } else if (usdValue === 0 || usdValue > 10000) {
            const toTxCount = await provider.getTransactionCount(
              to,
              txEvent.blockNumber - 1
            );

            if (toTxCount === 0) {
              if (usdValue > 10000) {
                findings.push(
                  createFinding(
                    token,
                    usdValue.toFixed(2),
                    txEvent.hash,
                    to,
                    FindingSeverity.Medium,
                    txEvent.from
                  )
                );
              }

              if (usdValue === 0) {
                findings.push(
                  createFinding(
                    token,
                    usdValue.toFixed(2),
                    txEvent.hash,
                    to,
                    FindingSeverity.Info,
                    txEvent.from
                  )
                );
              }
            }
          }
        }
      })
    );

    return findings;
  };

export default {
  handleTransaction: provideHandleTransaction(
    getEthersProvider(),
    new Fetcher(getEthersProvider())
  ),
};
