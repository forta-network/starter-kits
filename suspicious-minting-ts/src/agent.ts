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

    if (!mintEvents.length || mintEvents.length > 5) {
      return findings;
    }

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
    const burnEvents = txEvent
      .filterLog(ERC20_TRANSFER_EVENT)
      .filter((event) => event.args.to === ethers.constants.AddressZero);
    const burnOriginators = burnEvents.map((event) => event.args.from);
    const uniqueBurnOriginators = Array.from(new Set(burnOriginators));

    await Promise.all(
      mintEvents.map(async (event) => {
        const mintRecipient = event.args.to;
        if (
          isEoaRecord[mintRecipient] &&
          !uniqueBurnOriginators.includes(mintRecipient)
        ) {
          const {
            address: token,
            args: { value: amount },
          } = event;

          // Check for transfer events from the mint recipient
          const transferEvents = txEvent
            .filterLog(ERC20_TRANSFER_EVENT)
            .filter(
              (transferEvent) => transferEvent.args.from === mintRecipient
            );

          // Check if the total transferred amount is within ±20% of the minted amount
          const isTransferAmountWithinRange = transferEvents.some(
            (transferEvent) => {
              const transferAmount = transferEvent.args.value;
              const lowerBound = amount.sub(amount.div(5));
              const upperBound = amount.add(amount.div(5));

              return (
                transferAmount.gte(lowerBound) && transferAmount.lte(upperBound)
              );
            }
          );
          if (!isTransferAmountWithinRange) {
            const mintUsdValue = await fetcher.getValueInUsd(
              txEvent.network,
              amount.toString(),
              token
            );

            // Check if any transfer event USD value is within ±20% of the mint USD value
            const isTransferUsdValueWithinRange = await Promise.all(
              transferEvents.map(async (transferEvent) => {
                const transferAmount = transferEvent.args.value;
                const transferUsdValue = await fetcher.getValueInUsd(
                  txEvent.network,
                  transferAmount.toString(),
                  transferEvent.address
                );

                if (mintUsdValue === 0 && transferUsdValue === 0) {
                  return false;
                }

                const lowerBound = mintUsdValue * 0.8;
                const upperBound = mintUsdValue * 1.2;
                return (
                  transferUsdValue >= lowerBound &&
                  transferUsdValue <= upperBound
                );
              })
            ).then((results) => results.some((result) => result));

            let isNativeTokenValueWithinRange = false;
            let isNativeTokenUsdValueWithinRange = false;

            if (mintRecipient.toLowerCase() === txEvent.from.toLowerCase()) {
              // Check if the native token value is within ±20% of the minted amount
              const nativeTokenValue = txEvent.transaction.value;
              isNativeTokenValueWithinRange =
                ethers.BigNumber.from(nativeTokenValue).gte(
                  amount.sub(amount.div(5))
                ) &&
                ethers.BigNumber.from(nativeTokenValue).lte(
                  amount.add(amount.div(5))
                );

              // Check if the native token USD value is within ±20% of the mint USD value
              const nativeTokenUsdValue = await fetcher.getValueInUsd(
                txEvent.network,
                nativeTokenValue.toString(),
                "native"
              );
              isNativeTokenUsdValueWithinRange =
                nativeTokenUsdValue > 0 &&
                nativeTokenUsdValue >= mintUsdValue * 0.8 &&
                nativeTokenUsdValue <= mintUsdValue * 1.2;
            }
            if (
              !isTransferUsdValueWithinRange &&
              !isNativeTokenValueWithinRange &&
              !isNativeTokenUsdValueWithinRange
            ) {
              const toTxCount = await provider.getTransactionCount(
                mintRecipient,
                txEvent.blockNumber - 1
              );
              if (mintUsdValue > 50000 && toTxCount < 100) {
                findings.push(
                  createFinding(
                    token,
                    mintUsdValue.toFixed(2),
                    txEvent.hash,
                    mintRecipient,
                    FindingSeverity.High,
                    txEvent.from
                  )
                );
              } else if (mintUsdValue === 0 || mintUsdValue > 10000) {
                if (toTxCount === 0) {
                  if (mintUsdValue > 10000) {
                    findings.push(
                      createFinding(
                        token,
                        mintUsdValue.toFixed(2),
                        txEvent.hash,
                        mintRecipient,
                        FindingSeverity.Medium,
                        txEvent.from
                      )
                    );
                  }

                  if (mintUsdValue === 0) {
                    const tokenBalance = await fetcher.getBalance(
                      txEvent.blockNumber,
                      mintRecipient,
                      token
                    );

                    if (
                      tokenBalance.lte(amount) &&
                      amount.gt("1000000000000000000")
                    ) {
                      let isInitialMint = false;
                      if (!txEvent.to) {
                        const createdContractAddress =
                          ethers.utils.getContractAddress({
                            from: txEvent.from,
                            nonce: txEvent.transaction.nonce,
                          });
                        isInitialMint =
                          token.toLowerCase() ===
                          createdContractAddress.toLowerCase();
                      }
                      if (!isInitialMint) {
                        const totalSupply = await fetcher.getTotalSupply(
                          txEvent.blockNumber,
                          token
                        );

                        // Trigger an alert only if the minted amount is more than / equal to 0.2% of the total supply
                        if (amount.gte(totalSupply.div(500))) {
                          findings.push(
                            createFinding(
                              token,
                              mintUsdValue.toFixed(2),
                              txEvent.hash,
                              mintRecipient,
                              FindingSeverity.Info,
                              txEvent.from
                            )
                          );
                        }
                      }
                    }
                  }
                }
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
