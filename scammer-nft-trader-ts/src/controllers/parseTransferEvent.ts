import { setTokenData } from '../utils/helper.js';
import { transferEventTopics } from '../config/logEventTypes.js';

import type { Log, Interface } from 'ethers';
import type { TransactionData } from '../types/types.js';

/**
 *
 * Parses the transfer event log and updates the TransactionData
 * object with the transferred token data.
 *
 * @function
 * @param {TransactionData} tx - The TransactionData object to update.
 * @param {Log} log - The log containing the transfer event data.
 * @param {string} logAddress - The address of the log.
 * @param {Interface} iface - The interface object containing the ABI for the market.
 * @throws {Error} Will throw an error if the transfer event is invalid or if the contract address is invalid.
 **/
const parseTransferEvent = (
    tx: TransactionData,
    log: Log,
    logAddress: string,
    iface: Interface
) => {
    const abiCoder = iface.getAbiCoder();

    if (
        log.data === '0x' &&
        log.topics[0] === transferEventTopics.ERC721[0] &&
        logAddress === tx.contractAddress
    ) {
        let tokenId = abiCoder.decode(['uint256'], log.topics[3]).toString();
        //tokenId = tokenId.replace(/\D/g, '');

        tx.fromAddr = abiCoder.decode(['address'], log.topics[1]).toString();
        tx.toAddr = abiCoder.decode(['address'], log.topics[2]).toString();
        tx.totalAmount += 1;

        setTokenData({
            tokens: tx.tokens,
            tokenId: tokenId,
            amount: 1,
            market: tx.interactedMarket,
            currencyAddr: '0x0000000000000000000000000000000000000000'
        });
    } else if (
        transferEventTopics.ERC1155.includes(log.topics[0]) &&
        logAddress === tx.contractAddress
    ) {
        const decodedData = abiCoder.decode(['uint256', 'uint256'], log.data);
        const [tokenId, amount] = decodedData;

        tx.totalAmount += amount;
        tx.fromAddr = abiCoder.decode(['address'], log.topics[2]).toString();
        tx.toAddr = abiCoder.decode(['address'], log.topics[3]).toString();

        setTokenData({
            tokens: tx.tokens,
            tokenId: tokenId,
            amount: amount,
            market: tx.interactedMarket,
            currencyAddr: '0x0000000000000000000000000000000000000000'
        });
    }
};

export { parseTransferEvent };
