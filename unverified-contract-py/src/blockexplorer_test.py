from blockexplorer import BlockExplorer
import pytest

EOA = '0x6162759eDAd730152F0dF8115c698a42E666157F'
VERIFIED_CONTRACT = '0x1f9840a85d5af5bf1d1762f925bdaddc4201f984'
UNVERIFIED_CONTRACT = '0xe39f3c40966df56c69aa508d8ad459e77b8a2bc1'

blockexplorer = BlockExplorer(1)

class TestBlockExplorer:
    @pytest.mark.asyncio
    async def test_unverified_contract(self):
        await blockexplorer.set_api_key()
        assert not await blockexplorer.is_verified(UNVERIFIED_CONTRACT), "Etherscan incorrectly verified unverified contract"

    @pytest.mark.asyncio
    async def test_verified_contract(self):
        await blockexplorer.set_api_key()
        assert await blockexplorer.is_verified(VERIFIED_CONTRACT), "Etherscan didnt verify verified contract"

    @pytest.mark.asyncio
    async def test_eoa(self):
        await blockexplorer.set_api_key()
        assert not await blockexplorer.is_verified(EOA), "Etherscan verified an EOA"
