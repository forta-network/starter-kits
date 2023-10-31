from utils import Utils
from web3_errormock import Web3ErrorMock

w3 = Web3ErrorMock()

class TestErrorCache:
    
    def test_utils_is_fp_error(self):
        Utils.ERROR_CACHE.clear()
        assert Utils.ERROR_CACHE.len() == 0, "ERROR_CACHE should be empty"
        is_contract = Utils.is_contract(w3, "0x1c5dCdd006EA78a7E4783f9e6021C32935a10fb4")
        assert is_contract == True
        assert Utils.ERROR_CACHE.len() == 1, "ERROR_CACHE should have 1 error"
        error_findings = Utils.ERROR_CACHE.get_all()
        assert error_findings[0].description == "Error: unable to get contract code"
        assert error_findings[0].metadata['error_source'] == 'Utils.is_contract'
        assert len(error_findings[0].metadata['error_stacktrace']) >0 