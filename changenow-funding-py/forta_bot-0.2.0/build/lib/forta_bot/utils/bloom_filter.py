import mmh3
import base64
import math


class BloomFilter:
    def __init__(self, dict):
        self.k = int(dict.get('k'), 16) if type(
            dict.get('k')) == str else dict.get('k')
        self.m = int(dict.get('m'), 16) if type(
            dict.get('m')) == str else dict.get('m')
        self.base64_data = dict.get('bitset')
        self.bitset = None

    def has(self, key):
        if self.bitset is None:
            self.bitset = BitSet({'m': self.m, 'bitset': self.base64_data})
        indices = self.get_indices(key)
        for index in indices:
            if not self.bitset.has(index):
                return False
        return True

    def get_indices(self, key):
        indices = []
        base_hashes = self.get_base_hashes(key)
        for i in range(self.k):
            a = base_hashes[i % 2]
            b = (i + (i % 2)) % 4
            c = 2 + (b/2)
            d = 0xFFFFFFFFFFFFFFFF & (
                i * base_hashes[int(c)])  # truncate 64 bits
            location = 0xFFFFFFFFFFFFFFFF & (a + d)  # truncate 64 bits
            indices.append(location % self.m)
        return indices

    def get_base_hashes(self, key):
        val1, val2 = mmh3.hash64(key, 0, signed=False)
        # convert key string to bytearray
        b = bytearray()
        b.extend(key.encode())
        # append 1
        b.append(1)
        val3, val4 = mmh3.hash64(bytes(b), 0, signed=False)
        return [val1, val2, val3, val4]


class BitSet:
    def __init__(self, dict):
        # first Uint64 (i.e. 8 bytes) encodes m, next Uint64 encodes k, next Uint64 encodes m again (so we slice them out)
        decoded_bytes = base64.b64decode(dict.get('bitset'))[8*3:]
        # how many Uint64 do we need to store m bits
        array_length = math.ceil(dict.get('m') / 64)
        self.data = []
        for i in range(array_length):
            bytes_index = 8*i
            self.data.append(int.from_bytes(
                decoded_bytes[bytes_index:bytes_index+8], "big"))  # read as big endian

    def has(self, index):
        word_index = index >> 6
        words_index_i = index & (64-1)
        mask = int(math.pow(2, words_index_i))
        word = self.data[word_index]
        return (word & mask) != 0
