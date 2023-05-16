import binascii
from urllib import request, error

class byte_indexOracleAttack():
    def __init__(self):
        self.block_size = 16
        self.url = "http://crypto-class.appspot.com/po?er="
        self.query = "%s%s%s%s" % ( "f20bdba6ff29eed7b046d1df9fb70000",
                                    "58b1ffb4210a580f748b4ac714c001bd",
                                    "4a61044426fb515dad3f21f18aa577c0",
                                    "bdf302936266926ff37dbf7035d5eeb4")

    def oracle(self, query):
        '''
        Check with the "Oracle" if the ciphertext is valid or not
        '''
        target = "%s%s" % (self.url, request.quote(query))
        req = request.Request(target)
        try:
            request.urlopen(req)
        except error.HTTPError as e:
            if e.code == 404:
                return True
            elif e.code == 403:
                return False
            else:
                exit()

    def hex_to_byte(self, value):
        '''
        Convert the value from hex to byte
        '''
        return binascii.unhexlify(value)

    def split_blocks(self, query):
        '''
        Split the query into blocks with 16 bytes
        '''
        blocks = []
        for i in range(0, len(query), self.block_size):
            blocks.append(query[i:i+self.block_size])
        return(blocks)

    def get_xor(self, a, b):
        '''
        Perform the xor between two values
        '''
        return bytes([a ^ b])

    def get_padding_standard(self, byte_index):
        '''
        Form the padding standard following the PKCS#7 according to the round
        '''
        zero_padding = "00"*(16-byte_index)
        hex_padding = f"{byte_index:02x}"*byte_index
        return "%s%s" % (zero_padding, hex_padding)

    def check_range(self, block_index, byte_index):
        '''
        Checks if it is the first character of the last block, if so, the guess is made
        from 15 to 0
        '''
        if block_index == 2 and byte_index == 1:
            return 15, 0, -1
        else:
            return 0, 256, 1

    def get_custom_block(self, block, byte_index, byte, guess, message_block):
        custom_block = block[0:16 - byte_index]
        byte_xor = self.get_xor(byte, guess)
        custom_block += byte_xor + b"".join(message_block)
        return custom_block.hex()

    def hex_xor_128(self, a, b):
        return "{0:032x}".format(int(a, base=16) ^ int(b, base=16))

    def debug_progress(self, block_index, byte_index, guess):
        print("Block: %02d - Byte: %02d - Guess: %03d" % (block_index,
            byte_index, guess))

    def debug_partial_result(self, plaintext):
        print("Partial result: %s" % (plaintext))

    def attack(self, query = None):
        '''
        Launch attack to discover plaintext
        '''
        if query == None:
            query = self.query
        query = self.hex_to_byte(query)
        blocks = self.split_blocks(query)
        plaintext = [""]*(len(blocks)-1)
        for block_index, block in enumerate(blocks[0:-1]):
            message_block = []
            for byte_index, byte in enumerate(block[::-1], 1):
                padding = self.get_padding_standard(byte_index)
                start, end, step = self.check_range(block_index, byte_index)
                for guess in range(start, end, step):
                    custom_block = self.get_custom_block(block, byte_index, byte,
                        guess, message_block)
                    req_string = "%s%s" % (self.hex_xor_128(custom_block, padding),
                        blocks[block_index+1].hex())
                    self.debug_progress(block_index+1, byte_index-1, guess)
                    if(self.oracle(req_string)):
                        message_block.insert(0, self.get_xor(byte, guess))
                        plaintext[block_index] = "%s%s" % (chr(guess),
                            plaintext[block_index])
                        self.debug_partial_result(plaintext)
                        break
                    if guess == 255:
                        exit()
            self.debug_partial_result("".join(plaintext))
        return plaintext

if __name__ == '__main__':
    byte_index_oracle = byte_indexOracleAttack()
    plaintext = byte_index_oracle.attack()
    print("\nResult:\n%s" % ("".join(plaintext)))
