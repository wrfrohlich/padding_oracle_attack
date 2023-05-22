import binascii
from sys import argv
from urllib import request, error

class PaddingOracleAttack():
    def __init__(self):
        self.block_size = 16
        self.url = "http://crypto-class.appspot.com/po?er="
        self.ciphertext = "%s%s%s%s" % ("f20bdba6ff29eed7b046d1df9fb70000",
                                        "58b1ffb4210a580f748b4ac714c001bd",
                                        "4a61044426fb515dad3f21f18aa577c0",
                                        "bdf302936266926ff37dbf7035d5eeb4")

    def oracle(self, ciphertext: str)-> bool:
        '''
        Check with the "Oracle" if the ciphertext is valid or not

        Args:
            ciphertext (str): Altered ciphertext, usually 32-bytes.

        Return:
            True (Code 404)/False (Code 403)
        '''
        target = "%s%s" % (self.url, request.quote(ciphertext))
        req = request.Request(target)
        try:
            request.urlopen(req)
        except error.HTTPError as e:
            if e.code == 404:
                return True
            elif e.code == 403:
                return False
            else:
                exit("Unable to perform decoding: mismatched size blocks")

    def hex_to_byte(self, value: str)-> bytes:
        '''
        Convert the value from hex to byte

        Args:
            value (str): String with values in hex (e.g. F20DBA6FF2).

        Return:
            Value converted into bytes
        '''
        return binascii.unhexlify(value)

    def split_blocks(self, ciphertext: bytes)-> list:
        '''
        Split the ciphertext into blocks with 16-bytes

        Args:
            ciphertext (bytes): Ciphertext in bytes, usually 64-bytes.

        Return:
            List divided into 16-bytes values
        '''
        blocks = []
        for i in range(0, len(ciphertext), self.block_size):
            blocks.append(ciphertext[i:i+self.block_size])
        return blocks

    def get_xor(self, a: int, b: int)-> bytes:
        '''
        XOR between two values (1-byte)

        Args:
            a (int): 1-byte.
            b (int): 1-byte.

        Return:
            1-Byte in bytes format
        '''
        return bytes([a ^ b])

    def get_xor_blocks(self, a: str, b: str)-> str:
        '''
        XOR between two 128-bit (16-byte) values

        Args:
            a (str): String with 16-bytes in hex (e.g. F20BDBA6FF29EED7B046D1DF9FB70000).
            b (str): String with 16-bytes in hex (e.g. 58B1FFB4210A580F748B4AC714C001BD).

        Return:
            String with 16-bytes in hex
        '''
        return f"{int(a, base=16) ^ int(b, base=16):032x}"

    def get_padding_standard(self, byte_index: int)-> str:
        '''
        Form the padding standard following the PKCS#7 according to the round

        Args:
            byte_index (int): Block index of interest.

        Return:
            String with 16-byte padding in hex
        '''
        zero_padding = "00"*(16-byte_index)
        hex_padding = f"{byte_index:02x}"*byte_index
        return "%s%s" % (zero_padding, hex_padding)

    def check_range(self, block_index: int, byte_index: int)-> tuple:
        '''
        Checks if it is the last character of the last block, if so, the guess is made
        from 15 to 0

        Args:
            block_index (int): Block IV index.
            byte_index (int): Block index of interest.

        Return:
            Tuple with the start value, end value and steps for the for loop
        '''
        if block_index == 2 and byte_index == 1:
            return 15, 0, -1
        else:
            return 0, 256, 1

    def get_custom_block(self, block: bytes, byte_index: int, byte: int, guess: int,
                        message_block: list)-> list:
        '''
        Create the custom block based on the original block, XOR between the byte of
        interest and the round guess, and the previous discovered bytes

        Args:
            block (bytes): Original block with 16-bytes.
            byte_index (int): Byte index of interest.
            byte (int): Byte of interest.
            guess (int): Round guess.
            message_block (list): List of bytes discovered in previous rounds.

        Return:
            String with 16-bytes in hex
        '''
        custom_block = block[:self.block_size - byte_index]
        byte_xor = self.get_xor(byte, guess)
        custom_block += byte_xor + b"".join(message_block)
        return custom_block.hex()


    def debug_progress(self, block_index: int, byte_index: int, guess: int)-> None:
        print("Block: %02d - Byte: %02d - Guess: %03d" % (block_index,
            byte_index, guess))

    def debug_partial_result(self, plaintext: str)-> None:
        print("Partial result: %s" % (plaintext))


    def attack(self, ciphertext: str = None)-> str:
        '''
        Launch attack to discover plaintext

        Args:
            ciphertext (str): String with values in hex (e.g. F20DBA6FF2).

        Return:
            Deciphered plaintext.
        '''
        if ciphertext == None:
            ciphertext = self.ciphertext
        if len(ciphertext) % self.block_size != 0:
            exit("Unable to perform decoding: mismatched size blocks")
        ciphertext = self.hex_to_byte(ciphertext)
        blocks = self.split_blocks(ciphertext)
        plaintext = [""]*(len(blocks)-1)
        for block_index, block in enumerate(blocks[0:-1]):
            message_block = []
            for byte_index, byte in enumerate(block[::-1], 1):
                padding = self.get_padding_standard(byte_index)
                start, end, step = self.check_range(block_index, byte_index)
                for guess in range(start, end, step):
                    custom_block = self.get_custom_block(block, byte_index, byte,
                        guess, message_block)
                    custom_block = self.get_xor_blocks(custom_block, padding)
                    req_string = "%s%s" % (custom_block, blocks[block_index+1].hex())
                    self.debug_progress(block_index+1, byte_index-1, guess)
                    if(self.oracle(req_string)):
                        message_block.insert(0, self.get_xor(byte, guess))
                        plaintext[block_index] = "%s%s" % (chr(guess),
                            plaintext[block_index])
                        self.debug_partial_result(plaintext)
                        break
                    if guess == 255:
                        exit("Unable to perform decoding")
            self.debug_partial_result("".join(plaintext))
        return plaintext

if __name__ == '__main__':
    padding_oracle = PaddingOracleAttack()
    args = None
    if len(argv) > 1:
        args = argv[1]
    plaintext = padding_oracle.attack(args)
    print("\nResult:\n%s" % ("".join(plaintext)))
