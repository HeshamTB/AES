# EE495/EE494 AES Implementaion
# Hesham T. Banafa
# Assad Dadoush

# This time i'll leave the blocks 'flat' arrays

class InvalidAESKeyLength(RuntimeError): ...

class AESBlockView:
    """
    Object that contains states from all stages, of all rounds
    """
    plain_text_block : bytes
    cipher_blocks : list[bytes]

    def set_plain_text(self, data_block: bytes):
        self.plain_text_block = data_block
    
class AESCtx:

    """
    AES Context object contains structs that ciphers plain text,
    deciphers, and expands key into sub-keys. The object can operate
    on a data block fully, or can be driven step by step to view progress.
    """
    def __init__(self, key: bytes):
        
        if len(key) not in {16, 24, 32}:
            raise InvalidAESKeyLength(f'Invalid Key Length {len(key)}')

        self.master_key = key
        self.KeyExpantion()
    
    def KeyExpantion(self):
        pass
