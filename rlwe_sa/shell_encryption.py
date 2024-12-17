from rlwe_sa.cc.python._shell_encryption import RlweSecAgg

def next_power_of_two(n):
    """
    Check if the number is a power of two. If it is, return the number itself.
    If not, return the next power of two.
    """
    # Check if n is less than or equal to 0
    if n <= 0:
        raise ValueError("Input must be a positive integer.")

    # Check if n is already a power of 2
    if (n & (n - 1)) == 0:
        return n

    # Find the next power of 2
    power = 1
    while power < n:
        power *= 2
    return power

class RlweSA:

    def __init__(self, num_elements: int, ptxt_size:int, seed= ""):
        self.num_elements = num_elements
        self.new_num_elements = next_power_of_two(num_elements)
        self.ptxt_size = ptxt_size
        self._rlwe_sa = RlweSecAgg(self.new_num_elements, ptxt_size, seed)
        self._seed = seed

    def encrypt(self, secret_key, plaintext):
        plaintext = plaintext + [0] * (self.new_num_elements - len(plaintext))
        return self._rlwe_sa.encrypt(secret_key, plaintext)

    def get_seed(self):
        return self._rlwe_sa.get_seed()
    
    def gen_secret_key(self):
        return self._rlwe_sa.sample_key()
    
    def key_to_vector(self, key):
        return self._rlwe_sa.convert_key(key)
    
    def vector_to_key(self, vector):
        return self._rlwe_sa.create_key(vector)
    
    def decrypt(self, secret_key, ciphertext):
        return self._rlwe_sa.decrypt(secret_key, ciphertext)[:self.num_elements]

    def add(self, ciphertext1, ciphertext2):
        return self._rlwe_sa.aggregate(ciphertext1, ciphertext2)
    
    @property
    def get_modulus_key(self):
        return 646119422561999443726337
