import rlwe_sa.cc.python.rlwe_sa as rlwe_sa


class RlweSA:

    def __init__(self, num_elements: int, ptxt_size:int, public_matrix:list = []):
        self.num_elements = num_elements
        self.ptxt_size = ptxt_size
        self._rlwe_sa = rlwe_sa.RlweSecAgg(num_elements, ptxt_size, public_matrix)

    def encrypt(self, secret_key, plaintext):
        return self._rlwe_sa.encrypt(secret_key, plaintext)

    def get_public_matrix(self):
        return self._rlwe_sa.get_as()
    
    def gen_secret_key(self):
        return self._rlwe_sa.sample_key()
    
    def key_to_vector(self, key):
        return self._rlwe_sa.convert_key(key)
    
    def vector_to_key(self, vector):
        return self._rlwe_sa.create_key(vector)
    
    def decrypt(self, secret_key, ciphertext):
        return self._rlwe_sa.decrypt(secret_key, ciphertext)
