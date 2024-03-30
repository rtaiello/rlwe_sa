import rlwe_sa.cc.python.rlwe_sa as rlwe_sa
import time
import random

def assert_encryption_decryption(input_size, ptxt_bits):
    rlwe_sec_agg = rlwe_sa.RlweSecAgg(input_size, ptxt_bits)
    plaintext = rlwe_sec_agg.sample_plaintext(input_size, ptxt_bits)
    sk = rlwe_sec_agg.sample_key()
    sk_vector = rlwe_sec_agg.convert_key(sk)
    sk = rlwe_sec_agg.create_key(sk_vector)
    ciphertext = rlwe_sec_agg.encrypt(sk, plaintext)
    decrypted = rlwe_sec_agg.decrypt(sk, ciphertext)
    assert decrypted == plaintext


def assert_sum_key(input_size, ptxt_bits, modulus):
    rlwe_sec_agg = rlwe_sa.RlweSecAgg(input_size, ptxt_bits)
    sk_1 = rlwe_sec_agg.sample_key()
    sk_2 = rlwe_sec_agg.sample_key()
    sk_1_vector = rlwe_sec_agg.convert_key(sk_1)
    sk_2_vector = rlwe_sec_agg.convert_key(sk_2)
    sk_sum_vector = [(a + b) % modulus for a, b in zip(sk_1_vector, sk_2_vector)]
    sk_sum = rlwe_sec_agg.sum_keys(sk_1, sk_2)
    sk_sum_true_vector = rlwe_sec_agg.convert_key(sk_sum)
    assert sk_sum_vector == sk_sum_true_vector


def assert_aggregation(input_size, ptxt_bits, modulus):
    rlwe_sec_agg = rlwe_sa.RlweSecAgg(input_size, ptxt_bits)
    plaintext_1 = rlwe_sec_agg.sample_plaintext(input_size, ptxt_bits)
    sk_1 = rlwe_sec_agg.sample_key()
    sk_1_vector = rlwe_sec_agg.convert_key(sk_1)
    sk_1 = rlwe_sec_agg.create_key(sk_1_vector)
    ciphertext_1 = rlwe_sec_agg.encrypt(sk_1, plaintext_1)
    plaintext_2 = rlwe_sec_agg.sample_plaintext(input_size, ptxt_bits)
    sk_2 = rlwe_sec_agg.sample_key()
    sk_2_vector = rlwe_sec_agg.convert_key(sk_2)
    sk_2 = rlwe_sec_agg.create_key(sk_2_vector)
    ciphertext_2 = rlwe_sec_agg.encrypt(sk_2, plaintext_2)
    sk_sum_vector = [(a + b) % modulus for a, b in zip(sk_1_vector, sk_2_vector)]
    plaintext_sum = [
        (a + b) % ((2**ptxt_bits) + 1) for a, b in zip(plaintext_1, plaintext_2)
    ]
    sk_sum = rlwe_sec_agg.create_key(sk_sum_vector)
    ciphertext_sum = rlwe_sec_agg.aggregate(ciphertext_1, ciphertext_2)
    decrypted_sum = rlwe_sec_agg.decrypt(sk_sum, ciphertext_sum)
    assert decrypted_sum == plaintext_sum


def assert_multiple_aggregation(num_clients, input_size, ptxt_bits, modulus):
    encrypt_time = []
    aggregate_time = []
    for i in range(num_clients):
        if i == 0:
            plaintext_sum = [0] * input_size
            len_ptxt_sum = len(plaintext_sum)
            # check if is power of 2 otherwise add padding untill the next power of 2
            if (len_ptxt_sum & (len_ptxt_sum - 1)) != 0:
                next_power_of_2 = 1 << len_ptxt_sum.bit_length()
                plaintext_sum += [0] * (next_power_of_2 - len_ptxt_sum)

            rlwe_sec_agg = rlwe_sa.RlweSecAgg(len(plaintext_sum), ptxt_bits)
            sk_sum = rlwe_sec_agg.sample_key()
            ciphertext_sum = rlwe_sec_agg.encrypt(sk_sum, plaintext_sum)
            sk_vector_sum = rlwe_sec_agg.convert_key(sk_sum)
        plaintext = [1] * input_size
        len_ptxt_sum = len(plaintext)
        # check if is power of 2 otherwise add padding untill the next power of 2
        if (len_ptxt_sum & (len_ptxt_sum - 1)) != 0:
            next_power_of_2 = 1 << len_ptxt_sum.bit_length()
            plaintext += [0] * (next_power_of_2 - len_ptxt_sum)

        sk = rlwe_sec_agg.sample_key()
        start_encrypt = time.time()
        chipertext = rlwe_sec_agg.encrypt(sk, plaintext)
        sk_vector = rlwe_sec_agg.convert_key(sk)
        end_encrypt = time.time()
        time_encrypt = end_encrypt - start_encrypt
        encrypt_time.append(time_encrypt)
        plaintext_sum = [
            (a + b) % ((2 ** modulus.bit_length() + 1))
            for a, b in zip(plaintext_sum, plaintext)
        ]
        sk_vector_sum = [(a + b)  for a, b in zip(sk_vector_sum, sk_vector)]
        start_aggregate = time.time()
        ciphertext_sum = rlwe_sec_agg.aggregate(ciphertext_sum, chipertext)
        end_aggregate = time.time()
        time_aggregate = end_aggregate - start_aggregate
        aggregate_time.append(time_aggregate)
    sk_vector_sum = [a % modulus for a in sk_vector_sum]
    sk_sum = rlwe_sec_agg.create_key(sk_vector_sum)
    decrypted_sum = rlwe_sec_agg.decrypt(sk_sum, ciphertext_sum)
    assert decrypted_sum == plaintext_sum


input_size = 2**17
ptxt_bits = 16
modulus = 332366567264636929
num_clients = 5

assert_encryption_decryption(input_size, ptxt_bits)
assert_sum_key(input_size, ptxt_bits, modulus)
assert_aggregation(input_size, ptxt_bits, modulus)
assert_multiple_aggregation(num_clients, input_size, ptxt_bits, modulus)
