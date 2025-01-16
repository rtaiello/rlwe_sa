/**
 * Code implementing the RLWE-SecAgg encoding, prposed by https://eprint.iacr.org/2022/1461.pdf
 * Devoped by: Riccardo Taiello
*/


#include "rlwe_sa/cc/shell_encryption/symmetric_encryption.h"


#include <algorithm>
#include <cstdint>
#include <functional>
#include <iostream>
#include <random>
#include <vector>
#include <assert.h>  

#include "absl/status/status.h"
#include "rlwe_sa/cc/shell_encryption/constants.h"
#include "rlwe_sa/cc/shell_encryption/context.h"
#include "rlwe_sa/cc/shell_encryption/status_macros.h"
#include "rlwe_sa/cc/shell_encryption/montgomery.h"
#include "rlwe_sa/cc/shell_encryption/polynomial.h"
#include "rlwe_sa/cc/shell_encryption/prng/single_thread_hkdf_prng.h"
#include "absl/numeric/int128.h"
#include "rlwe_sa/cc/shell_encryption/modulus_conversion.h"


#undef ASSERT_OK_AND_ASSIGN
#define ASSERT_OK_AND_ASSIGN(lhs, rexpr) \
  RLWE_ASSERT_OK_AND_ASSIGN_IMPL_(       \
      RLWE_STATUS_MACROS_IMPL_CONCAT_(_status_or_value, __LINE__), lhs, rexpr)

#define RLWE_ASSERT_OK_AND_ASSIGN_IMPL_(statusor, lhs, rexpr) \
  auto statusor = (rexpr);                                    \
  assert(statusor.ok());            \
  lhs = std::move(statusor).value()


template <typename ModularInt>
class RlweSecAgg
{

private:
  std::unique_ptr<const rlwe::RlweContext<ModularInt>> _context_ptr_q; 
  std::unique_ptr<const rlwe::RlweContext<ModularInt>> _context_ptr_p;
  std::vector<rlwe::Polynomial<ModularInt>> _as; 
  int _input_size;
  std::string _seed;
  int _num_split;

rlwe::StatusOr<std::unique_ptr<rlwe::SingleThreadHkdfPrng>>GetPrg(std::string seed = std::string()) {
    std::string prng_seed = std::string();
    if (seed != std::string()) {
         prng_seed = seed;
    }
    else {
    RLWE_ASSIGN_OR_RETURN(prng_seed,
                          rlwe::SingleThreadHkdfPrng::GenerateSeed());
      _seed = prng_seed;
    }
    RLWE_ASSIGN_OR_RETURN(auto prng,
                          rlwe::SingleThreadHkdfPrng::Create(prng_seed));
    return prng;
}


std::vector<ModularInt> ConvertToMontgomery(
    const std::vector<typename ModularInt::Int>& coeffs,
    const rlwe::MontgomeryIntParams<typename ModularInt::Int>* params14) {
  auto val = ModularInt::ImportZero(params14);
  std::vector<ModularInt> output(coeffs.size(), val);
  for (unsigned int i = 0; i < output.size(); i++) {
    ASSERT_OK_AND_ASSIGN(output[i],
                          ModularInt::ImportInt(coeffs[i], params14));
  }
  return output;
}
static std::vector<std::vector<typename ModularInt::Int>> splitVector(const std::vector<typename ModularInt::Int>& input_vector, size_t n) {
    
    std::vector<std::vector<typename ModularInt::Int>> result;
    
    // Calculate the size of each part

    size_t partSize = input_vector.size() / n;
    
    // Iterate and split the vector into parts
    auto start = input_vector.begin();
    for (size_t i = 0; i < n; ++i) {
        auto end = (i == n - 1) ? input_vector.end() : start + partSize;
        result.emplace_back(start, end);
        start = end;
    }

    return result;
}

public:
  RlweSecAgg(int input_size, size_t log_t, std::string seed = std::string(), double stddev = 4.5) {
  _input_size = input_size;
  // Compute log_2 of t
   const auto& params = typename rlwe::RlweContext<ModularInt>::Parameters{
            /*.modulus =*/static_cast<absl::uint128>(rlwe::kModulus80),
            /*.log_n =*/11,
            /*.log_t =*/log_t,
            /*.variance =*/std::pow(stddev, 2)};
    ASSERT_OK_AND_ASSIGN(_context_ptr_q, rlwe::RlweContext<ModularInt>::Create(params));

    const auto& params_p = typename rlwe::RlweContext<ModularInt>::Parameters{
            /*.modulus =*/rlwe::kNewhopeModulus,
            /*.log_n =*/11,
            /*.log_t =*/9,
            /*.variance =*/std::pow(4.5, 2)};
    ASSERT_OK_AND_ASSIGN(_context_ptr_p, rlwe::RlweContext<ModularInt>::Create(params_p));
    // _context_ptr_q = _context;
    ASSERT_OK_AND_ASSIGN(auto prng, GetPrg(seed));

    _num_split = _input_size /_context_ptr_q->GetN() ;
    for (int i = 0; i < _num_split; i++)
    {
      ASSERT_OK_AND_ASSIGN(auto a, rlwe::SamplePolynomialFromPrng<ModularInt>(
                                         _context_ptr_q->GetN(), prng.get(), _context_ptr_q->GetModulusParams()));
      _as.push_back(a);
    }
    
  }
  ~RlweSecAgg() {}

  std::string GetSeed() {
    return _seed;
  }
  
  rlwe::SymmetricRlweKey<ModularInt> SampleKey() {
    ASSERT_OK_AND_ASSIGN(auto prng, GetPrg());
    ASSERT_OK_AND_ASSIGN(auto key, rlwe::SymmetricRlweKey<ModularInt>::Sample(
        _context_ptr_q->GetLogN(), _context_ptr_q->GetVariance(), _context_ptr_q->GetLogT(),
        _context_ptr_q->GetModulusParams(), _context_ptr_q->GetNttParams(), prng.get()));
    return key;
  }
 
  rlwe::SymmetricRlweKey<ModularInt> SumKeys(rlwe::SymmetricRlweKey<ModularInt> key1, rlwe::SymmetricRlweKey<ModularInt> key2) {
    ASSERT_OK_AND_ASSIGN(auto key, key1.Add(key2));
    return key;
  }
  rlwe::SymmetricRlweKey<ModularInt> CreateKey(const std::vector<typename ModularInt::Int>& coeffs_p_int) {
  // Convert the key_vector to a vector of ModularInt
  std::vector<ModularInt> coeffs_p;

  for (auto& coeff_p_int : coeffs_p_int){
      ASSERT_OK_AND_ASSIGN(auto tmp, ModularInt::ImportInt(coeff_p_int, _context_ptr_p->GetModulusParams()));
      coeffs_p.push_back(tmp);
  }
  ASSERT_OK_AND_ASSIGN(auto coeffs_q, rlwe::ConvertModulusBalanced(coeffs_p, *_context_ptr_p->GetModulusParams(), *_context_ptr_q->GetModulusParams()));
  rlwe::Polynomial<ModularInt> result = rlwe::Polynomial<ModularInt>::ConvertToNtt(std::move(coeffs_q), _context_ptr_q->GetNttParams(), _context_ptr_q->GetModulusParams());
  ASSERT_OK_AND_ASSIGN(auto key,
    rlwe::SymmetricRlweKey<ModularInt>::CreateKey(
        result, _context_ptr_q->GetVariance(), _context_ptr_q->GetLogT(),
        _context_ptr_q->GetModulusParams(), _context_ptr_q->GetNttParams()));
    return key;
  }

  std::vector<rlwe::SymmetricRlweCiphertext<ModularInt>> Encrypt(rlwe::SymmetricRlweKey<ModularInt> key, const std::vector<typename ModularInt::Int>& plaintext) {
    assert(plaintext.size() == unsigned(_input_size));
    ASSERT_OK_AND_ASSIGN(auto prng, this->GetPrg());
    // Divide the plaintext in _num_split parts
    std::vector<std::vector<typename ModularInt::Int>> plaintexts = RlweSecAgg::splitVector(plaintext, _num_split);
    std::vector<rlwe::SymmetricRlweCiphertext<ModularInt>> ciphertexts;
    // Iterate over the plaintexts and encrypt each part
    for (int i = 0; i < _num_split; i++){
      auto mont = this->ConvertToMontgomery(plaintexts[i], _context_ptr_q->GetModulusParams());
      auto plaintext_ntt = rlwe::Polynomial<ModularInt>::ConvertToNtt(
          mont, _context_ptr_q->GetNttParams(), _context_ptr_q->GetModulusParams());
      
      ASSERT_OK_AND_ASSIGN(auto chipertext, rlwe::Encrypt<ModularInt>(key, plaintext_ntt, _as[i],
                                        _context_ptr_q->GetErrorParams(), prng.get()));

      ciphertexts.push_back(chipertext);
    }
    return ciphertexts;
  }
  std::vector<typename ModularInt::Int> Decrypt(rlwe::SymmetricRlweKey<ModularInt> key, std::vector<rlwe::SymmetricRlweCiphertext<ModularInt>> chipertexts){
  
  std::vector<typename ModularInt::Int> decrypted_chipertext;
  for (int i = 0; i < _num_split; i++)
    {
      ASSERT_OK_AND_ASSIGN(std::vector<typename ModularInt::Int> plaintext, rlwe::Decrypt<ModularInt>(key, chipertexts[i]));
      // Append plaintext to decrypted_chipertext till the position _num_split * _context_ptr_q->GetN()
      decrypted_chipertext.insert(decrypted_chipertext.end(), plaintext.begin(), plaintext.end());
    }
    
    return decrypted_chipertext;
  }
std::vector<rlwe::SymmetricRlweCiphertext<ModularInt>> Aggregate(std::vector<rlwe::SymmetricRlweCiphertext<ModularInt>>& chipertext_sum, std::vector<rlwe::SymmetricRlweCiphertext<ModularInt>>& ciphertext) {
    std::vector<rlwe::SymmetricRlweCiphertext<ModularInt>> result = chipertext_sum;
    for (int j = 0; j < chipertext_sum.size(); j++) {
        ASSERT_OK_AND_ASSIGN(rlwe::SymmetricRlweCiphertext<ModularInt> tmp, chipertext_sum[j].AddInPlaceFst(ciphertext[j]));
        result[j] = tmp;
    }
    return result;
}
  

static std::vector<typename ModularInt::Int> SamplePlaintext(
    rlwe::Uint64 num_coeffs, int log_t) {
    // Seed for the random number generator that is used to create test
    // plaintexts.
    typename ModularInt::Int t = (absl::uint128{1} << log_t); 
    typename ModularInt::Int value = (absl::uint128{1} << (log_t-5)); 
    unsigned int seed = 1;
    std::mt19937 mt_rand(seed);
    std::vector<typename ModularInt::Int> plaintext(num_coeffs);
    for (unsigned int i = 0; i < num_coeffs; i++) {
      rlwe::Uint64 rand = mt_rand();
      typename ModularInt::Int int_rand =
          static_cast<typename ModularInt::Int>(rand);
      plaintext[i] = int_rand % t;
    }
    return plaintext;
  }

std::vector<typename ModularInt::Int> ConvertKey(
  rlwe::SymmetricRlweKey<ModularInt> key) {

  std::vector<ModularInt> coeffs_q = key.Key().InverseNtt(_context_ptr_q->GetNttParams(), _context_ptr_q->GetModulusParams());
  ASSERT_OK_AND_ASSIGN(auto coeffs_p, rlwe::ConvertModulusBalanced(coeffs_q, *_context_ptr_q->GetModulusParams(), *_context_ptr_p->GetModulusParams()));
  std::vector<typename ModularInt::Int> coeffs_p_int;
  for (int i = 0; i < coeffs_p.size(); i++){
    coeffs_p_int.push_back(coeffs_p[i].ExportInt(_context_ptr_p->GetModulusParams()));
  }
  return coeffs_p_int;
}
};



