/*
 * Copyright 2018 Google LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "shell_encryption/relinearization_key.h"

#include <memory>

#include "absl/memory/memory.h"
#include "absl/numeric/int128.h"
#include "absl/status/status.h"
#include "shell_encryption/bits_util.h"
#include "shell_encryption/montgomery.h"
#include "shell_encryption/prng/prng.h"
#include "shell_encryption/gadget.h"
#include "shell_encryption/prng/single_thread_chacha_prng.h"
#include "shell_encryption/prng/single_thread_hkdf_prng.h"
#include "shell_encryption/serialization.pb.h"
#include "shell_encryption/status_macros.h"
#include "shell_encryption/statusor.h"
#include "shell_encryption/symmetric_encryption_with_prng.h"

namespace rlwe {
namespace {

// Returns a random vector r orthogonal to (1,s). The second component is chosen
// using randomness-of-encryption sampled using the specified PRNG. The first
// component is then chosen so that r is perpendicular to (1,s).
template <typename ModularInt>
rlwe::StatusOr<std::vector<Polynomial<ModularInt>>> SampleOrthogonalFromPrng(
    const SymmetricRlweKey<ModularInt>& key, SecurePrng* prng) {
  // Sample a random polynomial r using a PRNG.
  RLWE_ASSIGN_OR_RETURN(auto r, SamplePolynomialFromPrng<ModularInt>(
                                    key.Len(), prng, key.ModulusParams()));
  // Top entries of the matrix R will be -s*r, thus R is orthogonal to
  // (1,s).
  RLWE_ASSIGN_OR_RETURN(Polynomial<ModularInt> r_top,
                        r.Mul(key.Key(), key.ModulusParams()));
  r_top.NegateInPlace(key.ModulusParams());
  std::vector<Polynomial<ModularInt>> res = {std::move(r_top), std::move(r)};
  return res;
}

// The i-th component of the result is (T^i key_power).
template <typename ModularInt>
rlwe::StatusOr<std::vector<Polynomial<ModularInt>>> PowersOfT(
    const Polynomial<ModularInt>& key_power,
    const SymmetricRlweKey<ModularInt>& key,
    const ModularInt& decomposition_modulus, int dimension) {
  std::vector<Polynomial<ModularInt>> result;
  result.reserve(dimension);
  Polynomial<ModularInt> key_to_i = key_power;

  for (int i = 0; i < dimension; i++) {
    // Increase the power of T in T^i s in place.
    if (i != 0) {
      RLWE_RETURN_IF_ERROR(
          key_to_i.MulInPlace(decomposition_modulus, key.ModulusParams()));
    }
    result.push_back(key_to_i);
  }
  return result;
}

template <typename ModularInt>
rlwe::StatusOr<std::vector<Polynomial<ModularInt>>> MatrixMultiply(
    std::vector<std::vector<ModularInt>> decomposed_coefficients,
    const std::vector<std::vector<Polynomial<ModularInt>>>& matrix,
    const typename ModularInt::Params* modulus_params,
    const NttParameters<ModularInt>* ntt_params) {
  std::vector<Polynomial<ModularInt>> result(
      2, Polynomial<ModularInt>(decomposed_coefficients[0].size(),
                                modulus_params));

  for (size_t i = 0; i < matrix[0].size(); i++) {
    Polynomial<ModularInt> ntt_part = Polynomial<ModularInt>::ConvertToNtt(
        std::move(decomposed_coefficients[i]), ntt_params, modulus_params);
    RLWE_RETURN_IF_ERROR(
        result[0].FusedMulAddInPlace(ntt_part, matrix[0][i], modulus_params));
    RLWE_RETURN_IF_ERROR(
        result[1].FusedMulAddInPlace(ntt_part, matrix[1][i], modulus_params));
  }

  return result;
}
}  //  namespace

template <typename ModularInt>
rlwe::StatusOr<typename RelinearizationKey<ModularInt>::RelinearizationKeyPart>
RelinearizationKey<ModularInt>::RelinearizationKeyPart::Create(
    const Polynomial<ModularInt>& key_power,  // the source key power s^j
    const SymmetricRlweKey<ModularInt>& key,  // the target key s'
    const Uint64 log_decomposition_modulus,
    const ModularInt& decomposition_modulus, int dimension, SecurePrng* prng,
    SecurePrng* prng_encryption) {
  std::vector<std::vector<Polynomial<ModularInt>>> matrix(2);
  for (auto& row : matrix) {
    row.reserve(dimension);
  }

  // Compute a vector of (T^i key_power).
  RLWE_ASSIGN_OR_RETURN(
      auto powers_of_t,
      PowersOfT(key_power, key, decomposition_modulus, dimension));

  // For key_power = s^j, the ith iteration of this loop computes the column of
  // the KeyPart corresponding to (T^i s^j).
  for (int i = 0; i < dimension; ++i) {
    // Sample r component orthogonal to (1, s').
    RLWE_ASSIGN_OR_RETURN(auto r, SampleOrthogonalFromPrng(key, prng));

    // Sample error.
    RLWE_ASSIGN_OR_RETURN(auto error,
                          SampleFromErrorDistribution<ModularInt>(
                              key_power.Len(), key.Variance(), prng_encryption,
                              key.ModulusParams()));
    // Convert the error coefficients into an error polynomial.
    auto e = Polynomial<ModularInt>::ConvertToNtt(
        std::move(error), key.NttParams(), key.ModulusParams());
    // Set the column of the Relinearization matrix.
    RLWE_RETURN_IF_ERROR(
        e.MulInPlace(key.PlaintextModulus(), key.ModulusParams()));
    RLWE_RETURN_IF_ERROR(e.AddInPlace(r[0], key.ModulusParams()));
    RLWE_RETURN_IF_ERROR(e.AddInPlace(powers_of_t[i], key.ModulusParams()));
    matrix[0].push_back(std::move(e));
    matrix[1].push_back(std::move(r[1]));
  }

  return RelinearizationKeyPart(std::move(matrix), log_decomposition_modulus);
}

template <typename ModularInt>
rlwe::StatusOr<std::vector<Polynomial<ModularInt>>>
RelinearizationKey<ModularInt>::RelinearizationKeyPart::ApplyPartTo(
    const Polynomial<ModularInt>& ciphertext_part,
    const typename ModularInt::Params* modulus_params,
    const NttParameters<ModularInt>* ntt_params) const {
  // Convert ciphertext out of NTT form.
  std::vector<ModularInt> ciphertext_coefficients =
      ciphertext_part.InverseNtt(ntt_params, modulus_params);

  // Bit-decompose the vector of coefficients in the ciphertext.
  RLWE_ASSIGN_OR_RETURN(
      std::vector<std::vector<ModularInt>> decomposed_coefficients,
      rlwe::BaseDecompose<ModularInt>(ciphertext_coefficients, modulus_params,
                               log_decomposition_modulus_, matrix_[0].size()));

  // Matrix multiply with the bit-decomposed coefficients.
  return MatrixMultiply<ModularInt>(std::move(decomposed_coefficients), matrix_,
                                    modulus_params, ntt_params);
}

template <typename ModularInt>
rlwe::StatusOr<typename RelinearizationKey<ModularInt>::RelinearizationKeyPart>
RelinearizationKey<ModularInt>::RelinearizationKeyPart::Deserialize(
    const std::vector<SerializedNttPolynomial>& polynomials,
    Uint64 log_decomposition_modulus, SecurePrng* prng,
    const ModularIntParams* modulus_params,
    const NttParameters<ModularInt>* ntt_params) {
  // The polynomials input is a flattened representation of a 2 x dimension
  // matrix where the first half corresponds to the first row of matrix and the
  // second half corresponds to the second row of matrix. This matrix makes up
  // the RelinearizationKeyPart.
  int dimension = polynomials.size();
  auto matrix = std::vector<std::vector<Polynomial<ModularInt>>>(2);
  matrix[0].reserve(dimension);
  matrix[1].reserve(dimension);

  for (int i = 0; i < dimension; i++) {
    RLWE_ASSIGN_OR_RETURN(auto elt, Polynomial<ModularInt>::Deserialize(
                                        polynomials[i], modulus_params));
    matrix[0].push_back(std::move(elt));
    RLWE_ASSIGN_OR_RETURN(auto sample,
                          SamplePolynomialFromPrng<ModularInt>(
                              matrix[0][i].Len(), prng, modulus_params));
    matrix[1].push_back(std::move(sample));
  }

  return RelinearizationKeyPart(std::move(matrix), log_decomposition_modulus);
}

template <typename ModularInt>
RelinearizationKey<ModularInt>::RelinearizationKey(
    const SymmetricRlweKey<ModularInt>& key, absl::string_view prng_seed,
    PrngType prng_type, int num_parts, Uint64 log_decomposition_modulus,
    Uint64 substitution_power, ModularInt decomposition_modulus,
    std::vector<RelinearizationKeyPart> relinearization_key)
    : dimension_(GadgetSize<ModularInt>(log_decomposition_modulus,
                                              key.ModulusParams())),
      num_parts_(num_parts),
      log_decomposition_modulus_(log_decomposition_modulus),
      decomposition_modulus_(decomposition_modulus),
      substitution_power_(substitution_power),
      modulus_params_(key.ModulusParams()),
      ntt_params_(key.NttParams()),
      relinearization_key_(std::move(relinearization_key)),
      prng_seed_(prng_seed),
      prng_type_(prng_type) {}

template <typename ModularInt>
rlwe::StatusOr<RelinearizationKey<ModularInt>>
RelinearizationKey<ModularInt>::Create(const SymmetricRlweKey<ModularInt>& key,
                                       PrngType prng_type, int num_parts,
                                       Uint64 log_decomposition_modulus,
                                       Uint64 substitution_power) {
  const bool has_identical_base_key = HasIdenticalBaseKey(substitution_power);
  const int expected_num_parts = has_identical_base_key ? 3 : 2;
  if (num_parts < expected_num_parts) {
    return absl::InvalidArgumentError(
        absl::StrCat("Num parts: ", num_parts, " must be at least ",
                     has_identical_base_key ? "three." : "two."));
  }
  if (log_decomposition_modulus <= 0) {
    return absl::InvalidArgumentError(
        absl::StrCat("Log decomposition modulus, ", log_decomposition_modulus,
                     ", must be positive."));
  } else if (log_decomposition_modulus > key.ModulusParams()->log_modulus) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Log decomposition modulus, ", log_decomposition_modulus,
        ", must be at most: ", key.ModulusParams()->log_modulus, "."));
  }
  RLWE_ASSIGN_OR_RETURN(auto decomposition_modulus,
                        ModularInt::ImportInt(key.ModulusParams()->One()
                                                  << log_decomposition_modulus,
                                              key.ModulusParams()));
  // Initialize the first part of the secret key, s.
  RLWE_ASSIGN_OR_RETURN(auto key_base, key.Substitute(substitution_power));
  auto key_power = key_base.Key();

  std::unique_ptr<SecurePrng> prng, prng_encryption;
  std::string prng_seed, prng_encryption_seed;
  if (prng_type == PRNG_TYPE_HKDF) {
    RLWE_ASSIGN_OR_RETURN(prng_seed, SingleThreadHkdfPrng::GenerateSeed());
    RLWE_ASSIGN_OR_RETURN(prng, SingleThreadHkdfPrng::Create(prng_seed));
    RLWE_ASSIGN_OR_RETURN(prng_encryption_seed,
                          SingleThreadHkdfPrng::GenerateSeed());
    RLWE_ASSIGN_OR_RETURN(prng_encryption,
                          SingleThreadHkdfPrng::Create(prng_encryption_seed));
  } else if (prng_type == PRNG_TYPE_CHACHA) {
    RLWE_ASSIGN_OR_RETURN(prng_seed, SingleThreadChaChaPrng::GenerateSeed());
    RLWE_ASSIGN_OR_RETURN(prng, SingleThreadChaChaPrng::Create(prng_seed));
    RLWE_ASSIGN_OR_RETURN(prng_encryption_seed,
                          SingleThreadChaChaPrng::GenerateSeed());
    RLWE_ASSIGN_OR_RETURN(prng_encryption,
                          SingleThreadChaChaPrng::Create(prng_encryption_seed));
  } else {
    return absl::InvalidArgumentError("PrngType not specified correctly.");
  }

  auto dimension = GadgetSize<ModularInt>(log_decomposition_modulus,
                                                key.ModulusParams());
  int first_key_index = has_identical_base_key ? 2 : 1;
  std::vector<RelinearizationKeyPart> relinearization_key;
  relinearization_key.reserve(num_parts);
  // Create RealinearizationKeyPart for each non-trivial power of the secret
  // key s^first_key_index, ..., s^k.
  for (int i = first_key_index; i < num_parts; i++) {
    if (i != 1) {
      // Increment the power of s.
      RLWE_RETURN_IF_ERROR(
          key_power.MulInPlace(key_base.Key(), key.ModulusParams()));
    }
    RLWE_ASSIGN_OR_RETURN(
        auto key_part,
        RelinearizationKeyPart::Create(
            key_power, key, log_decomposition_modulus, decomposition_modulus,
            dimension, prng.get(), prng_encryption.get()));
    relinearization_key.push_back(std::move(key_part));
  }

  return RelinearizationKey<ModularInt>(
      key, prng_seed, prng_type, num_parts, log_decomposition_modulus,
      substitution_power, decomposition_modulus,
      std::move(relinearization_key));
}

template <typename ModularInt>
rlwe::StatusOr<SymmetricRlweCiphertext<ModularInt>>
RelinearizationKey<ModularInt>::ApplyTo(
    const SymmetricRlweCiphertext<ModularInt>& ciphertext) const {
  // Ensure that the length of the ciphertext is less than or equal to the
  // length of the relinearization key.
  if (static_cast<int>(ciphertext.Len()) > num_parts_) {
    return absl::InvalidArgumentError(
        "RelinearizationKey not large enough for ciphertext.");
  }

  // If this key is generated for target secret s' == s, then we store k - 2
  // key parts where k is the ciphertext length; otherwise we store k - 1 key
  // parts. The first RelinearizationKeyPart corresponds to the ciphertext
  // component at `first_key_index`.
  int first_key_index = HasIdenticalBaseKey() ? 2 : 1;

  // Initialize the result ciphertext of length 2 by applying the first
  // relinearization key part to its corresponding ciphertext component.
  RLWE_ASSIGN_OR_RETURN(auto c1, ciphertext.Component(first_key_index));
  RLWE_ASSIGN_OR_RETURN(auto result, relinearization_key_[0].ApplyPartTo(
                                         c1, modulus_params_, ntt_params_));

  // Apply each following RelinearizationKeyPart to the part of the ciphertext
  // it corresponds to.
  for (size_t i = 1; i < relinearization_key_.size(); i++) {
    // Add RelinearizationKeyPart_i c_i to the result vector.
    int ciphertext_index = i + first_key_index;
    RLWE_ASSIGN_OR_RETURN(auto temp_comp,
                          ciphertext.Component(ciphertext_index));
    RLWE_ASSIGN_OR_RETURN(auto result_part,
                          relinearization_key_[i].ApplyPartTo(
                              temp_comp, modulus_params_, ntt_params_));
    RLWE_RETURN_IF_ERROR(result[0].AddInPlace(result_part[0], modulus_params_));
    RLWE_RETURN_IF_ERROR(result[1].AddInPlace(result_part[1], modulus_params_));
  }

  // Finally, the first component of the ciphertext corresponds to the
  // "1" part of the secret key, and is added without any
  // RelinearizationKeyPart.
  RLWE_ASSIGN_OR_RETURN(auto c0, ciphertext.Component(0));
  RLWE_RETURN_IF_ERROR(result[0].AddInPlace(c0, modulus_params_));
  // If the target secret key s' is the same as the source secret s, then
  // we add the "s" component of ciphertext, i.e. the second component, to
  // the result without any RelinearizationKeyPart.
  if (HasIdenticalBaseKey()) {
    RLWE_ASSIGN_OR_RETURN(auto c1, ciphertext.Component(1));
    RLWE_RETURN_IF_ERROR(result[1].AddInPlace(c1, modulus_params_));
  }

  return SymmetricRlweCiphertext<ModularInt>(
      std::move(result), 1,
      ciphertext.Error() +
          ciphertext.ErrorParams()->B_relinearize(relinearization_key_.size(),
                                                  log_decomposition_modulus_),
      modulus_params_, ciphertext.ErrorParams());
}

template <typename ModularInt>
rlwe::StatusOr<SerializedRelinearizationKey>
RelinearizationKey<ModularInt>::Serialize() const {
  SerializedRelinearizationKey output;
  output.set_log_decomposition_modulus(log_decomposition_modulus_);
  output.set_num_parts(num_parts_);
  output.set_prng_seed(prng_seed_);
  output.set_prng_type(prng_type_);
  output.set_power_of_s(substitution_power_);
  for (const RelinearizationKeyPart& matrix : relinearization_key_) {
    // Only serialize the first row of each matrix.
    for (const Polynomial<ModularInt>& c : matrix.Matrix()) {
      RLWE_ASSIGN_OR_RETURN(*output.add_c(), c.Serialize(modulus_params_));
    }
  }
  return output;
}

template <typename ModularInt>
rlwe::StatusOr<RelinearizationKey<ModularInt>>
RelinearizationKey<ModularInt>::Deserialize(
    const SerializedRelinearizationKey& serialized,
    const typename ModularInt::Params* modulus_params,
    const NttParameters<ModularInt>* ntt_params) {
  // Verifies that the number of polynomials in serialized is expected.
  // A RelinearizationKey can decrypt ciphertexts with num_parts number of
  // components corresponding to decryption under (1, s, ..., s^k) or (1,
  // s(x^power)). For the former case, a RelinearizationKey contains parts
  // corresponding to the non-"1" and non-"s" components, and for the latter
  // case, it contains only the parts corresponding to the non-"1" components.
  // We are in the former case if the substitution power of the base key s is 1.
  bool has_identical_base_key = HasIdenticalBaseKey(serialized.power_of_s());
  int first_key_index = has_identical_base_key ? 2 : 1;
  if (serialized.num_parts() <= first_key_index) {
    return absl::InvalidArgumentError(absl::StrCat(
        "The number of parts, ", serialized.num_parts(),
        ", must be greater than ", has_identical_base_key ? "two." : "one."));
  }
  // The number of RelinearizationKeyParts.
  int expected_num_key_parts = serialized.num_parts() - first_key_index;
  if (serialized.c_size() % expected_num_key_parts != 0) {
    return absl::InvalidArgumentError(
        absl::StrCat("The length of serialized, ", serialized.c_size(), ", ",
                     "must be divisible by the number of parts minus ",
                     has_identical_base_key ? "two, " : "one, ",
                     expected_num_key_parts, "."));
  }

  // Return an error when log decomposition modulus is non-positive.
  if (serialized.log_decomposition_modulus() <= 0) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Log decomposition modulus, ", serialized.log_decomposition_modulus(),
        ", must be positive."));
  } else if (serialized.log_decomposition_modulus() >
             static_cast<int>(modulus_params->log_modulus)) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Log decomposition modulus, ", serialized.log_decomposition_modulus(),
        ", must be at most: ", modulus_params->log_modulus, "."));
  }

  int polynomials_per_key_part = serialized.c_size() / expected_num_key_parts;
  if (polynomials_per_key_part !=
      GadgetSize<ModularInt>(serialized.log_decomposition_modulus(),
                                   modulus_params)) {
    return absl::InvalidArgumentError(
        absl::StrCat("Number of NTT Polynomials does not match expected ",
                     "number of matrix entries."));
  }
  RLWE_ASSIGN_OR_RETURN(
      auto decomposition_modulus,
      ModularInt::ImportInt(static_cast<typename ModularInt::Int>(1)
                                << serialized.log_decomposition_modulus(),
                            modulus_params));
  RelinearizationKey output(serialized.log_decomposition_modulus(),
                            decomposition_modulus, modulus_params, ntt_params);
  output.dimension_ = polynomials_per_key_part;
  output.num_parts_ = serialized.num_parts();
  output.prng_seed_ = serialized.prng_seed();
  output.prng_type_ = serialized.prng_type();
  output.substitution_power_ = serialized.power_of_s();

  // Create prng based on seed and type.
  std::unique_ptr<SecurePrng> prng;
  if (output.prng_type_ == PRNG_TYPE_HKDF) {
    RLWE_ASSIGN_OR_RETURN(prng,
                          SingleThreadHkdfPrng::Create(output.prng_seed_));
  } else if (output.prng_type_ == PRNG_TYPE_CHACHA) {
    RLWE_ASSIGN_OR_RETURN(prng,
                          SingleThreadChaChaPrng::Create(output.prng_seed_));
  } else {
    return absl::InvalidArgumentError("Invalid PRNG type is specified.");
  }

  // Takes each polynomials_per_key_part chunk of serialized.c()'s and places
  // them into a KeyPart.
  output.relinearization_key_.reserve(expected_num_key_parts);
  for (int i = 0; i < expected_num_key_parts; i++) {
    auto start = serialized.c().begin() + i * polynomials_per_key_part;
    auto end = start + polynomials_per_key_part;
    std::vector<SerializedNttPolynomial> chunk(start, end);
    RLWE_ASSIGN_OR_RETURN(auto deserialized,
                          RelinearizationKeyPart::Deserialize(
                              chunk, serialized.log_decomposition_modulus(),
                              prng.get(), modulus_params, ntt_params));
    output.relinearization_key_.push_back(std::move(deserialized));
  }

  return output;
}

// Instantiations of RelinearizationKey with specific MontgomeryInt classes.
// If any new types are added, montgomery.h should be updated accordingly (such
// as ensuring BigInt is correctly specialized, etc.).
template class RelinearizationKey<MontgomeryInt<Uint16>>;
template class RelinearizationKey<MontgomeryInt<Uint32>>;
template class RelinearizationKey<MontgomeryInt<Uint64>>;
template class RelinearizationKey<MontgomeryInt<absl::uint128>>;
#ifdef ABSL_HAVE_INTRINSIC_INT128
template class RelinearizationKey<MontgomeryInt<unsigned __int128>>;
#endif
}  //  namespace rlwe
