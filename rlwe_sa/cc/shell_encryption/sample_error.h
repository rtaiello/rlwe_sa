/*
 * Copyright 2023 Google LLC.
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

#ifndef RLWE_SAMPLE_ERROR_H_
#define RLWE_SAMPLE_ERROR_H_

#include <cstdint>
#include <vector>
#include <memory>

#include "rlwe_sa/cc/shell_encryption/constants.h"
#include "rlwe_sa/cc/shell_encryption/error_params.h"
#include "rlwe_sa/cc/shell_encryption/prng/prng.h"
#include "rlwe_sa/cc/shell_encryption/status_macros.h"
#include "rlwe_sa/cc/shell_encryption/statusor.h"
#include "rlwe_sa/cc/shell_encryption/sampler/discrete_gaussian.h"

namespace rlwe {

// Samples a vector of coefficients from the centered binomial distribution
// with the specified variance. The RLWE proofs rely on
// sampling keys and error values from a discrete Gaussian distribution, but
// the NewHope paper [1] indicates that a centered binomial distribution is
// indistinguishable and is far more efficient, without being susceptible to
// timing attacks.
//
// [1] "Post-quantum key exchange -- a new hope", Erdem Alkim, Leo Ducas, Thomas
// Poppelmann, Peter Schwabe, USENIX Security Symposium.
//
// All values sampled are multiplied by scalar.
template <typename ModularInt>
static rlwe::StatusOr<std::vector<ModularInt>> SampleFromErrorDistribution(
    unsigned int num_coeffs, Uint64 variance, SecurePrng* prng,
    const typename ModularInt::Params* modulus_params) {
  if (variance > kMaxVariance) {
    return absl::InvalidArgumentError(absl::StrCat(
        "The variance, ", variance, ", must be at most ", kMaxVariance, "."));
  }
  auto zero = ModularInt::ImportZero(modulus_params);
  std::vector<ModularInt> coeffs(num_coeffs, zero);
  Uint64 k;
  typename ModularInt::Int coefficient;

  for (unsigned int i = 0; i < num_coeffs; i++) {
    coefficient = modulus_params->modulus;
    k = variance << 1;

    while (k > 0) {
      if (k >= 64) {
        RLWE_ASSIGN_OR_RETURN(auto r64, prng->Rand64());
        coefficient += rlwe::internal::CountOnes64(r64);
        RLWE_ASSIGN_OR_RETURN(r64, prng->Rand64());
        coefficient -= rlwe::internal::CountOnes64(r64);
        k -= 64;
      } else if (k >= 8) {
        RLWE_ASSIGN_OR_RETURN(auto r8, prng->Rand8());
        coefficient += rlwe::internal::CountOnesInByte(r8);
        RLWE_ASSIGN_OR_RETURN(r8, prng->Rand8());
        coefficient -= rlwe::internal::CountOnesInByte(r8);
        k -= 8;
      } else {
        Uint8 mask = (1 << k) - 1;
        RLWE_ASSIGN_OR_RETURN(auto r8, prng->Rand8());
        coefficient += rlwe::internal::CountOnesInByte(r8 & mask);
        RLWE_ASSIGN_OR_RETURN(r8, prng->Rand8());
        coefficient -= rlwe::internal::CountOnesInByte(r8 & mask);
        break;  // all k remaining pairs have been sampled.
      }
    }

    typename ModularInt::Int mask = -(coefficient >= modulus_params->modulus);
    coefficient -= mask & modulus_params->modulus;
    RLWE_ASSIGN_OR_RETURN(coeffs[i],
                          ModularInt::ImportInt(coefficient, modulus_params));
    auto tmp =  coeffs[i].ExportInt(modulus_params);

  }

  return coeffs;
}

// Samples a vector of coefficients using a discrete Gaussian distribution.
// This function utilizes the DiscreteGaussianSampler class to generate samples
// with center 0 and the specified standard deviation.
template <typename ModularInt>
static rlwe::StatusOr<std::vector<ModularInt>> SampleFromDiscreteGaussian(
    unsigned int num_coeffs, double stddev, SecurePrng* prng,
    const typename ModularInt::Params* modulus_params) {
  if (stddev < 0) {
    return absl::InvalidArgumentError("Standard deviation must be non-negative.");
  }
  // Gaussian parameter of the base sampler.
  using DGSampler = DiscreteGaussianSampler<typename ModularInt::Int>;
  RLWE_ASSIGN_OR_RETURN(
      static auto sampler,
      DGSampler::Create(stddev));

  auto zero = ModularInt::ImportZero(modulus_params);
  std::vector<ModularInt> coeffs(num_coeffs, zero);
  for (unsigned int i = 0; i < num_coeffs; ++i) {
    RLWE_ASSIGN_OR_RETURN(auto coeff, sampler->SampleWithIterations(stddev,0, *prng));
    
    bool is_negative = coeff > DGSampler::kNegativeThreshold;
    typename ModularInt::Int coeff_mod_q = is_negative ? modulus_params->modulus - (static_cast<typename ModularInt::Int>(-coeff) % modulus_params->modulus) : coeff;
    RLWE_ASSIGN_OR_RETURN(coeffs[i],
                           ModularInt::ImportInt(coeff_mod_q, modulus_params));        
  }

  return coeffs;
}

}  // namespace rlwe

#endif  // RLWE_SAMPLE_ERROR_H_
