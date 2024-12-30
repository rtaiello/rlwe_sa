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
    RLWE_ASSIGN_OR_RETURN(auto sample, sampler->SampleWithIterations(stddev,0, *prng));
    
    bool is_negative = sample > DGSampler::kNegativeThreshold;
    if (is_negative) {
      sample = -sample;
    }
    RLWE_ASSIGN_OR_RETURN(coeffs[i],
                           ModularInt::ImportInt(sample, modulus_params));
  }

  return coeffs;
}

}  // namespace rlwe

#endif  // RLWE_SAMPLE_ERROR_H_
