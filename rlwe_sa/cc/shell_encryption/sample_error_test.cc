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

#include "rlwe_sa/cc/shell_encryption/sample_error.h"

#include <cstdint>
#include <memory>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "rlwe_sa/cc/shell_encryption/context.h"
#include "rlwe_sa/cc/shell_encryption/montgomery.h"
#include "rlwe_sa/cc/shell_encryption/symmetric_encryption.h"
#include "rlwe_sa/cc/shell_encryption/testing/parameters.h"
#include "rlwe_sa/cc/shell_encryption/testing/status_matchers.h"
#include "rlwe_sa/cc/shell_encryption/testing/status_testing.h"
#include "rlwe_sa/cc/shell_encryption/testing/testing_prng.h"

namespace {

using ::rlwe::testing::StatusIs;
using ::testing::HasSubstr;

const int kTestingRounds = 10;
const std::vector<rlwe::Uint64> variances = {0, 1, 8, 15, 29, 50, 255};

template <typename ModularInt>
class SampleErrorTest : public ::testing::Test {};
TYPED_TEST_SUITE(SampleErrorTest, rlwe::testing::ModularIntTypes);

TYPED_TEST(SampleErrorTest, CheckUpperBoundOnNoise) {
  using Int = typename TypeParam::Int;

  auto prng = std::make_unique<rlwe::testing::TestingPrng>(0);

  for (const auto& params :
       rlwe::testing::ContextParameters<TypeParam>::Value()) {
    ASSERT_OK_AND_ASSIGN(auto context,
                         rlwe::RlweContext<TypeParam>::Create(params));

    for (auto variance : variances) {
      for (int i = 0; i < kTestingRounds; i++) {
        ASSERT_OK_AND_ASSIGN(std::vector<TypeParam> error,
                             rlwe::SampleFromErrorDistribution<TypeParam>(
                                 context->GetN(), variance, prng.get(),
                                 context->GetModulusParams()));
        // Check that each coefficient is in [-2*variance, 2*variance]
        for (size_t j = 0; j < context->GetN(); j++) {
          Int reduced = error[j].ExportInt(context->GetModulusParams());
          if (reduced > (context->GetModulus() >> 1)) {
            EXPECT_LT(context->GetModulus() - reduced, 2 * variance + 1);
          } else {
            EXPECT_LT(reduced, 2 * variance + 1);
          }
        }
      }
    }
  }
}

TYPED_TEST(SampleErrorTest, FailOnTooLargeVariance) {
  auto prng = std::make_unique<rlwe::testing::TestingPrng>(0);
  for (const auto& params :
       rlwe::testing::ContextParameters<TypeParam>::Value()) {
    ASSERT_OK_AND_ASSIGN(auto context,
                         rlwe::RlweContext<TypeParam>::Create(params));

    rlwe::Uint64 variance = rlwe::kMaxVariance + 1;
    EXPECT_THAT(
        rlwe::SampleFromErrorDistribution<TypeParam>(
            context->GetN(), variance, prng.get(), context->GetModulusParams()),
        StatusIs(
            absl::StatusCode::kInvalidArgument,
            HasSubstr(absl::StrCat("The variance, ", variance,
                                   ", must be at most ", rlwe::kMaxVariance))));
  }
}

TYPED_TEST(SampleErrorTest, DiscreteGaussianSamplesAreBounded) {
  using Int = typename TypeParam::Int;

  auto prng = std::make_unique<rlwe::testing::TestingPrng>(12345);
  const std::vector<double> stddevs = {12.8};

  for (const auto& params :
       rlwe::testing::ContextParameters<TypeParam>::Value()) {
    ASSERT_OK_AND_ASSIGN(auto context,
                         rlwe::RlweContext<TypeParam>::Create(params));

    for (double stddev : stddevs) {
      for (int i = 0; i < kTestingRounds; i++) {
        ASSERT_OK_AND_ASSIGN(
            std::vector<TypeParam> samples,
            rlwe::SampleFromDiscreteGaussian<TypeParam>(
                context->GetN(), stddev, prng.get(),
                context->GetModulusParams()));

        for (size_t j = 0; j < context->GetN(); ++j) {
          Int reduced = samples[j].ExportInt(context->GetModulusParams());
          EXPECT_GE(reduced, 0);
          EXPECT_LT(reduced, context->GetModulus());
          // add a print
        }
      }
    }
  }
}

TYPED_TEST(SampleErrorTest, FailOnNegativeStddev) {
  auto prng = std::make_unique<rlwe::testing::TestingPrng>(0);
  for (const auto& params :
       rlwe::testing::ContextParameters<TypeParam>::Value()) {
    ASSERT_OK_AND_ASSIGN(auto context,
                         rlwe::RlweContext<TypeParam>::Create(params));

    double invalid_stddev = -1.0;
    EXPECT_THAT(
        rlwe::SampleFromDiscreteGaussian<TypeParam>(
            context->GetN(), invalid_stddev, prng.get(),
            context->GetModulusParams()),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr("Standard deviation must be non-negative")));
  }
}

TYPED_TEST(SampleErrorTest, StressTestForLargeNumCoefficients) {
  using Int = typename TypeParam::Int;

  auto prng = std::make_unique<rlwe::testing::TestingPrng>(0);
  constexpr unsigned int large_num_coeffs = 1 << 14;  // 16,384 coefficients
  constexpr rlwe::Uint64 variance = 50;

  for (const auto& params :
       rlwe::testing::ContextParameters<TypeParam>::Value()) {
    ASSERT_OK_AND_ASSIGN(auto context,
                         rlwe::RlweContext<TypeParam>::Create(params));

    ASSERT_OK_AND_ASSIGN(std::vector<TypeParam> error,
                         rlwe::SampleFromErrorDistribution<TypeParam>(
                             large_num_coeffs, variance, prng.get(),
                             context->GetModulusParams()));

    EXPECT_EQ(error.size(), large_num_coeffs);

    for (const auto& coeff : error) {
      Int reduced = coeff.ExportInt(context->GetModulusParams());
      if (reduced > (context->GetModulus() >> 1)) {
        EXPECT_LT(context->GetModulus() - reduced, 2 * variance + 1);
      } else {
        EXPECT_LT(reduced, 2 * variance + 1);
      }
    }
  }
}

}  // namespace
