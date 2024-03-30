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

#include "rlwe_sa/cc/shell_encryption/symmetric_encryption_with_prng.h"

#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "rlwe_sa/cc/shell_encryption/context.h"
#include "rlwe_sa/cc/shell_encryption/montgomery.h"
#include "rlwe_sa/cc/shell_encryption/ntt_parameters.h"
#include "rlwe_sa/cc/shell_encryption/polynomial.h"
#include "rlwe_sa/cc/shell_encryption/status_macros.h"
#include "rlwe_sa/cc/shell_encryption/testing/parameters.h"
#include "rlwe_sa/cc/shell_encryption/testing/status_matchers.h"
#include "rlwe_sa/cc/shell_encryption/testing/status_testing.h"
#include "rlwe_sa/cc/shell_encryption/testing/testing_utils.h"

namespace rlwe {
namespace {

// Set constants.
const int kTestingRounds = 10;

template <typename ModularInt>
class SymmetricEncryptionWithPrngTest : public ::testing::Test {
 public:
  using Key = SymmetricRlweKey<ModularInt>;

  // Sample a random key.
  rlwe::StatusOr<Key> SampleKey(const rlwe::RlweContext<ModularInt>* context) {
    RLWE_ASSIGN_OR_RETURN(std::string prng_seed,
                          SingleThreadHkdfPrng::GenerateSeed());
    RLWE_ASSIGN_OR_RETURN(auto prng, SingleThreadHkdfPrng::Create(prng_seed));
    return Key::Sample(context->GetLogN(), context->GetVariance(),
                       context->GetLogT(), context->GetModulusParams(),
                       context->GetNttParams(), prng.get());
  }

  rlwe::StatusOr<std::vector<Polynomial<ModularInt>>> ConvertPlaintextsToNtt(
      const std::vector<std::vector<typename ModularInt::Int>>& coeffs,
      const rlwe::RlweContext<ModularInt>* context) {
    std::vector<Polynomial<ModularInt>> ntt_plaintexts;
    for (size_t i = 0; i < coeffs.size(); ++i) {
      RLWE_ASSIGN_OR_RETURN(auto mont,
                            rlwe::testing::ConvertToMontgomery<ModularInt>(
                                coeffs[i], context->GetModulusParams()));
      ntt_plaintexts.push_back(Polynomial<ModularInt>::ConvertToNtt(
          mont, context->GetNttParams(), context->GetModulusParams()));
    }
    return ntt_plaintexts;
  }

  void TestCompressedEncryptionDecryption(
      const std::vector<std::vector<typename ModularInt::Int>>& plaintexts,
      const rlwe::RlweContext<ModularInt>* context) {
    ASSERT_OK_AND_ASSIGN(auto key, SampleKey(context));
    ASSERT_OK_AND_ASSIGN(std::string prng_seed,
                         SingleThreadHkdfPrng::GenerateSeed());
    ASSERT_OK_AND_ASSIGN(auto prng, SingleThreadHkdfPrng::Create(prng_seed));
    ASSERT_OK_AND_ASSIGN(std::string prng_encryption_seed,
                         SingleThreadHkdfPrng::GenerateSeed());
    ASSERT_OK_AND_ASSIGN(auto prng_encryption,
                         SingleThreadHkdfPrng::Create(prng_encryption_seed));
    ASSERT_OK_AND_ASSIGN(std::vector<Polynomial<ModularInt>> ntt_plaintexts,
                         ConvertPlaintextsToNtt(plaintexts, context));
    ASSERT_OK_AND_ASSIGN(
        auto compressed_ciphertexts,
        EncryptWithPrng<ModularInt>(key, ntt_plaintexts, prng.get(),
                                    prng_encryption.get()));
    EXPECT_EQ(plaintexts.size(), compressed_ciphertexts.size());
    ASSERT_OK_AND_ASSIGN(auto another_prng,
                         SingleThreadHkdfPrng::Create(prng_seed));
    ASSERT_OK_AND_ASSIGN(auto ciphertexts,
                         ExpandFromPrng<ModularInt>(compressed_ciphertexts,
                                                    context->GetModulusParams(),
                                                    context->GetNttParams(),
                                                    context->GetErrorParams(),
                                                    another_prng.get()));
    EXPECT_EQ(plaintexts.size(), ciphertexts.size());
    for (size_t i = 0; i < ciphertexts.size(); ++i) {
      // Expect that the error of an expanded ciphertext is of a fresh
      // encryption.
      EXPECT_EQ(ciphertexts[i].Error(),
                context->GetErrorParams()->B_encryption());
      ASSERT_OK_AND_ASSIGN(auto decrypted,
                           Decrypt<ModularInt>(key, ciphertexts[i]));
      EXPECT_EQ(plaintexts[i], decrypted);
    }
  }
};
TYPED_TEST_SUITE(SymmetricEncryptionWithPrngTest,
                 rlwe::testing::ModularIntTypes);

// Ensure that the encryption scheme can encrypt and decrypt a single compressed
// ciphertext.
TYPED_TEST(SymmetricEncryptionWithPrngTest, EncryptDecryptSingleCompressed) {
  for (const auto& params :
       rlwe::testing::ContextParameters<TypeParam>::Value()) {
    ASSERT_OK_AND_ASSIGN(auto context,
                         rlwe::RlweContext<TypeParam>::Create(params));
    for (int i = 0; i < kTestingRounds; ++i) {
      this->TestCompressedEncryptionDecryption(
          {rlwe::testing::SamplePlaintext<TypeParam>(context->GetN(),
                                                     context->GetT())},
          context.get());
    }
  }
}

// Ensure that the encryption scheme can encrypt and decrypt multiple compressed
// ciphertexts.
TYPED_TEST(SymmetricEncryptionWithPrngTest, EncryptDecryptMultipleCompressed) {
  for (const auto& params :
       rlwe::testing::ContextParameters<TypeParam>::Value()) {
    ASSERT_OK_AND_ASSIGN(auto context,
                         rlwe::RlweContext<TypeParam>::Create(params));
    for (int i = 0; i < kTestingRounds; ++i) {
      std::vector<std::vector<typename TypeParam::Int>> plaintexts;
      for (int j = 0; j < i + 2; ++j) {
        plaintexts.push_back(rlwe::testing::SamplePlaintext<TypeParam>(
            context->GetN(), context->GetT()));
      }
      this->TestCompressedEncryptionDecryption(plaintexts, context.get());
    }
  }
}

}  // namespace
}  // namespace rlwe
