/*
 * Copyright 2017 Google LLC.
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

#include "rlwe_sa_api.h"

#include <algorithm>

#include <cstdint>

#include <functional>

#include <iostream>

#include <random>

#include <vector>

#include <gmock/gmock.h>

#include <gtest/gtest.h>

#include "rlwe_sa/cc/shell_encryption/testing/parameters.h"

#include "rlwe_sa/cc/shell_encryption/testing/status_matchers.h"

#include "rlwe_sa/cc/shell_encryption/testing/status_testing.h"

#include "rlwe_sa/cc/shell_encryption/testing/testing_prng.h"

#include "rlwe_sa/cc/shell_encryption/testing/testing_utils.h"

namespace {

  using::rlwe::testing::StatusIs;
  using::testing::Eq;
  using::testing::HasSubstr;

  // Set constants.
  const int kTestingRounds = 1;

  // Tests symmetric-key encryption scheme, including the following homomorphic
  // operations: addition, scalar multiplication by a polynomial (absorb), and
  // multiplication. Substitutions are implemented in
  // testing/coefficient_polynomial_ciphertext.h, and SymmetricRlweKey::Substitute
  // and SymmetricRlweCiphertext::PowersOfS() (updated on substitution calls) are
  // further tested in testing/coefficient_polynomial_ciphertext_test.cc.
  template < typename ModularInt >
    class RlweSecAggTest: public::testing::Test {};
  TYPED_TEST_SUITE(RlweSecAggTest, rlwe::MontgomeryInt < uint64_t > );

  // Ensure that the encryption scheme can decrypt its own ciphertexts.
  TYPED_TEST(RlweSecAggTest, CanDecrypt) {
    struct rlwe_sec_agg_test {
      int input_size;
      int log_t;
    };
    std::vector < rlwe_sec_agg_test > test_cases = {
      {
        static_cast < int > (pow(2, 11)), 11
      },
      // {static_cast<int>(pow(2,15)), 13},
      // {static_cast<int>(pow(2,15)), 15},
    };
    for (auto test_case: test_cases) {
      int input_size = test_case.input_size;
      int log_t = test_case.log_t;
      for (unsigned int i = 0; i < kTestingRounds; i++) {
        RlweSecAgg < TypeParam > rlweSecAgg = RlweSecAgg < TypeParam > (input_size, log_t);
        std::vector < typename TypeParam::Int > plaintext = rlweSecAgg.SamplePlaintext(input_size, log_t);
        rlwe::SymmetricRlweKey < TypeParam > key = rlweSecAgg.SampleKey();
        std::vector < rlwe::SymmetricRlweCiphertext < TypeParam >> ciphertext = rlweSecAgg.Encrypt(key, plaintext);
        std::vector < typename TypeParam::Int > decrypted = rlweSecAgg.Decrypt(key, ciphertext);
        EXPECT_EQ(plaintext, decrypted);
      }
    }
  }

  TYPED_TEST(RlweSecAggTest, CanSumKey) {
    int n = 10;
    int input_size = pow(2, 11);
    int log_t = 11;
    for (int i = 0; i < kTestingRounds; i++) {

      RlweSecAgg < TypeParam > rlweSecAgg = RlweSecAgg < TypeParam > (input_size, log_t);
      rlwe::SymmetricRlweKey < TypeParam > key = rlweSecAgg.SampleKey();
      std::vector < typename TypeParam::Int > vector_key = rlweSecAgg.ConvertKey(key);

      for (int j = 1; j < n; j++) {
        rlwe::SymmetricRlweKey < TypeParam > tmp_key = rlweSecAgg.SampleKey();
        std::vector < typename TypeParam::Int > vector_tmp_key = rlweSecAgg.ConvertKey(tmp_key);
        ASSERT_OK_AND_ASSIGN(key, key.Add(tmp_key));
        for (int k = 0; k < vector_key.size(); k++) {
          vector_key[k] = (vector_key[k] + vector_tmp_key[k]) % static_cast < uint64_t > (rlwe::kModulus59);
        }
      }
      rlwe::SymmetricRlweKey < TypeParam > key_sum = rlweSecAgg.CreateKey(vector_key);
      EXPECT_THAT(key.Key(), key_sum.Key());
    }
  }
  TYPED_TEST(RlweSecAggTest, Add) {
    int n = 10;
    int input_size = pow(2, 13);
    int log_t = 11;
    int mod_t = (1 << log_t) + 1;
    for (int i = 0; i < kTestingRounds; i++) {
      RlweSecAgg < TypeParam > rlweSecAgg = RlweSecAgg < TypeParam > (input_size, log_t);
      std::vector < typename TypeParam::Int > plaintext_sum = rlweSecAgg.SamplePlaintext(input_size, log_t);
      rlwe::SymmetricRlweKey < TypeParam > key_sum = rlweSecAgg.SampleKey();
      std::vector < rlwe::SymmetricRlweCiphertext < TypeParam >> chipertext_sum = rlweSecAgg.Encrypt(key_sum, plaintext_sum);
      for (int i = 1; i < n; i++) {
        std::vector < typename TypeParam::Int > plaintext = rlweSecAgg.SamplePlaintext(input_size, log_t);
        rlwe::SymmetricRlweKey < TypeParam > key = rlweSecAgg.SampleKey();
        std::vector < rlwe::SymmetricRlweCiphertext < TypeParam >> ciphertext = rlweSecAgg.Encrypt(key, plaintext);
        // Sum ciphertext element-wise modulor kModulus80
        chipertext_sum = rlweSecAgg.Aggregate(chipertext_sum, ciphertext);
        // Sum plaintext element-wise modulor kModulus80
        for (int j = 0; j < plaintext.size(); j++) {
          plaintext_sum[j] += plaintext[j];
          plaintext_sum[j] %= mod_t;
        }
        // Sum key element-wise modulor kModulus80
        ASSERT_OK_AND_ASSIGN(key_sum, key_sum.Add(key));
      }
      std::vector < typename TypeParam::Int > decrypted_chipertext = rlweSecAgg.Decrypt(key_sum, chipertext_sum);
      EXPECT_THAT(plaintext_sum, decrypted_chipertext);
    }

  }
} // namespace