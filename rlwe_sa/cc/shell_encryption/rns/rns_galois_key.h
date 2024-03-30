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

#ifndef RLWE_RNS_RNS_GALOIS_KEY_H_
#define RLWE_RNS_RNS_GALOIS_KEY_H_

#include <algorithm>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "rlwe_sa/cc/shell_encryption/rns/rns_bfv_ciphertext.h"
#include "rlwe_sa/cc/shell_encryption/rns/rns_bgv_ciphertext.h"
#include "rlwe_sa/cc/shell_encryption/rns/rns_ciphertext.h"
#include "rlwe_sa/cc/shell_encryption/rns/rns_gadget.h"
#include "rlwe_sa/cc/shell_encryption/rns/rns_modulus.h"
#include "rlwe_sa/cc/shell_encryption/rns/rns_polynomial.h"
#include "rlwe_sa/cc/shell_encryption/rns/rns_secret_key.h"

namespace rlwe {

// This class implements the Galois key based on RNS polynomials. A Galois key
// is a special kind of key switching key that can transform a ciphertext under
// a secret key (1, s(X^substitution_power)) to a ciphertext encrypting the same
// plaintext message but under the canonical secret key (1, s(X)). Each Galois
// key instance is defined with a specific substitution power, and it can only
// be applied to ciphertexts whose PowerOfS exactly matches this substitution
// power.
//
// The current RnsGaloisKey class implements the gadget-based Galois key in the
// power-of-2 cyclotomic ring R = Z[X]/(X^N + 1) with RNS modulus Q. A
// gadget-based Galois key is a k-by-2 matrix gk = (gk_b, gk_a):
//   gk_a = -u \in R_Q^k,
//   gk_b = u * s + t * e + s(X^substitution_power) * g,
// where u consists of independent and uniformly random polynomials, e is a
// vector of error polynomials, and g is the gadget vector of dimension k. To
// apply this Galois key to a degree-1 ciphertext (c0, c1), we must take two
// steps:
// 1. Compute c0' = c0(X^substitution_power) and c1' = c1(X^substitution_power);
// 2. Call the `ApplyTo` on the ciphertext (c0', c1').
template <typename ModularInt>
class RnsGaloisKey {
  using Integer = typename ModularInt::Int;
  using ModularIntParams = typename ModularInt::Params;

 public:
  // Samples a Galois key suitable for working with BGV ciphertexts, derived
  // from given secret_key for the given substitution power.
  static absl::StatusOr<RnsGaloisKey> CreateForBgv(
      const RnsRlweSecretKey<ModularInt>& secret_key, int power, int variance,
      const RnsGadget<ModularInt>* gadget, Integer plaintext_modulus,
      PrngType prng_type) {
    return Create(secret_key, power, variance, gadget, prng_type,
                  /*error_scalar=*/plaintext_modulus);
  }

  // Samples a Galois key suitable for working with BFV ciphertexts, derived
  // from given secret_key for the given substitution power.
  static absl::StatusOr<RnsGaloisKey> CreateForBfv(
      const RnsRlweSecretKey<ModularInt>& secret_key, int power, int variance,
      const RnsGadget<ModularInt>* gadget, PrngType prng_type) {
    return Create(secret_key, power, variance, gadget, prng_type);
  }

  // Applies the galois key to a BGV ciphertext.
  absl::StatusOr<RnsBgvCiphertext<ModularInt>> ApplyTo(
      const RnsBgvCiphertext<ModularInt>& ciphertext) const;

  // Applies the galois key to a BFV ciphertext
  absl::StatusOr<RnsBfvCiphertext<ModularInt>> ApplyTo(
      const RnsBfvCiphertext<ModularInt>& ciphertext) const;

  // Accessors to the key components.
  const std::vector<RnsPolynomial<ModularInt>>& GetKeyA() const {
    return key_as_;
  }

  const std::vector<RnsPolynomial<ModularInt>>& GetKeyB() const {
    return key_bs_;
  }

  const RnsGadget<ModularInt>* Gadget() { return gadget_; }

  int Dimension() const { return key_as_.size(); }

  int SubstitutionPower() const { return power_; }

 private:
  // Factory function that samples a Galois key for different RLWE schemes.
  // In particular, `error_scalar` should be set to the plaintext modulus
  // for Galois key in BGV, and it should be set to 1 otherwise.
  static absl::StatusOr<RnsGaloisKey> Create(
      const RnsRlweSecretKey<ModularInt>& secret_key, int power, int variance,
      const RnsGadget<ModularInt>* gadget, PrngType prng_type,
      Integer error_scalar = 1);

  explicit RnsGaloisKey(std::vector<RnsPolynomial<ModularInt>> key_as,
                        std::vector<RnsPolynomial<ModularInt>> key_bs,
                        const RnsGadget<ModularInt>* gadget, int power,
                        std::vector<const PrimeModulus<ModularInt>*> moduli,
                        absl::string_view prng_seed, PrngType prng_type)
      : key_as_(std::move(key_as)),
        key_bs_(std::move(key_bs)),
        gadget_(gadget),
        power_(power),
        moduli_(std::move(moduli)),
        prng_seed_(std::string(prng_seed)),
        prng_type_(prng_type) {}

  // Applies the galois key to a generic RLWE ciphertext, and returns the
  // component polynomials of the resulting ciphertext.
  absl::StatusOr<std::vector<RnsPolynomial<ModularInt>>> ApplyToRlweCiphertext(
      const RnsRlweCiphertext<ModularInt>& ciphertext) const;

  // The two columns of the key matrix.
  std::vector<RnsPolynomial<ModularInt>> key_as_;
  std::vector<RnsPolynomial<ModularInt>> key_bs_;

  // The gadget used to construct this Galois key; does not take ownership.
  const RnsGadget<ModularInt>* gadget_;

  // The substitution power of the source secret key.
  int power_;

  // The RNS moduli used to construct this Galois key.
  std::vector<const PrimeModulus<ModularInt>*> moduli_;

  // PRNG seed for sampling the random polynomials in `key_as_`.
  std::string prng_seed_;

  // PRNG type for sampling the random polynomials in `key_as_`.
  PrngType prng_type_;
};

}  // namespace rlwe

#endif  // RLWE_RNS_RNS_GALOIS_KEY_H_
