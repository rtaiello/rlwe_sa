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

#ifndef RLWE_RNS_RNS_BGV_PUBLIC_KEY_H_
#define RLWE_RNS_RNS_BGV_PUBLIC_KEY_H_

#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "rlwe_sa/cc/shell_encryption/prng/prng.h"
#include "rlwe_sa/cc/shell_encryption/rns/coefficient_encoder.h"
#include "rlwe_sa/cc/shell_encryption/rns/rns_bgv_ciphertext.h"
#include "rlwe_sa/cc/shell_encryption/rns/rns_error_params.h"
#include "rlwe_sa/cc/shell_encryption/rns/rns_modulus.h"
#include "rlwe_sa/cc/shell_encryption/rns/rns_polynomial.h"
#include "rlwe_sa/cc/shell_encryption/rns/rns_public_key.h"
#include "rlwe_sa/cc/shell_encryption/rns/rns_secret_key.h"
#include "rlwe_sa/cc/shell_encryption/status_macros.h"

namespace rlwe {

template <typename ModularInt>
class RnsBgvPublicKey : public RnsRlwePublicKey<ModularInt> {
 public:
  using Integer = typename ModularInt::Int;

  // Allow copy and move, disallow copy-assign and move-assign.
  RnsBgvPublicKey(const RnsBgvPublicKey&) = default;
  RnsBgvPublicKey& operator=(const RnsBgvPublicKey&) = delete;
  RnsBgvPublicKey(RnsBgvPublicKey&&) = default;
  RnsBgvPublicKey& operator=(RnsBgvPublicKey&&) = delete;
  ~RnsBgvPublicKey() = default;

  // Generate a public key (b = a*s + t*e, -a) derived from the given secret
  // key, where the randomness a is freshly sampled uniform over the key's
  // modulus, and the error term e has coefficients sampled from a centered
  // binomial distribution of the given variance.
  static absl::StatusOr<RnsBgvPublicKey> Create(
      const RnsRlweSecretKey<ModularInt>& secret_key, int variance,
      PrngType prng_type, Integer plaintext_modulus) {
    RLWE_ASSIGN_OR_RETURN(RnsRlwePublicKey<ModularInt> public_key,
                          RnsRlwePublicKey<ModularInt>::Create(
                              secret_key, variance, prng_type,
                              /*error_scalar=*/plaintext_modulus));
    return RnsBgvPublicKey<ModularInt>(std::move(public_key));
  }

  // Returns a ciphertext that encrypts `messages` under this public key, where
  // `messages` are encoded using the given encoder, the encryption noises and
  // randomness have the same variance as the errors in this public key and are
  // sampled using `prng`, and the error parameters are given in `error_params`.
  // Note that the encoder type is a template parameter, and by default we use
  // `CoefficientEncoder` to use messages as coefficients of the plaintext
  // polynomial.
  template <typename Encoder = CoefficientEncoder<ModularInt>>
  absl::StatusOr<RnsBgvCiphertext<ModularInt>> Encrypt(
      absl::Span<const typename ModularInt::Int> messages,
      const Encoder* encoder, const RnsErrorParams<ModularInt>* error_params,
      SecurePrng* prng) const;

 private:
  explicit RnsBgvPublicKey(RnsRlwePublicKey<ModularInt> public_key)
      : RnsRlwePublicKey<ModularInt>(std::move(public_key)) {}
};

template <typename ModularInt>
template <typename Encoder>
absl::StatusOr<RnsBgvCiphertext<ModularInt>>
RnsBgvPublicKey<ModularInt>::Encrypt(
    absl::Span<const typename ModularInt::Int> messages, const Encoder* encoder,
    const RnsErrorParams<ModularInt>* error_params, SecurePrng* prng) const {
  if (encoder == nullptr) {
    return absl::InvalidArgumentError("`encoder` must not be null.");
  }
  if (error_params == nullptr) {
    return absl::InvalidArgumentError("`error_params` must not be null.");
  }
  if (prng == nullptr) {
    return absl::InvalidArgumentError("`prng` must not be null.");
  }

  // Encode messages into a plaintext polynomial.
  RLWE_ASSIGN_OR_RETURN(RnsPolynomial<ModularInt> plaintext,
                        encoder->EncodeBgv(messages, this->Moduli()));

  if (!plaintext.IsNttForm()) {
    RLWE_RETURN_IF_ERROR(plaintext.ConvertToNttForm(this->Moduli()));
  }

  // Sample encryption randomness r.
  int log_n = this->LogN();
  RLWE_ASSIGN_OR_RETURN(
      RnsPolynomial<ModularInt> r,
      SampleError<ModularInt>(log_n, this->variance(), this->Moduli(), prng));

  // c0 = b * r + t * e' + Encode(messages).
  Integer plaintext_modulus = encoder->PlaintextModulus();
  RLWE_ASSIGN_OR_RETURN(
      RnsPolynomial<ModularInt> c0,
      SampleError<ModularInt>(log_n, this->variance(), this->Moduli(), prng));
  RLWE_RETURN_IF_ERROR(c0.MulInPlace(plaintext_modulus, this->Moduli()));
  RLWE_RETURN_IF_ERROR(c0.FusedMulAddInPlace(this->KeyB(), r, this->Moduli()));
  RLWE_RETURN_IF_ERROR(c0.AddInPlace(plaintext, this->Moduli()));

  // c1 = a * r + t * e''.
  RLWE_ASSIGN_OR_RETURN(
      RnsPolynomial<ModularInt> c1,
      SampleError<ModularInt>(log_n, this->variance(), this->Moduli(), prng));
  RLWE_RETURN_IF_ERROR(c1.MulInPlace(plaintext_modulus, this->Moduli()));
  RLWE_RETURN_IF_ERROR(c1.FusedMulAddInPlace(this->KeyA(), r, this->Moduli()));

  return RnsBgvCiphertext<ModularInt>(
      {std::move(c0), std::move(c1)}, this->moduli(),
      /*power_of_s=*/1, error_params->B_publickey_encryption(), error_params);
}

}  // namespace rlwe

#endif  // RLWE_RNS_RNS_BGV_PUBLIC_KEY_H_
