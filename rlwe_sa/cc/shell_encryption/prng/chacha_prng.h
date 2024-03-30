/*
 * Copyright 2019 Google LLC.
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

// An implementation of a PRNG using the ChaCha20 stream cipher. Since this is
// a stream cipher, the key stream can be obtained by "encrypting" the plaintext
// 0....0.

#ifndef RLWE_CHACHA_PRNG_H_
#define RLWE_CHACHA_PRNG_H_

#include "absl/base/thread_annotations.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "rlwe_sa/cc/shell_encryption/prng/chacha_prng_util.h"
#include "rlwe_sa/cc/shell_encryption/prng/prng.h"
#include "rlwe_sa/cc/shell_encryption/statusor.h"

namespace rlwe {

class ChaChaPrng : public SecurePrng {
 public:
  // Constructs a secure pseudorandom number generator using the ChaCha20 stream
  // cipher. The parameter in_key is the key for the ChaCha20.
  //
  // Input keys should contain sufficient randomness (such as those generated by
  // the ChaChaPrngGenerateKey function) to ensure the random generated strings
  // are pseudorandom. As long as the initial key contains sufficient entropy,
  // there is no bound on the number of pseudorandom bytes that can be created.
  //
  // ChaChaPrng allows replaying pseudorandom outputs. For any fixed input key,
  // the pseudorandom outputs of ChaChaPrng will be identical.
  //
  // For a fixed key and salt, the underlying ChaCha primitive can
  // generate 2^32 * 64 pseudorandom bytes. Instead, we will construct a smaller
  // pool of 255 * 32 bytes to match the Hkdf Prng. Once, these bytes have been
  // exhausted, the prng deterministically re-salts the key using a salting
  // counter, thereby constructing a new internal ChaCha that can output more
  // pseudorandom bytes.
  //
  // Fails if the key is not the expected size or on internal cryptographic
  // errors.
  //
  // Thread safe.
  static rlwe::StatusOr<std::unique_ptr<ChaChaPrng>>
  Create(absl::string_view in_key);

  // Returns 8 bits of randomness.
  //
  // Fails on internal cryptographic errors.
  rlwe::StatusOr<Uint8> Rand8() override;

  // Returns 64 bits of randomness.
  //
  // Fails on internal cryptographic errors.
  rlwe::StatusOr<Uint64> Rand64() override;

  // Generate a valid seed for the Prng.
  //
  // Fails on internal cryptographic errors.
  static rlwe::StatusOr<std::string> GenerateSeed() {
    return internal::ChaChaPrngGenerateKey();
  }

  // Output the size of the expected generated seed.
  static int SeedLength() { return internal::kChaChaKeyBytesSize; }

 private:
  explicit ChaChaPrng(absl::string_view in_key, int position_in_buffer,
                      int salt_counter, std::vector<Uint8> buffer);

  absl::Mutex mu_;  // Guards all values below

  const std::string key_;
  int position_in_buffer_ ABSL_GUARDED_BY(mu_);
  int salt_counter_ ABSL_GUARDED_BY(mu_);
  std::vector<Uint8> buffer_ ABSL_GUARDED_BY(mu_);
};

}  // namespace rlwe

#endif  // RLWE_CHACHA_PRNG_H_
