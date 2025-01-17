/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RLWE_PRNG_INTEGRAL_PRNG_TYPE_H_
#define RLWE_PRNG_INTEGRAL_PRNG_TYPE_H_

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "rlwe_sa/cc/shell_encryption/prng/chacha_prng.h"
#include "rlwe_sa/cc/shell_encryption/prng/hkdf_prng.h"
#include "rlwe_sa/cc/shell_encryption/prng/single_thread_chacha_prng.h"
#include "rlwe_sa/cc/shell_encryption/prng/single_thread_hkdf_prng.h"

namespace rlwe {

typedef ::testing::Types<HkdfPrng, SingleThreadHkdfPrng, ChaChaPrng,
                         SingleThreadChaChaPrng>
    TestingPrngTypes;

}  // namespace rlwe

#endif  // RLWE_PRNG_INTEGRAL_PRNG_TYPE_H_
