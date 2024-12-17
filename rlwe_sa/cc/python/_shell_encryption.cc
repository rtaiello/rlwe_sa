#include <pybind11/pybind11.h>
#include <pybind11/complex.h>
#include <pybind11/stl.h>
#include "rlwe_sa/cc/shell_encryption_api.h"  // Include the header file where your class is defined
#include "rlwe_sa/cc/shell_encryption/montgomery.h"
#include "absl/numeric/int128.h"


namespace rlwe_sa {

namespace py = pybind11;
using ModularInt = rlwe::MontgomeryInt<absl::uint128>;

// Convert absl::uint128 to Python int
py::int_ Uint128ToPyInt(absl::uint128 value) {
    uint64_t high = absl::Uint128High64(value);
    uint64_t low = absl::Uint128Low64(value);
    return (py::int_(high) << 64) | py::int_(low);
}

PYBIND11_MODULE(_shell_encryption, m) {
    // Bind the class
    py::class_<RlweSecAgg<ModularInt>>(m, "RlweSecAgg")
        // Constructor int,size_t and optional string
        .def(py::init<int, size_t>(), "Constructor with two arguments")
        .def(py::init<int, size_t, std::string>(), "Constructor with three arguments")
        // Return get_seed as bytes
        .def("get_seed", [](RlweSecAgg<ModularInt> &instance) {
            std::string seed = instance.GetSeed();  // Get the seed as a std::string
            return py::bytes(seed);  // Return the data as py::bytes without transcoding
        })
        .def("sample_key", &RlweSecAgg<ModularInt>::SampleKey)  // Member function
        .def("create_key", &RlweSecAgg<ModularInt>::CreateKey)  // Member function
        .def("encrypt", [](RlweSecAgg<rlwe::MontgomeryInt<absl::uint128>>& self,
                           const rlwe::SymmetricRlweKey<rlwe::MontgomeryInt<absl::uint128>>& key,
                           const std::vector<std::uint64_t>& plaintext) {
            // Convert std::uint64_t into absl::uint128
            std::vector<absl::uint128> converted_plaintext;
            for (const auto& value : plaintext) {
                converted_plaintext.push_back(static_cast<absl::uint128>(value));
            }
            return self.Encrypt(key, converted_plaintext);
        })
        .def("decrypt", [](RlweSecAgg<rlwe::MontgomeryInt<absl::uint128>>& self,
                           const rlwe::SymmetricRlweKey<rlwe::MontgomeryInt<absl::uint128>>& key,
                           const std::vector<rlwe::SymmetricRlweCiphertext<rlwe::MontgomeryInt<absl::uint128>>>& ciphertexts) {
            // Call the original Decrypt function
            auto result = self.Decrypt(key, ciphertexts);

            // Convert std::vector<absl::uint128> to Python list of ints
            std::vector<py::int_> py_result;
            for (const auto& val : result) {
                py_result.push_back(Uint128ToPyInt(val));
            }
            return py_result;  // Return as Python list
        }) // Member function
        .def("aggregate", &RlweSecAgg<ModularInt>::Aggregate)  // Member function
        .def("sum_keys", &RlweSecAgg<ModularInt>::SumKeys)  // Member function
        .def_static("sample_plaintext", &RlweSecAgg<ModularInt>::SamplePlaintext)  // Static function
        .def_static("convert_key", &RlweSecAgg<ModularInt>::ConvertKey);  // Static function
    py::class_<rlwe::SymmetricRlweKey<ModularInt>>(m, "SymmetricRlweKey");
    py::class_<rlwe::SymmetricRlweCiphertext<ModularInt>>(m, "SymmetricRlweCiphertext")
    // Add this two method Len and LogModulus
        .def("len", &rlwe::SymmetricRlweCiphertext<ModularInt>::Len)
        .def("log_modulus", &rlwe::SymmetricRlweCiphertext<ModularInt>::LogModulus)
        .def("num_coeffs", &rlwe::SymmetricRlweCiphertext<ModularInt>::NumCoeffs);
}
}