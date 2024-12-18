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
py::object Uint128ToPyInt(const absl::uint128& val) {
    // Convert absl::uint128 to Python integer
    // Use Python's built-in int constructors to handle large integers
    uint64_t high = absl::Uint128High64(val);
    uint64_t low = absl::Uint128Low64(val);
    
    // Reconstruct the full integer in Python
    py::object py_high = py::int_(high);
    py::object py_low = py::int_(low);
    
    // Shift high part and combine with low part
    return py_high * py::int_(1ULL << 64) + py_low;
}

absl::uint128 convert_python_int_to_uint128(py::object py_int) {
    // Convert Python int to a string representation
    py::str py_str = py::str(py_int);
    std::string int_str = py_str.cast<std::string>();
    
    // Manual parsing of the string to uint128
    absl::uint128 result = 0;
    for (char c : int_str) {
        if (c >= '0' && c <= '9') {
            result = result * 10 + (c - '0');
        } else {
            throw std::invalid_argument("Invalid integer string");
        }
    }
    
    return result;
}

PYBIND11_MODULE(_shell_encryption, m) {
    // Bind the class
    m.def("uint128_to_pyint", &Uint128ToPyInt, "Convert absl::uint128 to Python int");
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
                   const py::list& plaintext) {
    std::vector<absl::uint128> converted_plaintext;
    for (py::handle value : plaintext) {
        // converted_plaintext.push_back(convert_python_int_to_uint128(py::reinterpret_borrow<py::object>(value)));
        
        converted_plaintext.push_back(absl::MakeUint128(1ULL << 6, 0));

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

        std::cout << "Decrypted values (first 10):" << std::endl;
        int count = 0;
        for (const auto& val : result) {
            py_result.push_back(Uint128ToPyInt(val));
            
            // Print the first 10 values to the console
            if (count < 10) {
                uint64_t high = absl::Uint128High64(val);
                uint64_t low = absl::Uint128Low64(val);
                std::cout << "Value " << count << ": high=" << high << ", low=" << low << std::endl;
                ++count;
            }
        }

        return py_result;  // Return as Python list
    })
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