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
    uint64_t high = absl::Uint128High64(val);
    uint64_t low = absl::Uint128Low64(val);
    
    if (high == 0) {
        return py::int_(low);
    } else {
        // Create the high part first as a Python integer
        py::object result = py::int_(high);
        
        // Multiply by 2^64 using Python's arithmetic
        result = result.attr("__lshift__")(64);
        
        // Add the low part
        if (low != 0) {
            result = result.attr("__or__")(low);
        }
        
        return result;
    }
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
        converted_plaintext.push_back(convert_python_int_to_uint128(py::reinterpret_borrow<py::object>(value)));
        

    }
    return self.Encrypt(key, converted_plaintext);
})
    .def("decrypt", [](RlweSecAgg<rlwe::MontgomeryInt<absl::uint128>>& self,
                    const rlwe::SymmetricRlweKey<rlwe::MontgomeryInt<absl::uint128>>& key,
                    const std::vector<rlwe::SymmetricRlweCiphertext<rlwe::MontgomeryInt<absl::uint128>>>& ciphertexts) {
        // Call the original Decrypt function
        auto result = self.Decrypt(key, ciphertexts);
        // // Convert std::vector<absl::uint128> to Python list of ints
        std::vector<py::int_> py_result;
        for (const absl::uint128& val : result) {

            py_result.push_back(py::int_(Uint128ToPyInt(val)));
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