#include <pybind11/pybind11.h>
#include <pybind11/complex.h>
#include <pybind11/stl.h>
#include "rlwe_sa/cc/rlwe_sa_api.h"  // Include the header file where your class is defined
#include "rlwe_sa/cc/shell_encryption/montgomery.h"
#include "absl/numeric/int128.h"

namespace py = pybind11;


// Define the module name
using ModularInt = rlwe::MontgomeryInt<uint64_t>;


PYBIND11_MODULE(rlwe_sa, m) {
    // Bind the class
    py::class_<RlweSecAgg<ModularInt>>(m, "RlweSecAgg")
        .def(py::init<int, size_t, const std::vector<rlwe::Polynomial<ModularInt>>&>(),
            py::arg("input_size"), py::arg("log_t"), py::arg("as") = std::vector<rlwe::Polynomial<ModularInt>>())
        .def("get_as", &RlweSecAgg<ModularInt>::GetAs)  // Member function
        .def("sample_key", &RlweSecAgg<ModularInt>::SampleKey)  // Member function
        .def("create_key", &RlweSecAgg<ModularInt>::CreateKey)  // Member function
        .def("encrypt", &RlweSecAgg<ModularInt>::Encrypt)  // Member function
        .def("decrypt", &RlweSecAgg<ModularInt>::Decrypt)  // Member function
        .def("aggregate", &RlweSecAgg<ModularInt>::Aggregate)  // Member function
        .def("sum_keys", &RlweSecAgg<ModularInt>::SumKeys)  // Member function
        .def_static("sample_plaintext", &RlweSecAgg<ModularInt>::SamplePlaintext)  // Static function
        .def_static("convert_key", &RlweSecAgg<ModularInt>::ConvertKey);  // Static function
    py::class_<rlwe::SymmetricRlweKey<ModularInt>>(m, "SymmetricRlweKey");
    py::class_<rlwe::SymmetricRlweCiphertext<ModularInt>>(m, "SymmetricRlweCiphertext");
    py::class_<rlwe::Polynomial<ModularInt>>(m, "Polynomial");
}
