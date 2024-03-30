load("@pybind11_bazel//:build_defs.bzl", "pybind_extension")
load("@rules_python//python:defs.bzl", "py_binary", "py_library", "py_test")

pybind_extension(
    name = "rlwe_sa",  
    srcs = ["rlwe_sa.cc"],
    deps = ["//rlwe_sa/cc:rlwe_sa_api"],


)

py_test(
    name = "rlwe_sa_test",
    srcs = ["rlwe_sa_test.py"],
    deps = [
        ":rlwe_sa"
    ],
    python_version = "PY3",
)

py_library(
    name = "rlwe_sa",
    data = [":rlwe_sa.so"],
)

py_binary(
    name = "rlwe_sa_benchmark",
    srcs = ["rlwe_sa_benchmark.py"],
    deps = [
        ":rlwe_sa"
    ],
)