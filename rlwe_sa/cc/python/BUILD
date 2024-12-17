load("@pybind11_bazel//:build_defs.bzl", "pybind_extension")
load("@rules_python//python:defs.bzl", "py_binary", "py_library", "py_test")

pybind_extension(
    name = "_shell_encryption",  
    srcs = ["_shell_encryption.cc"],
    deps = ["//rlwe_sa/cc:shell_encryption_api"],


)

py_test(
    name = "_shell_encryption_test",
    srcs = ["_shell_encryption_test.py"],
    deps = [
        ":_shell_encryption"
    ],
    python_version = "PY3",
)

py_library(
    name = "_shell_encryption",
    data = [":_shell_encryption.so"],
)
