load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

cc_library(
    name = "rlwe_sa_api",
    hdrs = [
        "rlwe_sa_api.h",
    ],
    deps = [
        "//rlwe_sa/cc/shell_encryption:constants",
        "//rlwe_sa/cc/shell_encryption:context",
        "//rlwe_sa/cc/shell_encryption:montgomery",
        "//rlwe_sa/cc/shell_encryption:ntt_parameters",
        "//rlwe_sa/cc/shell_encryption:polynomial",
        "//rlwe_sa/cc/shell_encryption:serialization_cc_proto",
        "//rlwe_sa/cc/shell_encryption:statusor_fork",
        "//rlwe_sa/cc/shell_encryption:sample_error",
        "//rlwe_sa/cc/shell_encryption:symmetric_encryption",
        "//rlwe_sa/cc/shell_encryption/prng:single_thread_hkdf_prng",
        "@com_google_absl//absl/status",

    ],
    visibility = ["//visibility:public"],

)
cc_test(
    name = "rlwe_sa_api_test",
    size = "medium",
    srcs = [
        "rlwe_sa_api_test.cc",
    ],
    deps = [
        ":rlwe_sa_api",
        "//rlwe_sa/cc/shell_encryption/testing:parameters",
        "//rlwe_sa/cc/shell_encryption/testing:status_is_fork",
        "//rlwe_sa/cc/shell_encryption/testing:status_testing",
        "//rlwe_sa/cc/shell_encryption/testing:testing_prng",
        "//rlwe_sa/cc/shell_encryption/testing:testing_utils",
        "@com_github_google_googletest//:gtest_main",
        "@com_google_absl//absl/status",
    ],
)

