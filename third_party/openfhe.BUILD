# Bazel build file for OpenFHE library
# This wraps the OpenFHE CMake build for Bazel consumption

package(default_visibility = ["//visibility:public"])

# OpenFHE core library
cc_library(
    name = "openfhe_core",
    hdrs = glob([
        "src/core/include/**/*.h",
        "src/pke/include/**/*.h",
        "src/binfhe/include/**/*.h",
    ]),
    includes = [
        "src/core/include",
        "src/pke/include",
        "src/binfhe/include",
    ],
    srcs = glob([
        "src/core/lib/**/*.cpp",
        "src/pke/lib/**/*.cpp",
    ]),
    copts = [
        "-std=c++17",
        "-DMATHBACKEND=4",  # Use NTL backend for ring operations
        "-Wno-unused-parameter",
        "-Wno-unused-variable",
    ],
    linkopts = ["-lntl", "-lgmp", "-lpthread"],
)

# OpenFHE PKE (Public Key Encryption) - for BGV/BFV/CKKS
cc_library(
    name = "openfhe_pke",
    deps = [":openfhe_core"],
    hdrs = glob(["src/pke/include/**/*.h"]),
    includes = ["src/pke/include"],
)

# Convenience alias for main library
alias(
    name = "openfhe",
    actual = ":openfhe_pke",
)
