# CMakeLists.txt
# Root C++20 & CUDA Build System for guardrail-cpp
# Author: Kamran Saberifard
# License: Apache 2.0

cmake_minimum_required(VERSION 3.20)

project(guardrail-cpp
    VERSION 0.1.0
    DESCRIPTION "Sub-Millisecond Native C++/CUDA Prompt Injection Defense & Memory Shield"
    LANGUAGES CXX CUDA
)

# ------------------------------------------------------------------------------
# 1. C++ Standard & Compiler Optimization Flags
# ------------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Default to Release build type for maximum SLA throughput (<0.4ms requirement)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Target modern CUDA architectures (Ampere, Ada, Hopper, Blackwell ready)
if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
    set(CMAKE_CUDA_ARCHITECTURES 80 86 89 90)
endif()

# Enable aggressive C++ compiler optimizations for sub-millisecond execution
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(
        -O3
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wnon-virtual-dtor
        -Wnull-dereference
        -Wconversion
        -fstrict-aliasing
    )
    # Enable AVX-512 / AVX-2 SIMD vectorization if supported by host CPU
    if(NOT CMAKE_CROSSCOMPILING)
        add_compile_options(-march=native)
    endif()
endif()

# ------------------------------------------------------------------------------
# 2. Find Dependencies (OpenSSL 3.0, CUDAToolkit, Threads, PkgConfig)
# ------------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

find_package(OpenSSL 3.0 REQUIRED)
message(STATUS "[guardrail-cpp] Found OpenSSL: Version ${OPENSSL_VERSION}")

find_package(CUDAToolkit REQUIRED)
message(STATUS "[guardrail-cpp] Found CUDA Toolkit: Version ${CUDAToolkit_VERSION}")

# Optional: Hyperscan / Vectorscan SIMD regex engine
pkg_check_modules(HYPERSCAN libhs)
if(HYPERSCAN_FOUND)
    message(STATUS "[guardrail-cpp] Found Intel Hyperscan SIMD Regex Engine")
    add_compile_definitions(GUARDRAIL_HAS_HYPERSCAN=1)
else()
    message(STATUS "[guardrail-cpp] Hyperscan not found. Falling back to native C++20 Aho-Corasick matcher.")
endif()

# ------------------------------------------------------------------------------
# 3. Core C++/CUDA Library Target (`guardrail_core`)
# ------------------------------------------------------------------------------
file(GLOB_RECURSE GUARDRAIL_CXX_SOURCES
    "src/*.cpp"
)

file(GLOB_RECURSE GUARDRAIL_CUDA_SOURCES
    "cuda/*.cu"
)

add_library(guardrail_core SHARED
    ${GUARDRAIL_CXX_SOURCES}
    ${GUARDRAIL_CUDA_SOURCES}
)

target_include_directories(guardrail_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        ${OPENSSL_INCLUDE_DIR}
        ${CUDAToolkit_INCLUDE_DIRS}
)

if(HYPERSCAN_FOUND)
    target_include_directories(guardrail_core PUBLIC ${HYPERSCAN_INCLUDE_DIRS})
    target_link_libraries(guardrail_core PUBLIC ${HYPERSCAN_LIBRARIES})
endif()

target_link_libraries(guardrail_core
    PUBLIC
        OpenSSL::Crypto
        CUDA::cudart
        CUDA::cuda_driver
        Threads::Threads
)

target_compile_definitions(guardrail_core
    PRIVATE
        GUARDRAIL_BUILD_INTERNAL=1
)

# ------------------------------------------------------------------------------
# 4. CLI Executable Target (`guardrail-cli`)
# ------------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmd/guardrail-cli/main.cpp")
    add_executable(guardrail-cli cmd/guardrail-cli/main.cpp)
    target_link_libraries(guardrail-cli PRIVATE guardrail_core)
endif()

# ------------------------------------------------------------------------------
# 5. Unit & Security Performance Testing
# ------------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    enable_testing()
    add_subdirectory(tests)
endif()