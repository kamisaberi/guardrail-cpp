# tests/CMakeLists.txt
# Security & Sub-Millisecond SLA Unit Test Configuration for guardrail-cpp
# Author: Kamran Saberifard
# License: Apache 2.0

message(STATUS "[guardrail-cpp] Configuring Security & Sub-Millisecond SLA Unit Tests")

enable_testing()

# ------------------------------------------------------------------------------
# Test 1: Prompt Injection & System Override Security Test
# ------------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_prompt_injection.cpp")
    add_executable(test_prompt_injection test_prompt_injection.cpp)
    target_link_libraries(test_prompt_injection PRIVATE guardrail_core Threads::Threads)
    add_test(NAME PromptInjectionTest COMMAND test_prompt_injection)
endif()

# ------------------------------------------------------------------------------
# Test 2: Token Sanitizer & Unicode Normalization Test
# ------------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_token_sanitizer.cpp")
    add_executable(test_token_sanitizer test_token_sanitizer.cpp)
    target_link_libraries(test_token_sanitizer PRIVATE guardrail_core Threads::Threads)
    add_test(NAME TokenSanitizerTest COMMAND test_token_sanitizer)
endif()

# ------------------------------------------------------------------------------
# Test 3: GPU Parallel Batch CUDA Pattern Matcher Test
# ------------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_cuda_matcher.cpp")
    add_executable(test_cuda_matcher test_cuda_matcher.cpp)
    target_link_libraries(test_cuda_matcher PRIVATE guardrail_core Threads::Threads)
    add_test(NAME CUDAMatcherTest COMMAND test_cuda_matcher)
endif()