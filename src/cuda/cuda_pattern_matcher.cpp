/**
 * @file cuda_pattern_matcher.cpp
 * @brief GPU Parallel Batch Prompt Pattern Matcher Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <guardrail/cuda/cuda_pattern_matcher.hpp>

#include <cuda_runtime.h>
#include <iostream>
#include <format>
#include <cstring>
#include <numeric>

// Declare C linkage CUDA launcher function defined in cuda/cuda_pattern_matcher.cu
extern "C" cudaError_t cuda_launch_batch_pattern_search(
    const char* d_prompts_flat,
    const uint32_t* d_prompt_offsets,
    const uint32_t* d_prompt_lengths,
    size_t num_prompts,
    const uint8_t* d_patterns_flat,
    const uint32_t* d_pattern_offsets,
    const uint32_t* d_pattern_lengths,
    size_t num_patterns,
    uint8_t* d_match_results,
    uint32_t* d_match_rules,
    uint32_t* d_match_offsets,
    cudaStream_t stream
);

namespace guardrail::cuda {

CUDAPatternMatcher::CUDAPatternMatcher() = default;

CUDAPatternMatcher::~CUDAPatternMatcher() {
    clear_dictionary();
}

Status CUDAPatternMatcher::upload_pattern_dictionary(std::span<const std::string> patterns) {
    std::lock_guard<std::mutex> lock(m_mutex);

    clear_dictionary();

    if (patterns.empty()) {
        return Status::Success;
    }

    m_pattern_count = patterns.size();

    // 1. Calculate pattern offsets and flatten strings into a single linear host byte array
    std::vector<uint8_t> h_patterns_flat;
    std::vector<uint32_t> h_pattern_offsets;
    std::vector<uint32_t> h_pattern_lengths;

    h_pattern_offsets.reserve(patterns.size());
    h_pattern_lengths.reserve(patterns.size());

    size_t current_offset = 0;
    for (const auto& pat : patterns) {
        h_pattern_offsets.push_back(static_cast<uint32_t>(current_offset));
        h_pattern_lengths.push_back(static_cast<uint32_t>(pat.size()));

        h_patterns_flat.insert(h_patterns_flat.end(), pat.begin(), pat.end());
        current_offset += pat.size();
    }

    m_total_pattern_bytes = h_patterns_flat.size();

    // 2. Allocate GPU VRAM memory for pattern dictionary
    cudaError_t err = cudaMalloc(&m_d_patterns_flat, m_total_pattern_bytes);
    if (err != cudaSuccess) return Status::ErrCUDAInspectionFailed;

    err = cudaMalloc(&m_d_pattern_offsets, patterns.size() * sizeof(uint32_t));
    if (err != cudaSuccess) {
        clear_dictionary();
        return Status::ErrCUDAInspectionFailed;
    }

    err = cudaMalloc(&m_d_pattern_lengths, patterns.size() * sizeof(uint32_t));
    if (err != cudaSuccess) {
        clear_dictionary();
        return Status::ErrCUDAInspectionFailed;
    }

    // 3. Copy pattern dictionary to GPU VRAM
    cudaMemcpy(m_d_patterns_flat, h_patterns_flat.data(), m_total_pattern_bytes, cudaMemcpyHostToDevice);
    cudaMemcpy(m_d_pattern_offsets, h_pattern_offsets.data(), patterns.size() * sizeof(uint32_t), cudaMemcpyHostToDevice);
    cudaMemcpy(m_d_pattern_lengths, h_pattern_lengths.data(), patterns.size() * sizeof(uint32_t), cudaMemcpyHostToDevice);

    m_dictionary_loaded = true;
    return Status::Success;
}

std::vector<BatchMatchResult> CUDAPatternMatcher::inspect_batch_prompts(
    std::span<const std::string> batch_prompts,
    cudaStream_t stream
) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::vector<BatchMatchResult> results(batch_prompts.size());
    if (batch_prompts.empty() || !m_dictionary_loaded) {
        return results;
    }

    // 1. Flatten host batch prompts into linear byte array
    std::vector<char> h_prompts_flat;
    std::vector<uint32_t> h_prompt_offsets;
    std::vector<uint32_t> h_prompt_lengths;

    h_prompt_offsets.reserve(batch_prompts.size());
    h_prompt_lengths.reserve(batch_prompts.size());

    size_t current_offset = 0;
    for (const auto& prompt : batch_prompts) {
        h_prompt_offsets.push_back(static_cast<uint32_t>(current_offset));
        h_prompt_lengths.push_back(static_cast<uint32_t>(prompt.size()));

        h_prompts_flat.insert(h_prompts_flat.end(), prompt.begin(), prompt.end());
        current_offset += prompt.size();
    }

    if (h_prompts_flat.empty()) return results;

    // 2. Allocate temporary device buffers for prompt batch and results
    char* d_prompts_flat = nullptr;
    uint32_t* d_prompt_offsets = nullptr;
    uint32_t* d_prompt_lengths = nullptr;
    uint8_t* d_match_results = nullptr;
    uint32_t* d_match_rules = nullptr;
    uint32_t* d_match_offsets = nullptr;

    size_t num_prompts = batch_prompts.size();

    cudaMalloc(&d_prompts_flat, h_prompts_flat.size());
    cudaMalloc(&d_prompt_offsets, num_prompts * sizeof(uint32_t));
    cudaMalloc(&d_prompt_lengths, num_prompts * sizeof(uint32_t));
    cudaMalloc(&d_match_results, num_prompts * sizeof(uint8_t));
    cudaMalloc(&d_match_rules, num_prompts * sizeof(uint32_t));
    cudaMalloc(&d_match_offsets, num_prompts * sizeof(uint32_t));

    // Copy batch prompts to GPU VRAM
    cudaMemcpyAsync(d_prompts_flat, h_prompts_flat.data(), h_prompts_flat.size(), cudaMemcpyHostToDevice, stream);
    cudaMemcpyAsync(d_prompt_offsets, h_prompt_offsets.data(), num_prompts * sizeof(uint32_t), cudaMemcpyHostToDevice, stream);
    cudaMemcpyAsync(d_prompt_lengths, h_prompt_lengths.data(), num_prompts * sizeof(uint32_t), cudaMemcpyHostToDevice, stream);

    // 3. Launch parallel CUDA batch pattern search kernel
    cudaError_t err = cuda_launch_batch_pattern_search(
        d_prompts_flat,
        d_prompt_offsets,
        d_prompt_lengths,
        num_prompts,
        m_d_patterns_flat,
        m_d_pattern_offsets,
        m_d_pattern_lengths,
        m_pattern_count,
        d_match_results,
        d_match_rules,
        d_match_offsets,
        stream
    );

    if (err != cudaSuccess) {
        std::cerr << std::format("[GUARDRAIL-CUDA-ERROR] CUDA batch pattern search kernel failed: {}\n", cudaGetErrorString(err));
    }

    // 4. Copy results back to host memory
    std::vector<uint8_t> h_match_results(num_prompts);
    std::vector<uint32_t> h_match_rules(num_prompts);
    std::vector<uint32_t> h_match_offsets(num_prompts);

    cudaMemcpyAsync(h_match_results.data(), d_match_results, num_prompts * sizeof(uint8_t), cudaMemcpyDeviceToHost, stream);
    cudaMemcpyAsync(h_match_rules.data(), d_match_rules, num_prompts * sizeof(uint32_t), cudaMemcpyDeviceToHost, stream);
    cudaMemcpyAsync(h_match_offsets.data(), d_match_offsets, num_prompts * sizeof(uint32_t), cudaMemcpyDeviceToHost, stream);

    if (stream) cudaStreamSynchronize(stream);
    else cudaDeviceSynchronize();

    // 5. Populate BatchMatchResult output vector
    for (size_t i = 0; i < num_prompts; ++i) {
        results[i].prompt_index = i;
        results[i].pattern_matched = (h_match_results[i] == 1);
        results[i].matched_rule_id = h_match_rules[i];
        results[i].match_offset = h_match_offsets[i];
    }

    // Free temporary device memory
    cudaFree(d_prompts_flat);
    cudaFree(d_prompt_offsets);
    cudaFree(d_prompt_lengths);
    cudaFree(d_match_results);
    cudaFree(d_match_rules);
    cudaFree(d_match_offsets);

    return results;
}

void CUDAPatternMatcher::clear_dictionary() noexcept {
    if (m_d_patterns_flat) {
        cudaFree(m_d_patterns_flat);
        m_d_patterns_flat = nullptr;
    }
    if (m_d_pattern_offsets) {
        cudaFree(m_d_pattern_offsets);
        m_d_pattern_offsets = nullptr;
    }
    if (m_d_pattern_lengths) {
        cudaFree(m_d_pattern_lengths);
        m_d_pattern_lengths = nullptr;
    }

    m_pattern_count = 0;
    m_total_pattern_bytes = 0;
    m_dictionary_loaded = false;
}

} // namespace guardrail::cuda