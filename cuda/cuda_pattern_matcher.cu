/**
 * @file cuda_pattern_matcher.cu
 * @brief GPU Parallel Batch Prompt Pattern Matching Kernels for guardrail-cpp
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>

#include <cstdint>
#include <cstddef>

namespace guardrail::cuda {

// -----------------------------------------------------------------------------
// CUDA Device Helper Functions
// -----------------------------------------------------------------------------

__device__ __forceinline__ static bool device_substr_match(
    const char* prompt,
    size_t prompt_len,
    size_t start_pos,
    const uint8_t* pattern,
    size_t pattern_len
) {
    if (start_pos + pattern_len > prompt_len) return false;

    for (size_t i = 0; i < pattern_len; ++i) {
        // Lowercase comparison for fast case-insensitive CUDA matching
        char p_ch = prompt[start_pos + i];
        if (p_ch >= 'A' && p_ch <= 'Z') p_ch += 32;

        char pat_ch = static_cast<char>(pattern[i]);
        if (pat_ch >= 'A' && pat_ch <= 'Z') pat_ch += 32;

        if (p_ch != pat_ch) return false;
    }
    return true;
}

// -----------------------------------------------------------------------------
// CUDA Batch Pattern Search Kernel
// -----------------------------------------------------------------------------

/**
 * @brief CUDA kernel assigning threads to inspect batch prompt buffers in parallel.
 */
__global__ void kernel_batch_pattern_search(
    const char* __restrict__ d_prompts_flat,
    const uint32_t* __restrict__ d_prompt_offsets,
    const uint32_t* __restrict__ d_prompt_lengths,
    size_t num_prompts,
    const uint8_t* __restrict__ d_patterns_flat,
    const uint32_t* __restrict__ d_pattern_offsets,
    const uint32_t* __restrict__ d_pattern_lengths,
    size_t num_patterns,
    uint8_t* __restrict__ d_match_results,
    uint32_t* __restrict__ d_match_rules,
    uint32_t* __restrict__ d_match_offsets
) {
    size_t prompt_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (prompt_idx >= num_prompts) return;

    const char* prompt = d_prompts_flat + d_prompt_offsets[prompt_idx];
    size_t prompt_len = d_prompt_lengths[prompt_idx];

    d_match_results[prompt_idx] = 0;
    d_match_rules[prompt_idx] = 0;
    d_match_offsets[prompt_idx] = 0;

    if (prompt_len == 0) return;

    // Scan prompt text against all dictionary patterns
    for (size_t pat_idx = 0; pat_idx < num_patterns; ++pat_idx) {
        const uint8_t* pattern = d_patterns_flat + d_pattern_offsets[pat_idx];
        size_t pattern_len = d_pattern_lengths[pat_idx];

        if (pattern_len == 0 || pattern_len > prompt_len) continue;

        for (size_t pos = 0; pos <= (prompt_len - pattern_len); ++pos) {
            if (device_substr_match(prompt, prompt_len, pos, pattern, pattern_len)) {
                d_match_results[prompt_idx] = 1;
                d_match_rules[prompt_idx] = static_cast<uint32_t>(pat_idx);
                d_match_offsets[prompt_idx] = static_cast<uint32_t>(pos);
                return; // Early exit on first pattern match hit
            }
        }
    }
}

// -----------------------------------------------------------------------------
// C Linkage Host Launcher
// -----------------------------------------------------------------------------

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
) {
    if (num_prompts == 0 || num_patterns == 0) return cudaSuccess;

    int threads_per_block = 256;
    int blocks_per_grid = static_cast<int>((num_prompts + threads_per_block - 1) / threads_per_block);

    kernel_batch_pattern_search<<<blocks_per_grid, threads_per_block, 0, stream>>>(
        d_prompts_flat,
        d_prompt_offsets,
        d_prompt_lengths,
        num_prompts,
        d_patterns_flat,
        d_pattern_offsets,
        d_pattern_lengths,
        num_patterns,
        d_match_results,
        d_match_rules,
        d_match_offsets
    );

    return cudaGetLastError();
}

} // namespace guardrail::cuda