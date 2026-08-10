/**
 * @file cuda_pattern_matcher.hpp
 * @brief GPU-Accelerated Parallel Batch Pattern Matcher Header for guardrail-cpp
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <guardrail/guardrail.hpp>

#include <cuda_runtime.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <span>

namespace guardrail::cuda {

/**
 * @brief Structure representing a pattern match result for a single prompt in a batch.
 */
struct GUARDRAIL_API BatchMatchResult {
    size_t prompt_index{0};
    bool pattern_matched{false};
    uint32_t matched_rule_id{0};
    size_t match_offset{0};
};

/**
 * @brief Thread-Safe CUDA GPU Parallel Batch Pattern Matcher.
 */
class GUARDRAIL_API CUDAPatternMatcher {
public:
    CUDAPatternMatcher();
    ~CUDAPatternMatcher();

    // Non-copyable, non-movable
    CUDAPatternMatcher(const CUDAPatternMatcher&) = delete;
    CUDAPatternMatcher& operator=(const CUDAPatternMatcher&) = delete;
    CUDAPatternMatcher(CUDAPatternMatcher&&) = delete;
    CUDAPatternMatcher& operator=(CUDAPatternMatcher&&) = delete;

    /**
     * @brief Uploads a dictionary of pattern signatures to GPU device memory.
     * @param patterns Vector of pattern string views to monitor.
     * @return Status::Success if patterns are copied to GPU device memory.
     */
    Status upload_pattern_dictionary(std::span<const std::string> patterns);

    /**
     * @brief Scans a batch of prompt strings in parallel on CUDA cores.
     * @param batch_prompts Vector of input prompt strings.
     * @param stream Optional CUDA stream handle for asynchronous execution.
     * @return Vector of BatchMatchResult structs corresponding to each input prompt.
     */
    [[nodiscard]] std::vector<BatchMatchResult> inspect_batch_prompts(
        std::span<const std::string> batch_prompts,
        cudaStream_t stream = nullptr
    ) const;

    /**
     * @brief Clears and frees GPU pattern memory.
     */
    void clear_dictionary() noexcept;

    [[nodiscard]] bool is_dictionary_loaded() const noexcept { return m_dictionary_loaded; }
    [[nodiscard]] size_t pattern_count() const noexcept { return m_pattern_count; }

private:
    mutable std::mutex m_mutex;
    uint8_t* m_d_patterns_flat{nullptr};  // Flat device array of pattern bytes
    uint32_t* m_d_pattern_offsets{nullptr}; // Device array of pattern offsets
    uint32_t* m_d_pattern_lengths{nullptr}; // Device array of pattern lengths
    size_t m_pattern_count{0};
    size_t m_total_pattern_bytes{0};
    bool m_dictionary_loaded{false};
};

} // namespace guardrail::cuda