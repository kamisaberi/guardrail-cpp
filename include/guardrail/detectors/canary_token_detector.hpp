/**
 * @file canary_token_detector.hpp
 * @brief System Prompt Canary Token Generation & Leak Detector Header
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <guardrail/guardrail.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <optional>
#include <span>

namespace guardrail::detectors {

/**
 * @brief Cryptographic Canary Token structure used to detect system prompt exfiltration.
 */
struct GUARDRAIL_API CanaryToken {
    std::string token_id;
    std::string canary_value; // e.g., "CANARY-7f8a9b2c3d4e"
};

/**
 * @brief Result payload returned after inspecting an LLM response string for canary leaks.
 */
struct GUARDRAIL_API CanaryDetectionResult {
    bool canary_leak_detected{false};
    std::string leaked_token_id;
    std::string leaked_canary_value;
    size_t leak_offset{0};
};

/**
 * @brief Thread-Safe Canary Token Generator & System Prompt Leak Detector.
 */
class GUARDRAIL_API CanaryTokenDetector {
public:
    CanaryTokenDetector() = default;
    ~CanaryTokenDetector() = default;

    // Non-copyable, non-movable (Registry state)
    CanaryTokenDetector(const CanaryTokenDetector&) = delete;
    CanaryTokenDetector& operator=(const CanaryTokenDetector&) = delete;
    CanaryTokenDetector(CanaryTokenDetector&&) = delete;
    CanaryTokenDetector& operator=(CanaryTokenDetector&&) = delete;

    /**
     * @brief Generates a cryptographically secure random canary token (e.g. "CANARY-a1b2c3d4e5f6").
     * @param prefix String prefix for the canary token (default: "CANARY-").
     * @return Generated CanaryToken object.
     */
    [[nodiscard]] static CanaryToken generate_canary(std::string_view prefix = "CANARY-");

    /**
     * @brief Registers a canary token in the active tracking registry.
     * @param token CanaryToken object to track.
     * @return Status::Success if registered.
     */
    Status register_canary(const CanaryToken& token);

    /**
     * @brief Injects a unique canary token instruction into a system prompt string.
     * @param system_prompt Original system prompt string view.
     * @param token Canary token object to embed.
     * @return Formatted system prompt containing the hidden canary token instruction.
     */
    [[nodiscard]] static std::string inject_canary(std::string_view system_prompt, const CanaryToken& token);

    /**
     * @brief Scans an LLM output response stream for active registered canary tokens.
     * @param model_response_text LLM response output text.
     * @return CanaryDetectionResult indicating whether a canary token leak occurred.
     */
    [[nodiscard]] CanaryDetectionResult inspect_response(std::string_view model_response_text) const;

    /**
     * @brief Unregisters a canary token from tracking memory.
     * @param token_id Unique identifier for canary token to remove.
     */
    void unregister_canary(std::string_view token_id) noexcept;

    /**
     * @brief Clears all registered canary tokens.
     */
    void clear_canaries() noexcept;

    [[nodiscard]] size_t active_canary_count() const noexcept;

private:
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, CanaryToken> m_active_canaries; // token_id -> CanaryToken
};

} // namespace guardrail::detectors