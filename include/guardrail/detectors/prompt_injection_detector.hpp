/**
 * @file prompt_injection_detector.hpp
 * @brief Sub-Millisecond Indirect Prompt Injection & Jailbreak Detector Header
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <guardrail/guardrail.hpp>
#include <guardrail/sanitizer/unicode_normalizer.hpp>
#include <guardrail/sanitizer/aho_corasick_matcher.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <optional>
#include <span>

namespace guardrail::detectors {

/**
 * @brief Detailed result payload returned after inspecting a prompt for injection attacks.
 */
struct GUARDRAIL_API PromptInjectionResult {
    bool is_injection_detected{false};
    std::string matched_rule_id;
    std::string pattern_snippet;
    double confidence_score{0.0}; // 0.0 (Clean) to 1.0 (Definite Attack)
    size_t match_offset{0};
    bool unicode_obfuscation_used{false};
};

/**
 * @brief High-Throughput Sub-Millisecond Prompt Injection & System Override Detector.
 */
class GUARDRAIL_API PromptInjectionDetector {
public:
    PromptInjectionDetector();
    ~PromptInjectionDetector() = default;

    // Non-copyable, movable
    PromptInjectionDetector(const PromptInjectionDetector&) = delete;
    PromptInjectionDetector& operator=(const PromptInjectionDetector&) = delete;
    PromptInjectionDetector(PromptInjectionDetector&&) noexcept = default;
    PromptInjectionDetector& operator=(PromptInjectionDetector&&) noexcept = default;

    /**
     * @brief Pre-loads standard OWASP LLM Top 10 jailbreak signatures and system override rules.
     * @return Status::Success if rules loaded into Aho-Corasick matcher automaton.
     */
    Status load_default_jailbreak_rules();

    /**
     * @brief Adds a custom injection detection rule pattern.
     * @param rule_id Unique rule identifier (e.g., "SYSTEM_OVERRIDE_V1").
     * @param pattern Signature string to match (e.g., "ignore all previous instructions").
     */
    void add_custom_rule(std::string_view rule_id, std::string_view pattern);

    /**
     * @brief Performs 2-stage sub-millisecond inspection: Unicode normalization + Aho-Corasick O(N) scan.
     * @param raw_prompt Raw input prompt string view.
     * @return PromptInjectionResult containing threat status and matched rule details.
     */
    [[nodiscard]] PromptInjectionResult inspect(std::string_view raw_prompt) const;

    [[nodiscard]] size_t rule_count() const noexcept { return m_matcher.pattern_count(); }

private:
    sanitizer::UnicodeNormalizer m_normalizer;
    sanitizer::AhoCorasickMatcher m_matcher;
    bool m_rules_loaded{false};
};

} // namespace guardrail::detectors