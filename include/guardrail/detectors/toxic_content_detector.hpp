/**
 * @file toxic_content_detector.hpp
 * @brief Sub-Millisecond PII & Restricted Content Detector Header
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <guardrail/guardrail.hpp>
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
 * @brief Represents a individual PII or restricted content match.
 */
struct GUARDRAIL_API ToxicMatch {
    std::string category;      // e.g., "PII_CREDIT_CARD", "API_KEY_LEAK", "RESTRICTED_KEYWORD"
    std::string matched_text;  // Snippet of matched content
    size_t start_offset{0};
    size_t end_offset{0};
};

/**
 * @brief Detailed result payload returned after inspecting text for toxic/PII content.
 */
struct GUARDRAIL_API ToxicityResult {
    bool is_toxic_detected{false};
    std::vector<ToxicMatch> matches;
    double severity_score{0.0}; // 0.0 (Clean) to 1.0 (Critical Leak)
};

/**
 * @brief High-Speed PII & Restricted Content Classifier.
 */
class GUARDRAIL_API ToxicContentDetector {
public:
    ToxicContentDetector();
    ~ToxicContentDetector() = default;

    // Non-copyable, movable
    ToxicContentDetector(const ToxicContentDetector&) = delete;
    ToxicContentDetector& operator=(const ToxicContentDetector&) = delete;
    ToxicContentDetector(ToxicContentDetector&&) noexcept = default;
    ToxicContentDetector& operator=(ToxicContentDetector&&) noexcept = default;

    /**
     * @brief Pre-loads standard PII patterns (Credit Cards, SSNs, API keys) and restricted keywords.
     * @return Status::Success if patterns are compiled into the matcher.
     */
    Status load_default_pii_rules();

    /**
     * @brief Adds a custom restricted keyword rule.
     * @param category Threat classification category (e.g., "PII_EMAIL").
     * @param keyword Pattern string to match.
     */
    void add_keyword_rule(std::string_view category, std::string_view keyword);

    /**
     * @brief Performs sub-millisecond text inspection for PII and toxic content patterns.
     * @param text Input prompt or response string view.
     * @return ToxicityResult containing match details and severity score.
     */
    [[nodiscard]] ToxicityResult inspect(std::string_view text) const;

private:
    sanitizer::AhoCorasickMatcher m_matcher;
    bool m_rules_loaded{false};
};

} // namespace guardrail::detectors