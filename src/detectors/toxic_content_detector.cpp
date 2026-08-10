/**
 * @file toxic_content_detector.cpp
 * @brief Sub-Millisecond PII & Restricted Content Detector Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <guardrail/detectors/toxic_content_detector.hpp>

#include <regex>
#include <algorithm>

namespace guardrail::detectors {

ToxicContentDetector::ToxicContentDetector() {
    load_default_pii_rules();
}

Status ToxicContentDetector::load_default_pii_rules() {
    // Secret Key & Private Key Headers
    m_matcher.add_pattern("PII_PRIVATE_KEY_HEADER", "-----begin private key-----");
    m_matcher.add_pattern("PII_RSA_KEY_HEADER", "-----begin rsa private key-----");
    m_matcher.add_pattern("PII_EC_KEY_HEADER", "-----begin ec private key-----");

    // API Key & Credentials Patterns
    m_matcher.add_pattern("PII_AWS_KEY_PREFIX", "akia"); // AWS Access Key ID prefix
    m_matcher.add_pattern("PII_API_KEY_LABEL", "api_key=");
    m_matcher.add_pattern("PII_SECRET_KEY_LABEL", "secret_key=");
    m_matcher.add_pattern("PII_PASSWORD_LABEL", "password=");
    m_matcher.add_pattern("PII_BEARER_TOKEN", "bearer eyj");

    // Build Aho-Corasick failure transition state machine
    m_matcher.build();
    m_rules_loaded = true;

    return Status::Success;
}

void ToxicContentDetector::add_keyword_rule(std::string_view category, std::string_view keyword) {
    m_matcher.add_pattern(category, keyword);
    m_matcher.build();
}

ToxicityResult ToxicContentDetector::inspect(std::string_view text) const {
    ToxicityResult result{};
    if (text.empty()) {
        return result;
    }

    std::string text_lower(text);
    std::transform(text_lower.begin(), text_lower.end(), text_lower.begin(), [](unsigned char c){ 
        return static_cast<char>(std::tolower(c)); 
    });

    // 1. Stage 1: High-Speed Aho-Corasick Keyword Search (<0.1ms)
    auto ac_matches = m_matcher.search(text_lower);
    for (const auto& match : ac_matches) {
        ToxicMatch tm{};
        tm.category = match.rule_id;
        tm.matched_text = match.matched_pattern;
        tm.start_offset = match.start_offset;
        tm.end_offset = match.end_offset;
        result.matches.push_back(std::move(tm));
    }

    // 2. Stage 2: Structural PII Regex Matching (Credit Cards & SSN)
    std::string text_str(text);

    // Credit Card Regex (Visa, MasterCard, Amex)
    std::regex cc_regex(R"(\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b)");
    std::smatch match;
    auto cc_begin = std::sregex_iterator(text_str.begin(), text_str.end(), cc_regex);
    auto cc_end = std::sregex_iterator();

    for (auto i = cc_begin; i != cc_end; ++i) {
        ToxicMatch tm{};
        tm.category = "PII_CREDIT_CARD";
        tm.matched_text = i->str();
        tm.start_offset = static_cast<size_t>(i->position());
        tm.end_offset = tm.start_offset + static_cast<size_t>(i->length());
        result.matches.push_back(std::move(tm));
    }

    // Social Security Number (SSN) Regex
    std::regex ssn_regex(R"(\b\d{3}-\d{2}-\d{4}\b)");
    auto ssn_begin = std::sregex_iterator(text_str.begin(), text_str.end(), ssn_regex);
    auto ssn_end = std::sregex_iterator();

    for (auto i = ssn_begin; i != ssn_end; ++i) {
        ToxicMatch tm{};
        tm.category = "PII_SSN";
        tm.matched_text = i->str();
        tm.start_offset = static_cast<size_t>(i->position());
        tm.end_offset = tm.start_offset + static_cast<size_t>(i->length());
        result.matches.push_back(std::move(tm));
    }

    // 3. Evaluate Severity Score
    if (!result.matches.empty()) {
        result.is_toxic_detected = true;
        result.severity_score = 0.50; // Base score for any match

        for (const auto& m : result.matches) {
            if (m.category.find("PRIVATE_KEY") != std::string::npos || 
                m.category == "PII_CREDIT_CARD" || 
                m.category == "PII_AWS_KEY_PREFIX") {
                result.severity_score = 1.00; // Critical PII/Key Leak
                break;
            }
        }
    }

    return result;
}

} // namespace guardrail::detectors