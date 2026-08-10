/**
 * @file prompt_injection_detector.cpp
 * @brief Sub-Millisecond Indirect Prompt Injection & Jailbreak Detector Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <guardrail/detectors/prompt_injection_detector.hpp>

#include <algorithm>
#include <chrono>

namespace guardrail::detectors {

PromptInjectionDetector::PromptInjectionDetector() {
    load_default_jailbreak_rules();
}

Status PromptInjectionDetector::load_default_jailbreak_rules() {
    // OWASP LLM Top 10 - System Prompt Override Signatures
    m_matcher.add_pattern("SYSTEM_OVERRIDE_01", "ignore previous instructions");
    m_matcher.add_pattern("SYSTEM_OVERRIDE_02", "ignore all previous instructions");
    m_matcher.add_pattern("SYSTEM_OVERRIDE_03", "ignore all instructions");
    m_matcher.add_pattern("SYSTEM_OVERRIDE_04", "disregard all previous directions");
    m_matcher.add_pattern("SYSTEM_OVERRIDE_05", "disregard prior directives");
    m_matcher.add_pattern("SYSTEM_OVERRIDE_06", "forget previous instructions");
    m_matcher.add_pattern("SYSTEM_OVERRIDE_07", "system override");
    m_matcher.add_pattern("SYSTEM_OVERRIDE_08", "new system prompt");
    m_matcher.add_pattern("SYSTEM_OVERRIDE_09", "override system directive");

    // Role-Play & DAN Jailbreak Signatures
    m_matcher.add_pattern("JAILBREAK_DAN_01", "you are now dan");
    m_matcher.add_pattern("JAILBREAK_DAN_02", "do anything now");
    m_matcher.add_pattern("JAILBREAK_DAN_03", "jailbreak mode");
    m_matcher.add_pattern("JAILBREAK_ROLEPLAY_01", "pretend to be an unfiltered ai");
    m_matcher.add_pattern("JAILBREAK_ROLEPLAY_02", "bypass your safety filters");
    m_matcher.add_pattern("JAILBREAK_ROLEPLAY_03", "developer mode enabled");

    // Delimiter & Format Injection Signatures
    m_matcher.add_pattern("DELIMITER_INJECTION_01", "```system");
    m_matcher.add_pattern("DELIMITER_INJECTION_02", "[system prompt]");
    m_matcher.add_pattern("DELIMITER_INJECTION_03", "<|im_start|>system");
    m_matcher.add_pattern("DELIMITER_INJECTION_04", "<|im_end|>");
    m_matcher.add_pattern("DELIMITER_INJECTION_05", "[[system]]");

    // Build Aho-Corasick BFS failure state automaton
    m_matcher.build();
    m_rules_loaded = true;

    return Status::Success;
}

void PromptInjectionDetector::add_custom_rule(std::string_view rule_id, std::string_view pattern) {
    m_matcher.add_pattern(rule_id, pattern);
    m_matcher.build();
}

PromptInjectionResult PromptInjectionDetector::inspect(std::string_view raw_prompt) const {
    PromptInjectionResult result{};
    if (raw_prompt.empty()) {
        return result;
    }

    // 1. Stage 1: Normalize Unicode Homoglyphs & Strip Zero-Width Spaces (<0.1ms)
    auto norm_result = m_normalizer.normalize(raw_prompt, true);
    result.unicode_obfuscation_used = norm_result.obfuscation_detected;

    // 2. Stage 2: Execute $O(N)$ Aho-Corasick Multi-Pattern Scan (<0.2ms)
    auto matches = m_matcher.search(norm_result.normalized_text);

    // 3. Evaluate Match Results & Calculate Confidence Score
    if (!matches.empty()) {
        result.is_injection_detected = true;
        result.matched_rule_id = matches[0].rule_id;
        result.pattern_snippet = matches[0].matched_pattern;
        result.match_offset = matches[0].start_offset;

        // Higher confidence score if obfuscation was explicitly used to bypass filters
        if (norm_result.obfuscation_detected) {
            result.confidence_score = 0.99; // Obfuscated Injection Attack
        } else {
            result.confidence_score = 0.95; // Direct Injection Attack
        }
    } else if (norm_result.obfuscation_detected && norm_result.zero_width_chars_removed > 3) {
        // Suspicious Unicode obfuscation present even if no known keyword matched
        result.confidence_score = 0.40;
    }

    return result;
}

} // namespace guardrail::detectors