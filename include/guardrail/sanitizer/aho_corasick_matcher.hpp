/**
 * @file aho_corasick_matcher.hpp
 * @brief Sub-Millisecond O(N) Aho-Corasick Multi-Pattern Matcher Header
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <guardrail/guardrail.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <queue>
#include <memory>
#include <span>

namespace guardrail::sanitizer {

/**
 * @brief Structure representing a pattern match hit inside a prompt text.
 */
struct GUARDRAIL_API PatternMatch {
    std::string rule_id;
    std::string matched_pattern;
    size_t start_offset{0};
    size_t end_offset{0};
};

/**
 * @brief Node representation inside the Aho-Corasick Automaton Trie.
 */
struct GUARDRAIL_API TrieNode {
    std::unordered_map<char, size_t> children;
    size_t fail_state{0};
    std::vector<std::pair<std::string, std::string>> output_matches; // <rule_id, pattern>
};

/**
 * @brief High-Performance O(N) Aho-Corasick Multi-Pattern Matching Engine.
 */
class GUARDRAIL_API AhoCorasickMatcher {
public:
    AhoCorasickMatcher();
    ~AhoCorasickMatcher() = default;

    // Movable, non-copyable (DFA State Machine)
    AhoCorasickMatcher(const AhoCorasickMatcher&) = delete;
    AhoCorasickMatcher& operator=(const AhoCorasickMatcher&) = delete;
    AhoCorasickMatcher(AhoCorasickMatcher&&) noexcept = default;
    AhoCorasickMatcher& operator=(AhoCorasickMatcher&&) noexcept = default;

    /**
     * @brief Inserts a new pattern and rule ID into the Trie.
     * @param rule_id Unique identifier for the rule (e.g., "JAILBREAK_DAN_V1").
     * @param pattern Target keyword/signature string to match.
     */
    void add_pattern(std::string_view rule_id, std::string_view pattern);

    /**
     * @brief Constructs failure transitions and output links via Breadth-First Search (BFS).
     * Must be called after all patterns have been added and before searching.
     */
    void build();

    /**
     * @brief Scans an input text string in linear O(N) time and returns all matched patterns.
     * @param input_text Prompt text string view to scan.
     * @return Vector of PatternMatch structures.
     */
    [[nodiscard]] std::vector<PatternMatch> search(std::string_view input_text) const;

    /**
     * @brief Fast query returning true immediately upon the first pattern match hit.
     * @param input_text Prompt text string view.
     * @return True if any pattern matched; False otherwise.
     */
    [[nodiscard]] bool contains_match(std::string_view input_text) const noexcept;

    /**
     * @brief Resets and clears all states in the Trie.
     */
    void clear() noexcept;

    [[nodiscard]] size_t pattern_count() const noexcept { return m_pattern_count; }
    [[nodiscard]] bool is_built() const noexcept { return m_is_built; }

private:
    std::vector<TrieNode> m_trie;
    size_t m_pattern_count{0};
    bool m_is_built{false};
};

} // namespace guardrail::sanitizer