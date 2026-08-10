/**
 * @file aho_corasick_matcher.cpp
 * @brief Sub-Millisecond O(N) Aho-Corasick Multi-Pattern Matcher Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <guardrail/sanitizer/aho_corasick_matcher.hpp>

#include <queue>
#include <algorithm>
#include <iostream>

namespace guardrail::sanitizer {

AhoCorasickMatcher::AhoCorasickMatcher() {
    // Root node at index 0
    m_trie.emplace_back();
}

void AhoCorasickMatcher::clear() noexcept {
    m_trie.clear();
    m_trie.emplace_back(); // Re-initialize root node
    m_pattern_count = 0;
    m_is_built = false;
}

void AhoCorasickMatcher::add_pattern(std::string_view rule_id, std::string_view pattern) {
    if (pattern.empty()) return;

    size_t curr_state = 0;
    for (char ch : pattern) {
        auto it = m_trie[curr_state].children.find(ch);
        if (it == m_trie[curr_state].children.end()) {
            size_t next_state = m_trie.size();
            m_trie[curr_state].children[ch] = next_state;
            m_trie.emplace_back(); // Add new Trie node
            curr_state = next_state;
        } else {
            curr_state = it->second;
        }
    }

    // Add match rule to output list of leaf node
    m_trie[curr_state].output_matches.emplace_back(std::string(rule_id), std::string(pattern));
    m_pattern_count++;
    m_is_built = false;
}

void AhoCorasickMatcher::build() {
    if (m_is_built) return;

    std::queue<size_t> q;

    // 1. Set failure links for depth-1 nodes to root (index 0)
    for (auto& [ch, child_state] : m_trie[0].children) {
        m_trie[child_state].fail_state = 0;
        q.push(child_state);
    }

    // 2. BFS to compute failure transitions and merge output lists
    while (!q.empty()) {
        size_t curr_state = q.front();
        q.pop();

        for (auto& [ch, child_state] : m_trie[curr_state].children) {
            size_t fallback = m_trie[curr_state].fail_state;

            // Follow failure links until matching child transition or root
            while (fallback != 0 && m_trie[fallback].children.find(ch) == m_trie[fallback].children.end()) {
                fallback = m_trie[fallback].fail_state;
            }

            auto it = m_trie[fallback].children.find(ch);
            if (it != m_trie[fallback].children.end() && it->second != child_state) {
                m_trie[child_state].fail_state = it->second;
            } else {
                m_trie[child_state].fail_state = 0;
            }

            // Merge output matches from failure state node
            size_t fail_node = m_trie[child_state].fail_state;
            if (fail_node != 0 && !m_trie[fail_node].output_matches.empty()) {
                m_trie[child_state].output_matches.insert(
                    m_trie[child_state].output_matches.end(),
                    m_trie[fail_node].output_matches.begin(),
                    m_trie[fail_node].output_matches.end()
                );
            }

            q.push(child_state);
        }
    }

    m_is_built = true;
}

std::vector<PatternMatch> AhoCorasickMatcher::search(std::string_view input_text) const {
    std::vector<PatternMatch> matches;
    if (input_text.empty() || m_trie.empty()) return matches;

    // Const cast workaround if build() wasn't called explicitly
    if (!m_is_built) {
        const_cast<AhoCorasickMatcher*>(this)->build();
    }

    size_t curr_state = 0;
    for (size_t i = 0; i < input_text.size(); ++i) {
        char ch = input_text[i];

        // Transition through failure links if child transition is missing
        while (curr_state != 0 && m_trie[curr_state].children.find(ch) == m_trie[curr_state].children.end()) {
            curr_state = m_trie[curr_state].fail_state;
        }

        auto it = m_trie[curr_state].children.find(ch);
        if (it != m_trie[curr_state].children.end()) {
            curr_state = it->second;
        }

        // Collect matches if output list is non-empty
        if (!m_trie[curr_state].output_matches.empty()) {
            for (const auto& [rule_id, pattern] : m_trie[curr_state].output_matches) {
                PatternMatch match{};
                match.rule_id = rule_id;
                match.matched_pattern = pattern;
                match.end_offset = i + 1;
                match.start_offset = (i + 1 >= pattern.size()) ? (i + 1 - pattern.size()) : 0;
                matches.push_back(std::move(match));
            }
        }
    }

    return matches;
}

bool AhoCorasickMatcher::contains_match(std::string_view input_text) const noexcept {
    if (input_text.empty() || m_trie.empty()) return false;

    if (!m_is_built) {
        const_cast<AhoCorasickMatcher*>(this)->build();
    }

    size_t curr_state = 0;
    for (char ch : input_text) {
        while (curr_state != 0 && m_trie[curr_state].children.find(ch) == m_trie[curr_state].children.end()) {
            curr_state = m_trie[curr_state].fail_state;
        }

        auto it = m_trie[curr_state].children.find(ch);
        if (it != m_trie[curr_state].children.end()) {
            curr_state = it->second;
        }

        if (!m_trie[curr_state].output_matches.empty()) {
            return true; // Early exit on first match
        }
    }

    return false;
}

} // namespace guardrail::sanitizer