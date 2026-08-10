/**
 * @file unicode_normalizer.hpp
 * @brief Sub-Millisecond Unicode Homoglyph & Zero-Width Space Normalizer Header
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <guardrail/guardrail.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <optional>
#include <span>

namespace guardrail::sanitizer {

/**
 * @brief Result payload returned after normalizing a string string.
 */
struct GUARDRAIL_API NormalizationResult {
    std::string normalized_text;
    size_t zero_width_chars_removed{0};
    size_t homoglyphs_replaced{0};
    bool obfuscation_detected{false};
};

/**
 * @brief Zero-copy $O(N)$ UTF-8 Unicode Homoglyph & Invisible Character Normalizer.
 */
class GUARDRAIL_API UnicodeNormalizer {
public:
    UnicodeNormalizer();
    ~UnicodeNormalizer() = default;

    // Default copy/move
    UnicodeNormalizer(const UnicodeNormalizer&) = default;
    UnicodeNormalizer& operator=(const UnicodeNormalizer&) = default;
    UnicodeNormalizer(UnicodeNormalizer&&) noexcept = default;
    UnicodeNormalizer& operator=(UnicodeNormalizer&&) noexcept = default;

    /**
     * @brief Performs single-pass normalization: strips zero-width spaces and resolves homoglyphs to ASCII.
     * @param input_text Raw input string view (UTF-8 encoded).
     * @param lowercase_output If true, converts ASCII characters to lowercase for uniform matching.
     * @return NormalizationResult containing cleaned text and obfuscation metrics.
     */
    [[nodiscard]] NormalizationResult normalize(std::string_view input_text, bool lowercase_output = true) const;

    /**
     * @brief Fast query testing if a string contains zero-width spaces or homoglyph characters.
     * @param input_text Input UTF-8 string_view.
     * @return True if obfuscation patterns are detected.
     */
    [[nodiscard]] bool contains_obfuscation(std::string_view input_text) const noexcept;

    /**
     * @brief Resolves a single multi-byte UTF-8 codepoint to its standard ASCII equivalent if a homoglyph exists.
     * @param utf8_codepoint 32-bit representation of UTF-8 codepoint.
     * @return ASCII character if mapped; std::nullopt otherwise.
     */
    [[nodiscard]] static std::optional<char> map_homoglyph(uint32_t utf8_codepoint) noexcept;

    /**
     * @brief Tests if a 32-bit UTF-8 codepoint represents an invisible zero-width character.
     * @param utf8_codepoint 32-bit representation of UTF-8 codepoint.
     * @return True if character is a zero-width space/joiner/BOM.
     */
    [[nodiscard]] static bool is_zero_width_char(uint32_t utf8_codepoint) noexcept;

private:
    static const std::unordered_map<uint32_t, char> s_homoglyph_map;
};

} // namespace guardrail::sanitizer