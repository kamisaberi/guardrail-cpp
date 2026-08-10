/**
 * @file unicode_normalizer.cpp
 * @brief Sub-Millisecond Unicode Homoglyph & Zero-Width Space Normalizer Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <guardrail/sanitizer/unicode_normalizer.hpp>

#include <cctype>
#include <algorithm>

namespace guardrail::sanitizer {

// -----------------------------------------------------------------------------
// Homoglyph Mapping Table (Cyrillic & Greek -> Standard ASCII)
// -----------------------------------------------------------------------------
const std::unordered_map<uint32_t, char> UnicodeNormalizer::s_homoglyph_map = {
    // Cyrillic Small Letters -> ASCII
    {0x0430, 'a'}, // Cyrillic 'а' -> 'a'
    {0x0435, 'e'}, // Cyrillic 'е' -> 'e'
    {0x043E, 'o'}, // Cyrillic 'о' -> 'o'
    {0x0440, 'p'}, // Cyrillic 'р' -> 'p'
    {0x0441, 'c'}, // Cyrillic 'с' -> 'c'
    {0x0443, 'y'}, // Cyrillic 'у' -> 'y'
    {0x0445, 'x'}, // Cyrillic 'х' -> 'x'
    {0x0456, 'i'}, // Cyrillic 'і' -> 'i'
    {0x0455, 's'}, // Cyrillic 'ѕ' -> 's'

    // Cyrillic Capital Letters -> ASCII
    {0x0410, 'a'}, // Cyrillic 'А' -> 'a'
    {0x0415, 'e'}, // Cyrillic 'Е' -> 'e'
    {0x041E, 'o'}, // Cyrillic 'О' -> 'o'
    {0x0420, 'p'}, // Cyrillic 'Р' -> 'p'
    {0x0421, 'c'}, // Cyrillic 'С' -> 'c'
    {0x0425, 'x'}, // Cyrillic 'Х' -> 'x'
    {0x0406, 'i'}, // Cyrillic 'І' -> 'i'
    {0x0405, 's'}, // Cyrillic 'Ѕ' -> 's'
    {0x0412, 'b'}, // Cyrillic 'В' -> 'b'
    {0x041D, 'h'}, // Cyrillic 'Н' -> 'h'
    {0x041C, 'm'}, // Cyrillic 'М' -> 'm'
    {0x0422, 't'}, // Cyrillic 'Т' -> 't'
    {0x041A, 'k'}, // Cyrillic 'К' -> 'k'

    // Greek Small Letters -> ASCII
    {0x03B1, 'a'}, // Greek 'α' -> 'a'
    {0x03BF, 'o'}, // Greek 'ο' -> 'o'
    {0x03C5, 'y'}, // Greek 'υ' -> 'y'
    {0x03C1, 'p'}, // Greek 'ρ' -> 'p'
    {0x03BA, 'k'}, // Greek 'κ' -> 'k'
    {0x03BD, 'v'}, // Greek 'ν' -> 'v'
    {0x03C7, 'x'}  // Greek 'χ' -> 'x'
};

UnicodeNormalizer::UnicodeNormalizer() = default;

bool UnicodeNormalizer::is_zero_width_char(uint32_t utf8_codepoint) noexcept {
    switch (utf8_codepoint) {
        case 0x200B: // Zero-Width Space
        case 0x200C: // Zero-Width Non-Joiner
        case 0x200D: // Zero-Width Joiner
        case 0x2060: // Word Joiner
        case 0xFEFF: // Zero-Width No-Break Space (BOM)
        case 0x00AD: // Soft Hyphen
            return true;
        default:
            return false;
    }
}

std::optional<char> UnicodeNormalizer::map_homoglyph(uint32_t utf8_codepoint) noexcept {
    auto it = s_homoglyph_map.find(utf8_codepoint);
    if (it != s_homoglyph_map.end()) {
        return it->second;
    }
    return std::nullopt;
}

namespace {

// Helper: Decodes one multi-byte UTF-8 codepoint and returns advanced cursor length
uint32_t decode_utf8_codepoint(std::string_view str, size_t index, size_t& out_consumed_bytes) noexcept {
    uint8_t first = static_cast<uint8_t>(str[index]);

    if (first < 0x80) { // 1-byte ASCII
        out_consumed_bytes = 1;
        return first;
    }

    if ((first & 0xE0) == 0xC0 && index + 1 < str.size()) { // 2-byte sequence
        out_consumed_bytes = 2;
        return ((first & 0x1F) << 6) | (static_cast<uint8_t>(str[index + 1]) & 0x3F);
    }

    if ((first & 0xF0) == 0xE0 && index + 2 < str.size()) { // 3-byte sequence
        out_consumed_bytes = 3;
        return ((first & 0x0F) << 12) |
               ((static_cast<uint8_t>(str[index + 1]) & 0x3F) << 6) |
               (static_cast<uint8_t>(str[index + 2]) & 0x3F);
    }

    if ((first & 0xF8) == 0xF0 && index + 3 < str.size()) { // 4-byte sequence
        out_consumed_bytes = 4;
        return ((first & 0x07) << 18) |
               ((static_cast<uint8_t>(str[index + 1]) & 0x3F) << 12) |
               ((static_cast<uint8_t>(str[index + 2]) & 0x3F) << 6) |
               (static_cast<uint8_t>(str[index + 3]) & 0x3F);
    }

    out_consumed_bytes = 1;
    return first; // Invalid UTF-8 byte fallback
}

} // anonymous namespace

NormalizationResult UnicodeNormalizer::normalize(std::string_view input_text, bool lowercase_output) const {
    NormalizationResult result{};
    result.normalized_text.reserve(input_text.size());

    size_t i = 0;
    while (i < input_text.size()) {
        size_t consumed_bytes = 1;
        uint32_t codepoint = decode_utf8_codepoint(input_text, i, consumed_bytes);

        // 1. Check & Strip Zero-Width Invisible Characters
        if (is_zero_width_char(codepoint)) {
            result.zero_width_chars_removed++;
            result.obfuscation_detected = true;
            i += consumed_bytes;
            continue;
        }

        // 2. Check & Map Homoglyph Characters to ASCII
        auto homoglyph_ascii = map_homoglyph(codepoint);
        if (homoglyph_ascii.has_value()) {
            char ch = *homoglyph_ascii;
            if (lowercase_output) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            result.normalized_text.push_back(ch);
            result.homoglyphs_replaced++;
            result.obfuscation_detected = true;
            i += consumed_bytes;
            continue;
        }

        // 3. Regular ASCII / Multi-byte Characters
        if (consumed_bytes == 1) {
            char ch = input_text[i];
            if (lowercase_output) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            result.normalized_text.push_back(ch);
        } else {
            // Append non-homoglyph multi-byte UTF-8 sequence directly
            result.normalized_text.append(input_text.substr(i, consumed_bytes));
        }

        i += consumed_bytes;
    }

    return result;
}

bool UnicodeNormalizer::contains_obfuscation(std::string_view input_text) const noexcept {
    size_t i = 0;
    while (i < input_text.size()) {
        size_t consumed_bytes = 1;
        uint32_t codepoint = decode_utf8_codepoint(input_text, i, consumed_bytes);

        if (is_zero_width_char(codepoint) || map_homoglyph(codepoint).has_value()) {
            return true;
        }
        i += consumed_bytes;
    }
    return false;
}

} // namespace guardrail::sanitizer