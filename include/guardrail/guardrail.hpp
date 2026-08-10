/**
 * @file guardrail.hpp
 * @brief Master Header & Global Definitions for guardrail-cpp Engine
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <exception>
#include <span>
#include <format>
#include <chrono>

// -----------------------------------------------------------------------------
// Versioning & Metadata
// -----------------------------------------------------------------------------
#define GUARDRAIL_VERSION_MAJOR 0
#define GUARDRAIL_VERSION_MINOR 1
#define GUARDRAIL_VERSION_PATCH 0
#define GUARDRAIL_VERSION_STRING "0.1.0"

// -----------------------------------------------------------------------------
// Symbol Visibility Macros (Shared Library Exports)
// -----------------------------------------------------------------------------
#if defined(_WIN32) || defined(__CYGWIN__)
    #if defined(GUARDRAIL_BUILD_INTERNAL)
        #define GUARDRAIL_API __declspec(dllexport)
    #else
        #define GUARDRAIL_API __declspec(dllimport)
    #endif
#else
    #if __GNUC__ >= 4 || defined(__clang__)
        #define GUARDRAIL_API __attribute__((visibility("default")))
    #else
        #define GUARDRAIL_API
    #endif
#endif

namespace guardrail {

/**
 * @brief System-wide status codes for guardrail-cpp operations.
 */
enum class Status : uint32_t {
    Success                          = 0,
    ErrPromptInjectionDetected       = 1,
    ErrUnicodeObfuscationDetected    = 2,
    ErrCanaryTokenLeaked             = 3,
    ErrToxicContentDetected          = 4,
    ErrPolicyViolation               = 5,
    ErrCUDAInspectionFailed          = 6,
    ErrInvalidPatternDictionary      = 7,
    ErrUnknown                       = 999
};

/**
 * @brief Action mode triggered when a security threat is detected.
 */
enum class ActionMode : uint32_t {
    Allow    = 0, // Permit prompt unconditionally
    Block    = 1, // Reject prompt and return security exception
    Sanitize = 2, // Strip offending tokens and pass cleaned string
    LogOnly  = 3  // Permit prompt but log security alert
};

/**
 * @brief Converts a Status code into a human-readable string_view.
 */
[[nodiscard]] constexpr std::string_view status_to_string(Status status) noexcept {
    switch (status) {
        case Status::Success:                       return "Success: Prompt Clean";
        case Status::ErrPromptInjectionDetected:    return "Security Alert: Indirect Prompt Injection Detected";
        case Status::ErrUnicodeObfuscationDetected: return "Security Alert: Unicode Homoglyph Obfuscation Detected";
        case Status::ErrCanaryTokenLeaked:          return "Security Alert: System Prompt Canary Token Leak Detected";
        case Status::ErrToxicContentDetected:       return "Security Alert: Restricted Content Pattern Matched";
        case Status::ErrPolicyViolation:            return "Error: Guardrail Security Policy Violated";
        case Status::ErrCUDAInspectionFailed:       return "Error: GPU Batch CUDA Pattern Matcher Failed";
        case Status::ErrInvalidPatternDictionary:   return "Error: Malformed Aho-Corasick Pattern Dictionary";
        default:                                    return "Error: Unknown Guardrail Failure";
    }
}

/**
 * @brief Base exception class for guardrail-cpp runtime failures.
 */
class GUARDRAIL_API GuardrailException : public std::exception {
public:
    explicit GuardrailException(Status status, std::string_view message)
        : m_status(status), m_message(std::format("[GUARDRAIL-{}] {}", static_cast<uint32_t>(status), message)) {}

    [[nodiscard]] const char* what() const noexcept override {
        return m_message.c_str();
    }

    [[nodiscard]] Status status() const noexcept {
        return m_status;
    }

private:
    Status m_status;
    std::string m_message;
};

/**
 * @brief Inspection result payload returned after evaluating a prompt string.
 */
struct GUARDRAIL_API InspectionResult {
    bool is_threat_detected{false};
    ActionMode action_taken{ActionMode::Allow};
    std::string threat_category{"None"};
    std::string matched_rule_id;
    double latency_ms{0.0};              // Sub-millisecond execution duration
    std::string sanitized_prompt;       // Cleaned string if action_taken == Sanitize
};

/**
 * @brief Struct representing version details.
 */
struct Version {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;

    [[nodiscard]] std::string to_string() const {
        return std::format("{}.{}.{}", major, minor, patch);
    }
};

/**
 * @brief Returns the runtime version of the guardrail-cpp core library.
 */
[[nodiscard]] inline Version get_version() noexcept {
    return Version{GUARDRAIL_VERSION_MAJOR, GUARDRAIL_VERSION_MINOR, GUARDRAIL_VERSION_PATCH};
}

// -----------------------------------------------------------------------------
// Sub-namespace Forward Declarations
// -----------------------------------------------------------------------------
namespace sanitizer {}
namespace detectors {}
namespace cuda {}
namespace policy {}

} // namespace guardrail