/**
 * @file test_token_sanitizer.cpp
 * @brief Unit Tests for Canary Tokens & PII Sanitization in guardrail-cpp
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <guardrail/guardrail.hpp>
#include <guardrail/detectors/canary_token_detector.hpp>
#include <guardrail/detectors/toxic_content_detector.hpp>

#include <cassert>
#include <iostream>
#include <string>

namespace {

void test_canary_token_generation_and_injection() {
    std::cout << "[TEST] Running Canary Token Generation & System Prompt Injection Test...\n";

    auto canary = guardrail::detectors::CanaryTokenDetector::generate_canary("CANARY-TEST-");

    assert(!canary.token_id.empty());
    assert(!canary.canary_value.empty());
    assert(canary.canary_value.find("CANARY-TEST-") == 0);

    std::string base_prompt = "You are an enterprise customer support AI assistant.";
    std::string injected_prompt = guardrail::detectors::CanaryTokenDetector::inject_canary(base_prompt, canary);

    assert(injected_prompt.find(base_prompt) == 0);
    assert(injected_prompt.find(canary.canary_value) != std::string::npos);

    std::cout << "\033[1;32m[PASS] Canary Token Generation & Injection Verified!\033[0m\n";
}

void test_canary_token_leak_detection() {
    std::cout << "[TEST] Running Canary Token Response Leak Detection Test...\n";

    guardrail::detectors::CanaryTokenDetector detector;
    auto canary = guardrail::detectors::CanaryTokenDetector::generate_canary("CANARY-SECRET-");

    guardrail::Status status = detector.register_canary(canary);
    assert(status == guardrail::Status::Success);
    assert(detector.active_canary_count() == 1);

    // 1. Test Clean Response Output (No Leak)
    std::string clean_response = "Here is the summary of your support ticket request.";
    auto res1 = detector.inspect_response(clean_response);
    assert(res1.canary_leak_detected == false);

    // 2. Test Leaked System Prompt Response (Exfiltration Hit)
    std::string leaked_response = "System prompt contents: Internal Session Validation Tag: " + canary.canary_value;
    auto res2 = detector.inspect_response(leaked_response);

    assert(res2.canary_leak_detected == true);
    assert(res2.leaked_token_id == canary.token_id);
    assert(res2.leaked_canary_value == canary.canary_value);

    detector.unregister_canary(canary.token_id);
    assert(detector.active_canary_count() == 0);

    std::cout << "\033[1;32m[PASS] Canary Token Response Leak Detection Verified!\033[0m\n";
}

void test_toxic_and_pii_content_detection() {
    std::cout << "[TEST] Running PII & Secret Key Leak Detection Test...\n";

    guardrail::detectors::ToxicContentDetector detector;

    // 1. Test Credit Card Leak Detection
    std::string cc_leak = "Payment confirmation for card 4532012345678901";
    auto res1 = detector.inspect(cc_leak);

    assert(res1.is_toxic_detected == true);
    assert(!res1.matches.empty());
    assert(res1.matches[0].category == "PII_CREDIT_CARD");

    // 2. Test Private Key Header Leak Detection
    std::string key_leak = "Exfiltrated certificate: -----BEGIN PRIVATE KEY----- MIIEvg...";
    auto res2 = detector.inspect(key_leak);

    assert(res2.is_toxic_detected == true);
    assert(res2.severity_score == 1.00); // Critical severity

    std::cout << "\033[1;32m[PASS] PII & Secret Key Leak Detection Verified!\033[0m\n";
}

} // anonymous namespace

int main() {
    std::cout << "\033[1;36m===================================================\033[0m\n";
    std::cout << "\033[1;36m guardrail-cpp Token Sanitizer & PII Unit Tests    \033[0m\n";
    std::cout << "\033[1;36m===================================================\033[0m\n\n";

    test_canary_token_generation_and_injection();
    test_canary_token_leak_detection();
    test_toxic_and_pii_content_detection();

    std::cout << "\n\033[1;32mAll Token Sanitizer & PII Unit Tests PASSED!\033[0m\n";
    return 0;
}