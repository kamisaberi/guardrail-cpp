/**
 * @file guardrail_policy.hpp
 * @brief Declarative Policy Engine & Action Enforcement Header for guardrail-cpp
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
#include <filesystem>
#include <optional>
#include <mutex>

namespace guardrail::policy {

/**
 * @brief Specific rule threshold and enforcement specification.
 */
struct GUARDRAIL_API PolicyRuleSpec {
    std::string rule_id;
    std::string category;             // e.g., "PROMPT_INJECTION", "CANARY_LEAK", "TOXIC_PII"
    double confidence_threshold{0.80}; // Min score (0.0 to 1.0) to trigger action
    ActionMode action_on_match{ActionMode::Block};
    std::string replacement_text{"[REDACTED_PROMPT_PAYLOAD]"};
};

/**
 * @brief Complete guardrail configuration policy object.
 */
struct GUARDRAIL_API PolicyConfig {
    std::string policy_name;
    double default_confidence_threshold{0.75};
    ActionMode default_action{ActionMode::Block};
    std::unordered_map<std::string, PolicyRuleSpec> rule_specs; // rule_id -> PolicyRuleSpec
};

/**
 * @brief Thread-Safe Guardrail Policy Engine & Enforcement Evaluator.
 */
class GUARDRAIL_API GuardrailPolicyEngine {
public:
    GuardrailPolicyEngine();
    ~GuardrailPolicyEngine() = default;

    // Non-copyable, non-movable
    GuardrailPolicyEngine(const GuardrailPolicyEngine&) = delete;
    GuardrailPolicyEngine& operator=(const GuardrailPolicyEngine&) = delete;
    GuardrailPolicyEngine(GuardrailPolicyEngine&&) = delete;
    GuardrailPolicyEngine& operator=(GuardrailPolicyEngine&&) = delete;

    /**
     * @brief Parses and registers a guardrail security policy from a YAML configuration file.
     * @param yaml_path Path to the YAML policy specification file.
     * @return Status::Success if parsed and registered.
     */
    Status load_from_yaml(const std::filesystem::path& yaml_path);

    /**
     * @brief Parses and registers a security policy from a JSON configuration string.
     * @param json_str JSON formatted policy string.
     * @return Status::Success if loaded.
     */
    Status load_from_json(std::string_view json_str);

    /**
     * @brief Programmatically registers a pre-configured PolicyConfig object.
     * @param config Policy specification to register.
     * @return Status::Success if registered.
     */
    Status register_policy(const PolicyConfig& config);

    /**
     * @brief Evaluates the enforcement action to take based on a matched rule ID and confidence score.
     * @param policy_name Target policy identifier.
     * @param rule_id Matched rule ID string.
     * @param confidence_score Calculated score from detector (0.0 to 1.0).
     * @return ActionMode (BLOCK, SANITIZE, LOG_ONLY, or ALLOW).
     */
    [[nodiscard]] ActionMode evaluate_action(
        std::string_view policy_name, 
        std::string_view rule_id, 
        double confidence_score
    ) const;

    /**
     * @brief Pre-loads and registers the default "strict_guardrails" security policy.
     */
    Status register_default_strict_policy();

    /**
     * @brief Retrieves a copy of a registered PolicyConfig object.
     * @param policy_name Target policy identifier.
     * @return Optional PolicyConfig struct if found.
     */
    [[nodiscard]] std::optional<PolicyConfig> get_policy(std::string_view policy_name) const;

private:
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, PolicyConfig> m_policies;
};

} // namespace guardrail::policy