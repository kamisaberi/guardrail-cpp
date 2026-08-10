/**
 * @file guardrail_policy.cpp
 * @brief Declarative Policy Engine & Action Enforcement Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <guardrail/policy/guardrail_policy.hpp>

#include <fstream>
#include <sstream>
#include <iostream>
#include <format>
#include <regex>
#include <algorithm>

namespace guardrail::policy {

GuardrailPolicyEngine::GuardrailPolicyEngine() {
    register_default_strict_policy();
}

Status GuardrailPolicyEngine::load_from_yaml(const std::filesystem::path& yaml_path) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!std::filesystem::exists(yaml_path)) {
        std::cerr << std::format("[GUARDRAIL-POLICY-ERROR] YAML policy file not found: {}\n", yaml_path.string());
        return Status::ErrPolicyViolation;
    }

    std::ifstream file(yaml_path);
    if (!file.is_open()) {
        return Status::ErrPolicyViolation;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    PolicyConfig config{};
    
    // Light-weight regex extraction for YAML policy specifications
    std::regex name_regex(R"(policy_name\s*:\s*\"?([a-zA-Z0-9_\-]+)\"?)");
    std::regex threshold_regex(R"(default_confidence_threshold\s*:\s*([0-9\.]+))");
    std::regex action_regex(R"(default_action\s*:\s*\"?([A-Z_]+)\"?)");

    std::smatch match;
    if (std::regex_search(content, match, name_regex)) {
        config.policy_name = match[1].str();
    } else {
        config.policy_name = yaml_path.stem().string();
    }

    if (std::regex_search(content, match, threshold_regex)) {
        config.default_confidence_threshold = std::stod(match[1].str());
    }

    if (std::regex_search(content, match, action_regex)) {
        std::string act = match[1].str();
        if (act == "BLOCK") config.default_action = ActionMode::Block;
        else if (act == "SANITIZE") config.default_action = ActionMode::Sanitize;
        else if (act == "LOG_ONLY") config.default_action = ActionMode::LogOnly;
        else config.default_action = ActionMode::Allow;
    }

    m_policies.insert_or_assign(config.policy_name, std::move(config));
    return Status::Success;
}

Status GuardrailPolicyEngine::load_from_json(std::string_view json_str) {
    PolicyConfig config{};
    config.policy_name = "json_imported_policy";
    config.default_confidence_threshold = 0.75;
    config.default_action = ActionMode::Block;

    return register_policy(config);
}

Status GuardrailPolicyEngine::register_policy(const PolicyConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_policies.insert_or_assign(config.policy_name, config);
    return Status::Success;
}

ActionMode GuardrailPolicyEngine::evaluate_action(
    std::string_view policy_name, 
    std::string_view rule_id, 
    double confidence_score
) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_policies.find(std::string(policy_name));
    if (it == m_policies.end()) {
        return ActionMode::Block; // Unknown policy -> Block by default
    }

    const auto& config = it->second;

    // Check for rule-specific specification
    auto rule_it = config.rule_specs.find(std::string(rule_id));
    if (rule_it != config.rule_specs.end()) {
        const auto& spec = rule_it->second;
        if (confidence_score >= spec.confidence_threshold) {
            return spec.action_on_match;
        } else {
            return ActionMode::Allow; // Score below threshold -> Pass
        }
    }

    // Fallback to default policy threshold and action
    if (confidence_score >= config.default_confidence_threshold) {
        return config.default_action;
    }

    return ActionMode::Allow;
}

Status GuardrailPolicyEngine::register_default_strict_policy() {
    PolicyConfig config{};
    config.policy_name = "strict_guardrails";
    config.default_confidence_threshold = 0.75;
    config.default_action = ActionMode::Block;

    // Pre-configure rule specs for common prompt injection rules
    std::vector<std::string> critical_rules = {
        "SYSTEM_OVERRIDE_01", "SYSTEM_OVERRIDE_02", "SYSTEM_OVERRIDE_03",
        "JAILBREAK_DAN_01", "JAILBREAK_DAN_02", "DELIMITER_INJECTION_01"
    };

    for (const auto& r_id : critical_rules) {
        PolicyRuleSpec spec{};
        spec.rule_id = r_id;
        spec.category = "PROMPT_INJECTION";
        spec.confidence_threshold = 0.70;
        spec.action_on_match = ActionMode::Block;
        config.rule_specs.insert_or_assign(r_id, std::move(spec));
    }

    return register_policy(config);
}

std::optional<PolicyConfig> GuardrailPolicyEngine::get_policy(std::string_view policy_name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_policies.find(std::string(policy_name));
    if (it != m_policies.end()) {
        return it->second;
    }
    return std::nullopt;
}

} // namespace guardrail::policy