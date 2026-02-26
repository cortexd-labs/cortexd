use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    #[default]
    Deny,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyRule {
    pub id: String,
    pub description: Option<String>,
    pub effect: Effect,
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Policy {
    pub default_action: Effect,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            default_action: Effect::Deny,
            rules: Vec::new(),
        }
    }
}

impl Policy {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read policy file: {}", e))?;
        toml::from_str(&content).map_err(|e| format!("Failed to parse policy TOML: {}", e))
    }

    /// Check if a tool is allowed by the policy
    pub fn is_allowed(&self, tool_name: &str) -> bool {
        let mut matched_allow = false;

        for rule in &self.rules {
            for pattern in &rule.tools {
                if wildcard_match(pattern, tool_name) {
                    if rule.effect == Effect::Deny {
                        // Deny-wins: Short-circuit immediately on ANY explicit deny
                        return false;
                    } else if rule.effect == Effect::Allow {
                        matched_allow = true;
                    }
                }
            }
        }

        if matched_allow {
            true
        } else {
            self.default_action == Effect::Allow
        }
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    glob::Pattern::new(pattern)
        .map(|p| p.matches(value))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_match() {
        assert!(wildcard_match("system.*", "system.cpu"));
        assert!(wildcard_match("service.list", "service.list"));
        assert!(!wildcard_match("system.*", "service.list"));
    }

    #[test]
    fn test_policy_evaluation() {
        let policy = Policy {
            default_action: Effect::Deny,
            rules: vec![
                PolicyRule {
                    id: "allow-system".into(),
                    description: None,
                    effect: Effect::Allow,
                    tools: vec!["system.*".into()],
                },
                PolicyRule {
                    id: "deny-cpu".into(),
                    description: None,
                    effect: Effect::Deny,
                    tools: vec!["system.cpu".into()],
                },
            ],
        };

        assert!(policy.is_allowed("system.memory")); // Allowed by system.*
        assert!(!policy.is_allowed("system.cpu")); // Denied by system.cpu override
        assert!(!policy.is_allowed("service.list")); // Denied by default
    }

    #[test]
    fn test_deny_wins_over_allow_regardless_of_order() {
        // Even if the allow rule comes AFTER the deny rule, the deny should permanently short-circuit
        let policy = Policy {
            default_action: Effect::Allow,
            rules: vec![
                PolicyRule {
                    id: "deny-all-network".into(),
                    description: None,
                    effect: Effect::Deny,
                    tools: vec!["network.*".into()],
                },
                PolicyRule {
                    id: "allow-specific-ping-override".into(),
                    description: None,
                    effect: Effect::Allow,
                    tools: vec!["network.ping".into()],
                },
            ],
        };

        // Deny wins!
        assert!(!policy.is_allowed("network.ping"));
    }

    #[test]
    fn test_glob_support() {
        // Tests that actual globs are supported, not just end-matches
        assert!(wildcard_match("linux.*.info", "linux.system.info"));
        assert!(wildcard_match("redis.?et", "redis.get"));
        assert!(wildcard_match("redis.?et", "redis.set"));
        assert!(!wildcard_match("redis.?et", "redis.keys"));
    }

    #[test]
    fn test_effect_is_copy() {
        let effect1 = Effect::Allow;
        let effect2 = effect1; // Should copy, not move
        assert_eq!(effect1, effect2); 
    }

    #[test]
    fn test_parse_toml() {
        let toml = r#"
        default_action = "deny"

        [[rules]]
        id = "allow-safe"
        effect = "allow"
        tools = ["system.*", "service.list"]
        "#;

        let policy: Policy = toml::from_str(toml).unwrap();
        assert_eq!(policy.default_action, Effect::Deny);
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].id, "allow-safe");
        assert_eq!(policy.rules[0].tools.len(), 2);
    }
}
