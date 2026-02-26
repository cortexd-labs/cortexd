use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
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
        let mut final_effect = self.default_action.clone();

        for rule in &self.rules {
            for pattern in &rule.tools {
                if wildcard_match(pattern, tool_name) {
                    final_effect = rule.effect.clone();
                }
            }
        }

        final_effect == Effect::Allow
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern.ends_with(".*") {
        let prefix = &pattern[0..pattern.len() - 2];
        value.starts_with(prefix)
    } else {
        pattern == value
    }
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
