use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};

pub struct DomainSuffixRule {
    suffix: String,
    adapter: String,
}

impl DomainSuffixRule {
    pub fn new(suffix: &str, adapter: &str) -> Self {
        Self {
            suffix: suffix.to_lowercase(),
            adapter: adapter.to_string(),
        }
    }
}

impl Rule for DomainSuffixRule {
    fn rule_type(&self) -> RuleType {
        RuleType::DomainSuffix
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let host = metadata.rule_host().to_lowercase();
        host == self.suffix || host.ends_with(&format!(".{}", self.suffix))
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.suffix
    }
}
