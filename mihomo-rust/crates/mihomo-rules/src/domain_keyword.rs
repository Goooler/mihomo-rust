use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};

pub struct DomainKeywordRule {
    keyword: String,
    adapter: String,
}

impl DomainKeywordRule {
    pub fn new(keyword: &str, adapter: &str) -> Self {
        Self {
            keyword: keyword.to_lowercase(),
            adapter: adapter.to_string(),
        }
    }
}

impl Rule for DomainKeywordRule {
    fn rule_type(&self) -> RuleType {
        RuleType::DomainKeyword
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        metadata.rule_host().to_lowercase().contains(&self.keyword)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.keyword
    }
}
