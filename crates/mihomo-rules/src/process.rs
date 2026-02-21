use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};

pub struct ProcessRule {
    process_name: String,
    adapter: String,
}

impl ProcessRule {
    pub fn new(name: &str, adapter: &str) -> Self {
        Self {
            process_name: name.to_string(),
            adapter: adapter.to_string(),
        }
    }
}

impl Rule for ProcessRule {
    fn rule_type(&self) -> RuleType {
        RuleType::ProcessName
    }

    fn match_metadata(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        if metadata.process.is_empty() {
            (helper.find_process)();
        }
        metadata.process.eq_ignore_ascii_case(&self.process_name)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.process_name
    }

    fn should_find_process(&self) -> bool {
        true
    }
}
