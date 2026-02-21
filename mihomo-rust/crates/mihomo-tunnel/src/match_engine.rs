use mihomo_common::{Metadata, Rule, RuleMatchHelper};
use mihomo_dns::Resolver;
use std::sync::Arc;

pub struct MatchResult {
    pub adapter_name: String,
    pub rule_name: String,
    pub rule_payload: String,
}

/// Match metadata against rules. Returns the adapter name and matched rule info.
pub fn match_rules(
    metadata: &Metadata,
    rules: &[Box<dyn Rule>],
    _resolver: &Arc<Resolver>,
) -> Option<MatchResult> {
    // Create the lazy helper.
    // Note: In a real implementation, resolve_ip would mutate metadata.dst_ip via interior
    // mutability. For now, we provide the callbacks that the rules can use.
    let helper = RuleMatchHelper {
        resolve_ip: Box::new(|| {
            // This is called lazily when a rule needs IP resolution.
            // The actual resolution happens in the tunnel's pre-handle phase.
        }),
        find_process: Box::new(|| {
            // This is called lazily when a rule needs process info.
            // Process lookup is platform-specific.
        }),
    };

    for rule in rules {
        if rule.match_metadata(metadata, &helper) {
            return Some(MatchResult {
                adapter_name: rule.adapter().to_string(),
                rule_name: format!("{}", rule.rule_type()),
                rule_payload: rule.payload().to_string(),
            });
        }
    }
    None
}
