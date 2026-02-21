use mihomo_common::Rule;
use tracing::warn;

pub fn parse_rules(raw_rules: &[String]) -> Vec<Box<dyn Rule>> {
    let mut rules = Vec::new();
    for line in raw_rules {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match mihomo_rules::parse_rule(line) {
            Ok(rule) => rules.push(rule),
            Err(e) => warn!("Failed to parse rule '{}': {}", line, e),
        }
    }
    rules
}
