//! Reading YAML: conda-lock.yml, environment.yml, pnpm-lock.yaml, pnpm-workspace.yaml and yarn berry's
//! yarn.lock (#21).
//!
//! serde-saphyr caps every document at 250,000 nodes by default, which a large monorepo's lockfile
//! passes at around 4 MB. Nothing can hold more nodes or events than it has bytes, so the caps here
//! grow with the input instead; the alias limits, which stop a small file expanding into a huge one,
//! stay at their defaults.

use serde::Deserialize;

/// Deserialize one YAML document, with limits that scale with its size.
pub fn from_str<'de, T: Deserialize<'de>>(text: &'de str) -> Result<T, serde_saphyr::Error> {
    serde_saphyr::from_str_with_options(text, options(text.len()))
}

fn options(len: usize) -> serde_saphyr::Options {
    let defaults = serde_saphyr::Budget::default();
    serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_events: defaults.max_events.max(len.saturating_mul(2)),
            max_nodes: defaults.max_nodes.max(len),
            max_total_scalar_bytes: defaults.max_total_scalar_bytes.max(len),
        },
        with_snippet: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn reads_a_document_past_the_default_node_cap() {
        let text: String = (0..300_000).map(|i| format!("k{i}: v\n")).collect();
        let map: BTreeMap<String, String> = from_str(&text).expect("a large flat mapping parses");
        assert_eq!(map.len(), 300_000);
        assert!(
            serde_saphyr::from_str::<BTreeMap<String, String>>(&text).is_err(),
            "the default caps it"
        );
    }

    #[test]
    fn still_refuses_an_alias_bomb() {
        let mut text = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 1..12 {
            let prev = i - 1;
            text.push_str(&format!("a{i}: &a{i} [*a{prev}, *a{prev}, *a{prev}, *a{prev}, *a{prev}, *a{prev}, *a{prev}, *a{prev}, *a{prev}, *a{prev}]\n"));
        }
        assert!(from_str::<serde_json::Value>(&text).is_err());
    }

    #[test]
    fn errors_name_the_line() {
        let err = from_str::<BTreeMap<String, String>>("a: b\nc: [unclosed\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("line"), "{err}");
        assert!(!err.contains('\n'), "one line, for a warning: {err}");
    }
}
