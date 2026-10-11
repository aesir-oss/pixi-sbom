//! License policy: allow-list, deny-list and "every package must have a license".
//!
//! Whether an expression is acceptable is the shared crate's verdict (`common::license_policy`, #59), the one
//! pixi-policy's licenses rule gives too. This module applies it to a document's packages: the missing and
//! non-SPDX licenses `--require-license` fails, the exemptions `--ignore-license` grants, and the report.

use std::fmt;

use common::license::{self, License};
use common::license_policy::Lists;
use miette::Diagnostic;
use thiserror::Error;

use crate::model::Sbom;

/// Why a package violates the policy: the shared verdict's reasons.
pub use common::license_policy::Reason;

/// Exit code of a run whose documents were written but whose policy was violated.
pub const VIOLATION_EXIT_CODE: i32 = 3;

/// The `pixi:*` property recording that a package was let through the policy deliberately,
/// with the justification when one was given.
pub const EXEMPT_PROPERTY: &str = "pixi:license-exempt";

/// One package (or pattern of packages) the policy does not apply to, and why.
#[derive(Debug, Clone)]
pub struct Exemption {
    /// Name or shell-style pattern, as `--exclude` spells it.
    pub pattern: crate::filter::Glob,
    /// Free text, for the report and the document.
    pub justification: Option<String>,
}

impl Exemption {
    /// Parse `PACKAGE` or `PACKAGE:justification`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let (pattern, justification) = match text.split_once(':') {
            Some((pattern, rest)) => (pattern.trim(), Some(rest.trim()).filter(|r| !r.is_empty())),
            None => (text, None),
        };
        if pattern.is_empty() {
            return Err(format!("'{text}' names no package"));
        }
        Ok(Self {
            pattern: crate::filter::Glob::parse(pattern)?,
            justification: justification.map(str::to_string),
        })
    }
}

/// A package the policy would have failed, let through by an exemption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exempt {
    pub violation: Violation,
    pub justification: Option<String>,
}

impl fmt::Display for Exempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.violation)?;
        match &self.justification {
            Some(justification) => write!(f, " — {justification}"),
            None => Ok(()),
        }
    }
}

/// What a policy check found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Packages that fail the policy and are not exempt.
    pub violations: Vec<Violation>,
    /// Packages that would have failed and were let through.
    pub exempt: Vec<Exempt>,
}

/// A licensee given on the command line could not be parsed.
#[derive(Debug, Error, Diagnostic)]
#[error("'{text}' is not an SPDX license identifier: {reason}")]
#[diagnostic(
    code(pixi_sbom::policy::licensee),
    help("use an identifier from the SPDX license list, e.g. MIT, Apache-2.0, GPL-3.0-or-later, or a LicenseRef-")
)]
pub struct LicenseeError {
    /// What was given.
    pub text: String,
    /// Why it was rejected.
    pub reason: String,
}

impl From<common::license_policy::LicenseeError> for LicenseeError {
    fn from(err: common::license_policy::LicenseeError) -> Self {
        Self {
            text: err.text,
            reason: err.reason,
        }
    }
}

/// The policy to enforce.
#[derive(Debug, Default)]
pub struct Policy {
    lists: Lists,
    require_license: bool,
    /// Packages the policy deliberately does not apply to.
    exemptions: Vec<Exemption>,
}

/// One package that violates the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub package: String,
    pub version: Option<String>,
    pub license: Option<String>,
    pub reason: Reason,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.package)?;
        if let Some(version) = &self.version {
            write!(f, " {version}")?;
        }
        write!(f, ": {}", self.reason)?;
        if let Some(license) = &self.license {
            write!(f, " ({license})")?;
        }
        Ok(())
    }
}

impl Policy {
    /// Build a policy from the command-line lists; `None` when nothing was asked for.
    pub fn new(
        allow: &[String],
        deny: &[String],
        require_license: bool,
        exemptions: Vec<Exemption>,
    ) -> Result<Option<Self>, LicenseeError> {
        if allow.is_empty() && deny.is_empty() && !require_license {
            return Ok(None);
        }
        Ok(Some(Self {
            lists: Lists::new(allow, deny)?,
            require_license,
            exemptions,
        }))
    }

    /// The exemption that covers a package, if any.
    fn exemption(&self, package: &str) -> Option<&Exemption> {
        self.exemptions.iter().find(|e| e.pattern.matches(package))
    }

    /// Every package in `sbom` that violates the policy, in document order.
    pub fn check(&self, sbom: &Sbom) -> Outcome {
        let mut outcome = Outcome::default();
        for package in &sbom.packages {
            let violation = |reason, license: Option<String>| Violation {
                package: package.name.clone(),
                version: package.version.clone(),
                license,
                reason,
            };
            // A package the policy does not apply to is recorded, not failed.
            let mut record = |reason, license: Option<String>| match self.exemption(&package.name) {
                Some(exemption) => outcome.exempt.push(Exempt {
                    violation: violation(reason, license),
                    justification: exemption.justification.clone(),
                }),
                None => outcome.violations.push(violation(reason, license)),
            };
            let Some(raw) = package.license.as_deref() else {
                if self.require_license {
                    record(Reason::Missing, None);
                }
                continue;
            };
            let expression = match license::normalize(raw) {
                License::Expression(expression) => expression,
                License::Text(text) => {
                    if self.require_license {
                        let detail = license::rejection_reason(raw)
                            .map(|why| format!("{text} ({why})"))
                            .unwrap_or(text);
                        record(Reason::NotSpdx, Some(detail));
                    }
                    continue;
                }
            };
            if !self.lists.restricts() {
                continue;
            }
            if let Some(reason) = self.lists.evaluate(&expression) {
                record(reason, Some(expression));
            }
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_carries_a_code_and_a_next_step() {
        crate::assert_actionable(&LicenseeError {
            text: "MIT-ish".to_string(),
            reason: "unknown identifier".to_string(),
        });
    }
    use crate::format::testing::sample_sbom;

    fn policy(allow: &[&str], deny: &[&str], require: bool) -> Policy {
        let allow: Vec<String> = allow.iter().map(|s| s.to_string()).collect();
        let deny: Vec<String> = deny.iter().map(|s| s.to_string()).collect();
        Policy::new(&allow, &deny, require, Vec::new()).unwrap().unwrap()
    }

    /// The shared verdict table (#59), run through this gate: the same verdict pixi-policy's licenses rule gives.
    #[test]
    fn the_shared_verdict_table_gives_the_same_verdicts_through_the_gate() {
        for case in common::license_policy::cases::CASES {
            let mut sbom = sample_sbom();
            sbom.packages.truncate(1);
            sbom.packages[0].license = Some(case.expression.to_string());
            let violations = policy(case.allow, case.deny, false).check(&sbom).violations;
            let got = violations.first().map(|v| v.reason.clone());
            assert_eq!(got, case.expected, "{}: {}", case.expression, case.why);
        }
    }

    #[test]
    fn an_exempt_package_is_recorded_instead_of_failed() {
        let mut sbom = sample_sbom();
        // libzlib is Zlib, mylib is Proprietary: two different ways to fail one policy.
        let deny = Policy::new(
            &[],
            &["Zlib".into()],
            true,
            vec![
                Exemption::parse("libz*:vendored, reviewed 2026-01").unwrap(),
                Exemption::parse("mylib").unwrap(),
            ],
        )
        .unwrap()
        .unwrap();
        sbom.packages.iter_mut().find(|p| p.name == "mylib").unwrap().license = None;

        let outcome = deny.check(&sbom);
        // six declares no license and is nobody's exemption.
        let failed: Vec<&str> = outcome.violations.iter().map(|v| v.package.as_str()).collect();
        assert_eq!(failed, ["six"], "{outcome:?}");
        let exempt: Vec<(&str, Option<&str>)> = outcome
            .exempt
            .iter()
            .map(|e| (e.violation.package.as_str(), e.justification.as_deref()))
            .collect();
        assert_eq!(
            exempt,
            [("libzlib", Some("vendored, reviewed 2026-01")), ("mylib", None)]
        );
        assert_eq!(outcome.exempt[0].violation.reason, Reason::Denied);
        assert_eq!(outcome.exempt[1].violation.reason, Reason::Missing);
        assert!(
            outcome.exempt[0].to_string().contains("vendored, reviewed 2026-01"),
            "{}",
            outcome.exempt[0]
        );

        // Without the exemptions the same policy fails both.
        let strict = Policy::new(&[], &["Zlib".into()], true, Vec::new()).unwrap().unwrap();
        assert_eq!(strict.check(&sbom).violations.len(), 3);
    }

    #[test]
    fn an_exemption_needs_a_package_and_takes_a_justification() {
        assert_eq!(Exemption::parse("six").unwrap().justification, None);
        assert_eq!(
            Exemption::parse(" six : because ").unwrap().justification.as_deref(),
            Some("because")
        );
        assert_eq!(Exemption::parse("six:").unwrap().justification, None);
        assert!(Exemption::parse(":why").is_err());
        assert!(Exemption::parse("  ").is_err());
    }

    #[test]
    fn no_flags_means_no_policy_and_bad_licensees_are_errors() {
        assert!(Policy::new(&[], &[], false, Vec::new()).unwrap().is_none());
        assert!(Policy::new(&[], &[], true, Vec::new()).unwrap().is_some());
        let err = Policy::new(&["not a license!!".into()], &[], false, Vec::new()).unwrap_err();
        assert!(err.text.contains("not a license"));
        assert!(
            Policy::new(&["mit".into()], &[], false, Vec::new()).is_ok(),
            "lax parsing accepts lower case"
        );
    }

    #[test]
    fn check_reports_packages_in_document_order() {
        let sbom = sample_sbom();
        // libzlib: Zlib; zlib: MIT/Apache-2.0; mylib: Proprietary (text); six: none.
        let deny = policy(&[], &["Zlib"], false);
        let v = deny.check(&sbom).violations;
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].package, "libzlib");
        assert_eq!(v[0].reason, Reason::Denied);
        assert_eq!(v[0].to_string(), "libzlib 1.3.1: denied license (Zlib)");

        let allow = policy(&["Zlib", "MIT"], &[], false);
        let v = allow.check(&sbom).violations;
        assert_eq!(
            v.len(),
            0,
            "MIT satisfies MIT OR Apache-2.0; text and missing are not violations"
        );

        let require = policy(&[], &[], true);
        let v = require.check(&sbom).violations;
        let names: Vec<_> = v.iter().map(|v| (v.package.as_str(), v.reason.clone())).collect();
        assert_eq!(names, [("mylib", Reason::NotSpdx), ("six", Reason::Missing)]);
        assert_eq!(v[1].to_string(), "six 1.17.0: no license declared");
        assert_eq!(
            v[0].to_string(),
            "mylib: license is not an SPDX expression (Proprietary (unknown term: 'Proprietary'))"
        );
    }
}
