//! License policy: allow-list, deny-list and "every package must have a license".
//!
//! Whether an expression is acceptable is the shared crate's verdict (`crate::policy::verdict`, #59), the one
//! pixi-policy's licenses rule gives too. This module applies it to a document's packages: the missing and
//! non-SPDX licenses `--require-license` fails, the exemptions `--ignore-license` grants, and the report.

use std::fmt;

use crate::license::{self, License};
use crate::policy::verdict::Lists;
use miette::Diagnostic;
use thiserror::Error;

use crate::model::Sbom;

/// Why a package violates the policy: the shared verdict's reasons.
pub use crate::policy::verdict::Reason;

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

impl From<crate::policy::verdict::LicenseeError> for LicenseeError {
    fn from(err: crate::policy::verdict::LicenseeError) -> Self {
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
        for case in crate::policy::verdict::cases::CASES {
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

/// The license verdict, as it was shared with pixi-policy (#59) until the tools moved to repositories of their own.
pub mod verdict {
//! Whether a license expression is acceptable under allow and deny lists: the one verdict pixi-sbom's license gate
//! and pixi-policy's licenses rule share (#59), so a package gets the same answer from both.
//!
//! The expression is evaluated with its `AND` / `OR` structure respected: `MIT OR GPL-3.0-only` passes a policy that
//! denies GPL because MIT is an option; `MIT AND GPL-3.0-only` does not. Identifiers are compared by base id,
//! `-or-later` flag and exception, so the deprecated `GPL-3.0` and the current `GPL-3.0-only` mean the same thing,
//! and an `-or-later` requirement is satisfied by any allowed later version of the same family.

use std::fmt;

use spdx::{LicenseItem, LicenseReq, ParseMode};

/// A licensee given in an allow or deny list could not be parsed. Each tool reports it in its own words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseeError {
    /// What was given.
    pub text: String,
    /// Why it was rejected.
    pub reason: String,
}

impl fmt::Display for LicenseeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "'{}' is not an SPDX license identifier: {}", self.text, self.reason)
    }
}

impl std::error::Error for LicenseeError {}

/// A single license identifier in comparable form.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Lic {
    /// `GPL-3.0`, `MIT`, `LicenseRef-Proprietary`.
    base: String,
    /// The requirement or licensee accepts later versions.
    or_later: bool,
    /// Exception name, e.g. `Classpath-exception-2.0`.
    addition: Option<String>,
}

impl Lic {
    fn from_req(req: &LicenseReq) -> Self {
        let (name, mut or_later) = match &req.license {
            LicenseItem::Spdx { id, or_later } => (id.name.to_string(), *or_later),
            LicenseItem::Other(lic) => (
                match &lic.doc_ref {
                    Some(doc) => format!("DocumentRef-{doc}:LicenseRef-{}", lic.lic_ref),
                    None => format!("LicenseRef-{}", lic.lic_ref),
                },
                false,
            ),
        };
        let mut base = name;
        if let Some(stripped) = base.strip_suffix("-or-later") {
            base = stripped.to_string();
            or_later = true;
        } else if let Some(stripped) = base.strip_suffix("-only") {
            base = stripped.to_string();
        } else if let Some(stripped) = base.strip_suffix('+') {
            base = stripped.to_string();
            or_later = true;
        }
        let addition = req.addition.as_ref().map(|a| match a {
            spdx::AdditionItem::Spdx(id) => id.name.to_string(),
            spdx::AdditionItem::Other(add) => match &add.doc_ref {
                Some(doc) => format!("DocumentRef-{doc}:AdditionRef-{}", add.add_ref),
                None => format!("AdditionRef-{}", add.add_ref),
            },
        });
        Self {
            base,
            or_later,
            addition,
        }
    }

    /// `("GPL", "3.0")` for `GPL-3.0`; `None` when the id has no trailing version.
    fn family_version(&self) -> Option<(&str, Vec<u32>)> {
        let (family, version) = self.base.rsplit_once('-')?;
        let parts: Option<Vec<u32>> = version.split('.').map(|p| p.parse().ok()).collect();
        parts.filter(|p| !p.is_empty()).map(|v| (family, v))
    }

    /// Whether accepting this license satisfies `req`.
    fn satisfies(&self, req: &Lic) -> bool {
        if self.addition != req.addition {
            return false;
        }
        if self.base == req.base {
            return true;
        }
        if !req.or_later {
            return false;
        }
        match (self.family_version(), req.family_version()) {
            (Some((fa, va)), Some((fb, vb))) => fa == fb && va > vb,
            _ => false,
        }
    }
}

impl fmt::Display for Lic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.base)?;
        if self.or_later {
            write!(f, "-or-later")?;
        }
        if let Some(addition) = &self.addition {
            write!(f, " WITH {addition}")?;
        }
        Ok(())
    }
}

/// Why a package violates the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// The expression cannot be satisfied without a denied license.
    Denied,
    /// The expression cannot be satisfied with allowed licenses only.
    NotAllowed,
    /// The package declares no license.
    Missing,
    /// The declared license is not an SPDX expression, so it cannot be evaluated.
    NotSpdx,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Reason::Denied => "denied license",
            Reason::NotAllowed => "not in the allowed licenses",
            Reason::Missing => "no license declared",
            Reason::NotSpdx => "license is not an SPDX expression",
        })
    }
}

/// The allow and deny lists of a license policy.
#[derive(Debug, Default, Clone)]
pub struct Lists {
    allow: Vec<Lic>,
    deny: Vec<Lic>,
}

impl Lists {
    /// Parse both lists; an entry that is not an SPDX license identifier is an error.
    pub fn new(allow: &[String], deny: &[String]) -> Result<Self, LicenseeError> {
        Ok(Self {
            allow: allow.iter().map(|a| parse_licensee(a)).collect::<Result<_, _>>()?,
            deny: deny.iter().map(|d| parse_licensee(d)).collect::<Result<_, _>>()?,
        })
    }

    /// Whether the lists restrict which licenses are acceptable at all.
    pub fn restricts(&self) -> bool {
        !self.allow.is_empty() || !self.deny.is_empty()
    }

    /// `None` when `expression` is acceptable, otherwise why not: [`Reason::Denied`], [`Reason::NotAllowed`], or
    /// [`Reason::NotSpdx`] when it does not parse.
    pub fn evaluate(&self, expression: &str) -> Option<Reason> {
        let mode = ParseMode {
            allow_deprecated: true,
            ..ParseMode::STRICT
        };
        let Ok(parsed) = spdx::Expression::parse_mode(expression, mode) else {
            // normalize() only returns expressions this parser accepts; be safe anyway.
            return Some(Reason::NotSpdx);
        };
        let denied = |req: &LicenseReq| {
            let lic = Lic::from_req(req);
            self.deny.iter().any(|d| d.satisfies(&lic))
        };
        let allowed = |req: &LicenseReq| {
            let lic = Lic::from_req(req);
            self.allow.is_empty() || self.allow.iter().any(|a| a.satisfies(&lic))
        };
        if !self.deny.is_empty() && !parsed.evaluate(|req| !denied(req)) {
            return Some(Reason::Denied);
        }
        if !self.allow.is_empty() && !parsed.evaluate(|req| allowed(req) && !denied(req)) {
            return Some(Reason::NotAllowed);
        }
        None
    }
}

fn parse_licensee(text: &str) -> Result<Lic, LicenseeError> {
    let text = text.trim();
    // A licensee cannot carry the `+` shorthand; spell it out the way the license list does.
    let spelled = match text.strip_suffix('+') {
        Some(base) if !base.contains(' ') => format!("{base}-or-later"),
        _ => text.to_string(),
    };
    spdx::Licensee::parse_mode(&spelled, ParseMode::LAX)
        .map(|licensee| Lic::from_req(&licensee.into_req()))
        .map_err(|err| LicenseeError {
            text: text.to_string(),
            reason: err.reason.to_string(),
        })
}

/// The verdicts every tool that uses [`Lists`] must give: each case's lists, an expression, and the expected reason
/// (`None`: acceptable). This crate runs them against [`Lists::evaluate`]; each extension runs them through its own
/// gate, so a package can never pass one tool and fail the other.
#[doc(hidden)]
pub mod cases {
    use super::Reason;

    /// One expression under one pair of lists.
    pub struct Case {
        pub allow: &'static [&'static str],
        pub deny: &'static [&'static str],
        pub expression: &'static str,
        pub expected: Option<Reason>,
        /// What the case is about, for a failure message.
        pub why: &'static str,
    }

    const GPL3: &[&str] = &["GPL-3.0-only"];
    const ALLOW: &[&str] = &["MIT", "Apache-2.0", "GPL-3.0-or-later"];

    pub const CASES: &[Case] = &[
        Case {
            allow: &[],
            deny: GPL3,
            expression: "MIT OR GPL-3.0-only",
            expected: None,
            why: "MIT is an option",
        },
        Case {
            allow: &[],
            deny: GPL3,
            expression: "MIT AND GPL-3.0-only",
            expected: Some(Reason::Denied),
            why: "AND needs both",
        },
        Case {
            allow: &[],
            deny: GPL3,
            expression: "GPL-3.0-only",
            expected: Some(Reason::Denied),
            why: "denied outright",
        },
        Case {
            allow: &[],
            deny: GPL3,
            expression: "GPL-3.0",
            expected: Some(Reason::Denied),
            why: "deprecated spelling",
        },
        Case {
            allow: &[],
            deny: GPL3,
            expression: "GPL-2.0-only",
            expected: None,
            why: "an earlier version",
        },
        Case {
            allow: &[],
            deny: GPL3,
            expression: "GPL-2.0-or-later",
            expected: Some(Reason::Denied),
            why: "3.0 is a later version",
        },
        Case {
            allow: &[],
            deny: GPL3,
            expression: "LGPL-3.0-only",
            expected: None,
            why: "a different family",
        },
        Case {
            allow: ALLOW,
            deny: &[],
            expression: "MIT",
            expected: None,
            why: "allowed",
        },
        Case {
            allow: ALLOW,
            deny: &[],
            expression: "MIT OR GPL-2.0-only",
            expected: None,
            why: "one allowed choice is enough",
        },
        Case {
            allow: ALLOW,
            deny: &[],
            expression: "BSD-3-Clause",
            expected: Some(Reason::NotAllowed),
            why: "not on the list",
        },
        Case {
            allow: ALLOW,
            deny: &[],
            expression: "MIT AND BSD-3-Clause",
            expected: Some(Reason::NotAllowed),
            why: "AND needs both allowed",
        },
        Case {
            allow: ALLOW,
            deny: &[],
            expression: "GPL-3.0-only",
            expected: None,
            why: "the allowed base matches",
        },
        Case {
            allow: ALLOW,
            deny: &[],
            expression: "GPL-2.0-or-later",
            expected: None,
            why: "an allowed later version satisfies or-later",
        },
        Case {
            allow: ALLOW,
            deny: &[],
            expression: "GPL-2.0-only",
            expected: Some(Reason::NotAllowed),
            why: "only 2.0",
        },
        Case {
            allow: ALLOW,
            deny: &[],
            expression: "GPL-3.0-only WITH Classpath-exception-2.0",
            expected: Some(Reason::NotAllowed),
            why: "exceptions must match",
        },
        Case {
            allow: &["GPL-2.0-only WITH Classpath-exception-2.0"],
            deny: &[],
            expression: "GPL-2.0-only WITH Classpath-exception-2.0",
            expected: None,
            why: "the same exception",
        },
        Case {
            allow: &["GPL-2.0-only WITH Classpath-exception-2.0"],
            deny: &[],
            expression: "GPL-2.0-only",
            expected: Some(Reason::NotAllowed),
            why: "the exception is part of the allowance",
        },
        Case {
            allow: &["MIT", "GPL-3.0-only"],
            deny: GPL3,
            expression: "GPL-3.0-only",
            expected: Some(Reason::Denied),
            why: "deny wins over allow",
        },
        Case {
            allow: &["MIT", "GPL-3.0-only"],
            deny: GPL3,
            expression: "MIT",
            expected: None,
            why: "allowed and not denied",
        },
        Case {
            allow: &[],
            deny: &["LicenseRef-Proprietary"],
            expression: "LicenseRef-Proprietary",
            expected: Some(Reason::Denied),
            why: "a LicenseRef matches exactly",
        },
        Case {
            allow: &[],
            deny: &["LicenseRef-Proprietary"],
            expression: "LicenseRef-Other",
            expected: None,
            why: "another LicenseRef does not",
        },
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn every_case_gives_its_verdict() {
        for case in cases::CASES {
            let lists = Lists::new(&strings(case.allow), &strings(case.deny)).unwrap();
            assert_eq!(
                lists.evaluate(case.expression),
                case.expected,
                "{}: {}",
                case.expression,
                case.why
            );
        }
    }

    #[test]
    fn bad_licensees_are_errors_and_lax_parsing_takes_lower_case() {
        let err = Lists::new(&strings(&["not a license!!"]), &[]).unwrap_err();
        assert!(err.text.contains("not a license"));
        assert!(
            err.to_string()
                .starts_with("'not a license!!' is not an SPDX license identifier")
        );
        assert!(Lists::new(&strings(&["mit"]), &[]).is_ok());
        assert!(!Lists::default().restricts());
        assert!(Lists::new(&[], &strings(&["MIT"])).unwrap().restricts());
        assert_eq!(Lists::default().evaluate("not ( an expression"), Some(Reason::NotSpdx));
    }

    #[test]
    fn lic_display_and_version_parsing() {
        let l = parse_licensee("GPL-2.0+").unwrap();
        assert_eq!(l.to_string(), "GPL-2.0-or-later");
        assert_eq!(
            parse_licensee("LGPL-2.1").unwrap().family_version().unwrap().1,
            vec![2, 1]
        );
        assert_eq!(parse_licensee("MIT").unwrap().family_version(), None);
        assert_eq!(
            parse_licensee("Apache-2.0 WITH LLVM-exception").unwrap().to_string(),
            "Apache-2.0 WITH LLVM-exception"
        );
        assert_eq!(Reason::NotSpdx.to_string(), "license is not an SPDX expression");
    }
}
}
