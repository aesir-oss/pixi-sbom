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
