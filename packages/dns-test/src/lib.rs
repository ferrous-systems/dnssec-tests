//! A test framework for all things DNS

use std::borrow::Cow;
use std::env;
use std::path::Path;

use lazy_static::lazy_static;
use url::Url;

pub use crate::container::Network;
pub use crate::fqdn::FQDN;
pub use crate::resolver::Resolver;
pub use crate::trust_anchor::TrustAnchor;

pub mod client;
mod container;
mod fqdn;
pub mod name_server;
pub mod record;
mod resolver;
mod trust_anchor;
pub mod tshark;
pub mod zone_file;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = core::result::Result<T, Error>;

// TODO maybe this should be a TLS variable that each unit test (thread) can override
const DEFAULT_TTL: u32 = 24 * 60 * 60; // 1 day

#[derive(Clone, Debug)]
pub enum Implementation {
    Bind,
    Hickory(Repository<'static>),
    Unbound,
}

impl Implementation {
    #[must_use]
    pub fn is_bind(&self) -> bool {
        matches!(self, Self::Bind)
    }
}

#[derive(Clone, Debug)]
pub struct Repository<'a> {
    inner: Cow<'a, str>,
}

impl Repository<'_> {
    fn as_str(&self) -> &str {
        &self.inner
    }
}

/// checks that `input` looks like a valid repository which can be either local or remote
///
/// # Panics
///
/// this function panics if `input` is not a local `Path` that exists or a well-formed URL
#[allow(non_snake_case)]
pub fn Repository(input: impl Into<Cow<'static, str>>) -> Repository<'static> {
    let input = input.into();
    assert!(
        Path::new(&*input).exists() || Url::parse(&input).is_ok(),
        "{input} is not a valid repository"
    );
    Repository { inner: input }
}

impl Default for Implementation {
    fn default() -> Self {
        Self::Unbound
    }
}

lazy_static! {
    pub static ref SUBJECT: Implementation = parse_subject();
    pub static ref PEER: Implementation = parse_peer();
}

fn parse_subject() -> Implementation {
    if let Ok(subject) = env::var("DNS_TEST_SUBJECT") {
        if subject == "unbound" {
            return Implementation::Unbound;
        }

        if subject == "bind" {
            return Implementation::Bind;
        }

        if subject.starts_with("hickory") {
            if let Some(url) = subject.strip_prefix("hickory ") {
                Implementation::Hickory(Repository(url.to_string()))
            } else {
                panic!("the syntax of DNS_TEST_SUBJECT is 'hickory $URL', e.g. 'hickory /tmp/hickory' or 'hickory https://github.com/owner/repo'")
            }
        } else {
            panic!("unknown implementation: {subject}")
        }
    } else {
        Implementation::default()
    }
}

fn parse_peer() -> Implementation {
    if let Ok(peer) = env::var("DNS_TEST_PEER") {
        match peer.as_str() {
            "unbound" => Implementation::Unbound,
            "bind" => Implementation::Bind,
            _ => panic!("`{peer}` is not supported as a test peer implementation"),
        }
    } else {
        Implementation::default()
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;

    impl PartialEq for Implementation {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::Hickory(_), Self::Hickory(_)) => true,
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    #[test]
    fn immutable_subject() {
        let before = super::SUBJECT.clone();
        let newval = if before == Implementation::Unbound {
            "bind"
        } else {
            "unbound"
        };
        env::set_var("DNS_TEST_SUBJECT", newval);

        let after = super::SUBJECT.clone();
        assert_eq!(before, after);
    }

    #[test]
    fn immutable_peer() {
        let before = super::PEER.clone();
        let newval = if before == Implementation::Unbound {
            "bind"
        } else {
            "unbound"
        };
        env::set_var("DNS_TEST_PEER", newval);

        let after = super::PEER.clone();
        assert_eq!(before, after);
    }
}
