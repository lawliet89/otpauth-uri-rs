//! TOTP/HOTP URI
//!
//! This crate parses and generates TOTP/HOTP URI. This is usually provided in the form of QR codes.
//!
//! The format is documented
//! [here](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

#![allow(
    legacy_directory_ownership,
    missing_copy_implementations,
    missing_debug_implementations,
    unknown_lints
)]
#![deny(
    const_err,
    dead_code,
    deprecated,
    exceeding_bitshifts,
    improper_ctypes,
    missing_docs,
    mutable_transmutes,
    no_mangle_const_items,
    non_camel_case_types,
    non_shorthand_field_patterns,
    non_upper_case_globals,
    overflowing_literals,
    path_statements,
    plugin_as_library,
    private_no_mangle_fns,
    private_no_mangle_statics,
    stable_features,
    trivial_casts,
    trivial_numeric_casts,
    unconditional_recursion,
    unknown_crate_types,
    unreachable_code,
    unused_allocation,
    unused_assignments,
    unused_attributes,
    unused_comparisons,
    unused_extern_crates,
    unused_features,
    unused_imports,
    unused_import_braces,
    unused_qualifications,
    unused_must_use,
    unused_mut,
    unused_parens,
    unused_results,
    unused_unsafe,
    unused_variables,
    warnings,
    while_true
)]
#![doc(test(attr(allow(unused_variables), deny(warnings))))]

extern crate base32;
extern crate failure;
extern crate url;

use failure::Fail;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use url::Url;

// Serde
// QR Code?
// Generate totp

/// Errors that can be returned. This enum implements the [`failure::Fail`] trait from the
/// [`failure`](https://github.com/rust-lang-nursery/failure) crate.
#[derive(Debug, Fail)]
pub enum Error {
    /// Generic unknown error
    #[fail(display = "A Generic error has occured")]
    Generic,
    /// Uri parsing failed
    #[fail(display = "Uri Parsing failed")]
    ParseError(#[fail(cause)] url::ParseError),
    /// Invalid Scheme in the URI
    #[fail(
        display = "Invalid URI scheme. Expecting 'otpauth', got '{}'",
        actual
    )]
    InvalidScheme {
        /// Actual Scheme provided
        actual: String,
    },
    /// URI is missing the type
    // XXX: Not sure how to even trigger this error
    #[fail(display = "URI is missing the type")]
    MissingType,
    /// Invalid Type was provided
    #[fail(display = "Invalid Type was provided: {}", actual)]
    InvalidType {
        /// Invalid type provided
        actual: String,
    },
    /// Secret is missing from the URI
    #[fail(display = "Secret is missing from the URI")]
    MissingSecret,
    /// Invalid Algorithm was provided
    #[fail(display = "Invalid Algorithm was provided: {}", actual)]
    InvalidAlgorithm {
        /// Invalid Algorithm provided
        actual: String,
    },
    /// Invalid digits was provided
    #[fail(display = "Invalid digits was provided")]
    InvalidDigits,
    /// Invalid counter was provided
    #[fail(display = "Invalid counter was provided")]
    InvalidCounter,
    /// Invalid period was provided
    #[fail(display = "Invalid period was provided")]
    InvalidPeriod,
    /// Counter is invalid for type TOTP
    #[fail(display = "Counter is invalid for type TOTP")]
    InvalidCounterforTOTP,
    /// Counter is required for type HOTP, but is not present
    #[fail(display = "Counter is required for type HOTP, but is not present")]
    MissingCounter,
    /// Period is invalid for type HOTP
    #[fail(display = "Priod is invalid for type HOTP")]
    InvalidPeriodForHOTP,
}

impl From<url::ParseError> for Error {
    fn from(error: url::ParseError) -> Error {
        Error::ParseError(error)
    }
}

/// Type of the OTP secret
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Type {
    /// TOTP
    TOTP,
    /// HOTP
    HOTP,
}

impl FromStr for Type {
    type Err = Error;

    fn from_str(totp_type: &str) -> Result<Self, Self::Err> {
        let totp_type = totp_type.to_lowercase();
        if totp_type == "totp" {
            Ok(Type::TOTP)
        } else if totp_type == "hotp" {
            Ok(Type::HOTP)
        } else {
            Err(Error::InvalidType {
                actual: totp_type.to_string(),
            })
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Type::TOTP => write!(f, "totp"),
            Type::HOTP => write!(f, "hotp"),
        }
    }
}

/// Algorithm for the URI
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// SHA1 algorithm
    SHA1,
    /// SHA256 algorithm
    SHA256,
    /// SHA512 Algorithm
    SHA512,
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(algorithm: &str) -> Result<Self, Self::Err> {
        let algorithm = algorithm.to_uppercase();
        Ok(match algorithm.as_ref() {
            "SHA1" => Algorithm::SHA1,
            "SHA256" => Algorithm::SHA256,
            "SHA512" => Algorithm::SHA512,
            invalid => Err(Error::InvalidAlgorithm {
                actual: invalid.to_string(),
            })?,
        })
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Algorithm::SHA1 => write!(f, "SHA1"),
            Algorithm::SHA256 => write!(f, "SHA256"),
            Algorithm::SHA512 => write!(f, "SHA512"),
        }
    }
}

/// Number of digits to be generated for TOTP/HOTP
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Digits {
    /// Six digits will be generated for the TOTP
    Six = 6,
    /// Eight digits will be generated for the TOTP
    Eight = 8,
}

impl FromStr for Digits {
    type Err = Error;

    fn from_str(digits: &str) -> Result<Self, Self::Err> {
        let digits = digits.to_lowercase();
        Ok(match digits.as_ref() {
            "6" => Digits::Six,
            "8" => Digits::Eight,
            _invalid => Err(Error::InvalidDigits)?,
        })
    }
}

impl fmt::Display for Digits {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Digits::Six => write!(f, "6"),
            Digits::Eight => write!(f, "8"),
        }
    }
}

impl Default for Digits {
    fn default() -> Self {
        Digits::Six
    }
}

/// Parsed TOTP/HOTP URI
///
/// This is usually provided by the service requiring two factor authentication in the form
/// of a QR code.
///
/// The format is documented
/// [here](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtpAuthUri {
    /// Type of the OTP secret
    pub totp_type: Type,

    /// Label of the key. This usually identifies the account and the issuer associated with the
    /// key in the form of `PREFIX:ACCOUNT` where `PREFIX` refers to the issuer and the `ACCOUNT`
    /// refers to the associated account.
    ///
    /// You can extract the prefix using `[OtpAuthUri::prefix]` and the account using
    /// `[OtpAuthUri::account]`
    pub label: String,
    /// Byte value of the key
    ///
    /// Use `[OtpAuthUri::secret_b32]` to retrieve the key in Base32
    pub secret: Vec<u8>,
    /// String value indicating the provider or service the account is associated with
    pub issuer: Option<String>,
    /// Algorithm for the secret
    pub algorithm: Option<Algorithm>,
    /// Number of digits to be generated for TOTP/HOTP
    pub digits: Digits,
    /// Initial counter value for HOTP
    pub counter: Option<u32>,
    /// Period, in seconds, that a TOTP code will be valid for
    pub period: Option<u32>,
}

impl OtpAuthUri {
    /// Parse a URI string. Returns an error on invalid parsing or validation
    pub fn parse(uri: &str) -> Result<Self, Error> {
        let uri = Url::parse(uri)?;

        // Validate scheme
        if uri.scheme() != "otpauth" {
            Err(Error::InvalidScheme {
                actual: uri.scheme().to_string(),
            })?;
        }

        let totp_type = uri.host_str().ok_or_else(|| Error::MissingType)?;
        let totp_type = Type::from_str(totp_type)?;
        let label = uri.path().chars().skip(1).collect();

        let params: HashMap<Cow<str>, Cow<str>> = uri.query_pairs().collect();
        let algorithm = match params.get("algorithm") {
            Some(algo) => Some(algo.parse()?),
            None => None,
        };

        let issuer = params.get("issuer").map(ToString::to_string);

        let secret = params.get("secret").ok_or_else(|| Error::MissingSecret)?;
        let secret = base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret)
            .ok_or_else(|| Error::MissingSecret)?;

        let digits = match params.get("digits") {
            Some(digits) => Some(digits.parse()?),
            None => None,
        }.unwrap_or_default();

        let counter = match params.get("counter") {
            Some(counter) => Some(counter.parse().map_err(|_| Error::InvalidCounter)?),
            None => None,
        };

        let period = match params.get("period") {
            Some(period) => Some(period.parse().map_err(|_| Error::InvalidPeriod)?),
            None => {
                if totp_type == Type::TOTP {
                    Some(30)
                } else {
                    None
                }
            }
        };

        let uri = Self {
            totp_type,
            label,
            secret,
            issuer,
            algorithm,
            digits,
            counter,
            period,
        };

        uri.validate()?;

        Ok(uri)
    }

    /// Validate that the URI is valid
    pub fn validate(&self) -> Result<(), Error> {
        match self.totp_type {
            Type::TOTP => {
                if self.counter.is_some() {
                    Err(Error::InvalidCounterforTOTP)?;
                }
            }
            Type::HOTP => {
                if self.period.is_some() {
                    Err(Error::InvalidPeriodForHOTP)?
                }
                if self.counter.is_none() {
                    Err(Error::MissingCounter)?
                }
            }
        };

        Ok(())
    }

    fn _to_string(&self) -> String {
        let uri = format!("otpauth://{}/{}?", self.totp_type, self.label);
        let mut params = vec![];

        params.push(format!(
            "secret={}",
            base32::encode(base32::Alphabet::RFC4648 { padding: false }, &self.secret)
        ));

        if self.issuer.is_some() {
            params.push(format!(
                "issuer={}",
                self.issuer.as_ref().expect("to have some")
            ));
        }

        if self.algorithm.is_some() {
            params.push(format!(
                "algorithm={}",
                self.algorithm.as_ref().expect("to have some")
            ));
        }

        params.push(format!("digits={}", self.digits));

        if self.counter.is_some() {
            params.push(format!(
                "counter={}",
                self.counter.as_ref().expect("to have some")
            ));
        }

        if self.period.is_some() {
            params.push(format!(
                "period={}",
                self.period.as_ref().expect("to have some")
            ));
        }

        let params = params.join("&");
        [uri, params].join("")
    }

    /// Returns the prefix parsed from the label
    pub fn prefix(&self) -> Option<String> {
        unimplemented!("Not yet implemented");
    }


    /// Returns the account parsed from the label
    pub fn account(&self) -> Option<String> {
        unimplemented!("Not yet implemented");
    }
}

impl FromStr for OtpAuthUri {
    type Err = Error;

    fn from_str(uri: &str) -> Result<Self, Error> {
        Self::parse(uri)
    }
}

impl fmt::Display for OtpAuthUri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self._to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TOTP: &str =
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=8&period=30";
    static HOTP: &str =
        "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=8&counter=30";

    #[test]
    fn totp_round_trip() {
        let uri = OtpAuthUri::parse(TOTP).expect("Not to fail");
        assert_eq!(uri.to_string(), TOTP);
    }

    #[test]
    fn hotp_round_trip() {
        let uri = OtpAuthUri::parse(HOTP).expect("Not to fail");
        assert_eq!(uri.to_string(), HOTP);
    }

    #[test]
    fn totp_defaults() {
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let uri = OtpAuthUri::parse(uri).expect("Not to fail");

        assert_eq!(Some(30), uri.period);
        assert_eq!(Digits::Six, uri.digits);
        assert!(uri.counter.is_none());
    }

    #[test]
    fn hotp_defaults() {
        let uri = "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&counter=1";
        let uri = OtpAuthUri::parse(uri).expect("Not to fail");

        assert_eq!(Some(1), uri.counter);
        assert_eq!(Digits::Six, uri.digits);
        assert!(uri.period.is_none());
    }

    #[test]
    #[should_panic(expected = "RelativeUrlWithoutBase")]
    fn empty_url_should_panic() {
        let _ = OtpAuthUri::parse("").unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidType")]
    fn invalid_type_should_panic() {
        let uri = "otpauth://xxx/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&counter=1";
        let _ = OtpAuthUri::parse(uri).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingSecret")]
    fn missing_secret_should_panic() {
        let uri = "otpauth://hotp/Example:alice@google.com?issuer=Example&counter=1";
        let _ = OtpAuthUri::parse(uri).unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidDigits")]
    fn invalid_digits_should_panic() {
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=7&period=30";
        let _ = OtpAuthUri::parse(uri).unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidCounter")]
    fn invalid_counter_should_panic() {
        let uri = "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&counter=foobar";
        let _ = OtpAuthUri::parse(uri).unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidPeriod")]
    fn invalid_period_should_panic() {
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&period=foobar";
        let _ = OtpAuthUri::parse(uri).unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidCounterforTOTP")]
    fn counter_for_totp_should_panic() {
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&counter=1";
        let _ = OtpAuthUri::parse(uri).unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidPeriodForHOTP")]
    fn period_for_hotp_should_panic() {
        let uri = "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&period=30";
        let _ = OtpAuthUri::parse(uri).unwrap();
    }

    #[test]
    #[should_panic(expected = "MissingCounter")]
    fn missing_counter_for_hotp_should_panic() {
        let uri = "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let _ = OtpAuthUri::parse(uri).unwrap();
    }

}
