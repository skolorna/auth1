use std::str::FromStr;

use serde::{de, Deserialize, Deserializer};
use thiserror::Error;

/// The password type deliberately omits implementation of `Display` and `Serialize` in order
/// not to accidentally send passwords over the wire.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Password(String);

impl Password {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[derive(Debug, Error)]
pub enum ValidatePasswordError {
    #[error("password too short")]
    TooShort,
}

impl FromStr for Password {
    type Err = ValidatePasswordError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.chars().count() < 8 {
            return Err(ValidatePasswordError::TooShort);
        }

        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::types::Password;

    #[test]
    fn validation() {
        let good_passwords = vec!["8IrYFCoJadSzXVfkJVss/9/qISc6"];

        for pass in good_passwords {
            assert!(Password::from_str(pass).is_ok());
        }

        let bad_passwords = vec![""];

        for pass in bad_passwords {
            assert!(
                Password::from_str(pass).is_err(),
                "\"{}\" is a bad password",
                pass
            );
        }
    }
}
