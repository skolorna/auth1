use std::fmt::Display;

use pbkdf2::password_hash::PasswordVerifier;
use zxcvbn::feedback::Feedback;

use crate::errors::{AppError, AppResult};

/// Hash and salt a password.
/// ```
/// use auth1::crypto::hash_password;
///
/// let p = "Fel0n1ou$Grü";
/// assert_ne!(hash_password(p).unwrap(), hash_password(p).unwrap());
///
/// assert!(hash_password("Gru").is_err()); // too weak
/// ```
///
/// # Errors
/// This function throws if:
/// - the password isn't strong enough
/// - the hashing fails
pub fn hash_password(password: &str) -> AppResult<String> {
    use pbkdf2::{
        password_hash::{PasswordHasher, SaltString},
        Pbkdf2,
    };
    use rand_core::OsRng;

    let entropy = zxcvbn::zxcvbn(password, &[])?;

    if entropy.score() < 3 {
        Err(AppError::WeakPassword {
            feedback: entropy.feedback().as_ref().map(|f| f.into()),
        })
    } else {
        let salt = SaltString::generate(&mut OsRng);

        Ok(Pbkdf2
            .hash_password_simple(password.as_bytes(), &salt)?
            .to_string())
    }
}

/// Compare a password against a hashed value.
/// ```
/// use pbkdf2::password_hash::PasswordHash;
/// use auth1::crypto::{hash_password, verify_password};
///
/// let password = "d0ntpwnme";
/// let hash = hash_password(password).unwrap();
/// let parsed_hash = PasswordHash::new(&hash).unwrap();
///
/// assert!(verify_password(password, &parsed_hash).is_ok());
/// assert!(verify_password("dontpwnme", &parsed_hash).is_err());
/// ```
///
/// # Errors
/// Throws an error if the password is wrong.
pub fn verify_password(
    password: &str,
    hash: &pbkdf2::password_hash::PasswordHash,
) -> Result<(), pbkdf2::password_hash::Error> {
    pbkdf2::Pbkdf2.verify_password(password.as_bytes(), hash)
}

#[repr(transparent)]
#[derive(Debug)]
pub struct PasswordFeedback(pub Feedback);

impl Display for PasswordFeedback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(warning) = self.0.warning() {
            writeln!(f, "{}", warning)?;
        }

        for suggestion in self.0.suggestions() {
            writeln!(f, "{}", suggestion)?;
        }

        Ok(())
    }
}

impl From<Feedback> for PasswordFeedback {
    fn from(f: Feedback) -> Self {
        Self(f)
    }
}

impl From<&Feedback> for PasswordFeedback {
    fn from(f: &Feedback) -> Self {
        Self(f.to_owned())
    }
}
