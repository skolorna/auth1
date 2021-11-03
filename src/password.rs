use std::fmt::Display;

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use zxcvbn::feedback::Feedback;

use crate::errors::{AppError, AppResult};

/// Hash and salt a password.
/// ```
/// use auth1::password::hash_password;
///
/// let p = "Fel0n1ou$Grü";
/// assert_ne!(hash_password(p).unwrap(), hash_password(p).unwrap());
/// assert!(hash_password("Gru").is_err()); // too weak
/// ```
///
/// # Errors
/// This function returns [Err] if:
/// - the password isn't strong enough
/// - the hashing fails
pub fn hash_password(password: &str) -> AppResult<String> {
    let entropy = zxcvbn::zxcvbn(password, &[])?;

    if entropy.score() >= 3 {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

        Ok(hash)
    } else {
        Err(AppError::WeakPassword {
            feedback: entropy.feedback().as_ref().map(|f| f.into()),
        })
    }
}

/// Compare a password against a hashed value.
/// ```
/// use argon2::password_hash::PasswordHash;
/// use auth1::password::{hash_password, verify_password};
///
/// let password = "d0ntpwnme";
/// let hash = hash_password(password).unwrap();
///
/// assert!(verify_password(password, &hash).is_ok());
/// assert!(verify_password("dontpwnme", &hash).is_err());
/// ```
///
/// # Errors
/// Fails if the password is invalid or the hash cannot be parsed.
pub fn verify_password(password: &str, hash: &str) -> Result<(), argon2::password_hash::Error> {
    let hash = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();

    argon2.verify_password(password.as_bytes(), &hash)
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
        Self(f.clone())
    }
}

#[cfg(test)]
mod tests {
    use zxcvbn::zxcvbn;

    use super::*;

    #[test]
    fn display_feedback() {
        let feedback: PasswordFeedback = zxcvbn("abc123", &[])
            .unwrap()
            .feedback()
            .as_ref()
            .unwrap()
            .into();

        assert_eq!(
            feedback.to_string(),
            "This is similar to a commonly used password.\n\
                Add another word or two. Uncommon words are better.\n\
                Reversed words aren't much harder to guess.\n"
        );
    }
}
