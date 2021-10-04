use pbkdf2::password_hash::PasswordVerifier;

/// Hash and salt a password.
/// ```
/// use auth1::crypto::hash_password;
///
/// let p = b"gru";
/// assert_ne!(hash_password(p).unwrap(), hash_password(p).unwrap());
/// ```
///
/// # Errors
/// The function throws an error if the hashing fails.
pub fn hash_password(password: &[u8]) -> Result<String, pbkdf2::password_hash::Error> {
    use pbkdf2::{
        password_hash::{PasswordHasher, SaltString},
        Pbkdf2,
    };
    use rand_core::OsRng;

    let salt = SaltString::generate(&mut OsRng);

    Ok(Pbkdf2.hash_password_simple(password, &salt)?.to_string())
}

/// Compare a password against a hashed value.
/// ```
/// use pbkdf2::password_hash::PasswordHash;
/// use auth1::crypto::{hash_password, verify_password};
///
/// let password = b"d0ntpwnme";
/// let hash = hash_password(password).unwrap();
/// let parsed_hash = PasswordHash::new(&hash).unwrap();
///
/// assert!(verify_password(password, &parsed_hash).is_ok());
/// assert!(verify_password(b"dontpwnme", &parsed_hash).is_err());
/// ```
///
/// # Errors
/// Throws an error if the password is wrong.
pub fn verify_password(
    password: &[u8],
    hash: &pbkdf2::password_hash::PasswordHash,
) -> Result<(), pbkdf2::password_hash::Error> {
    pbkdf2::Pbkdf2.verify_password(password, hash)
}
