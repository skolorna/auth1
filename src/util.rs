use sqlx::PgExecutor;
use uuid::Uuid;

use crate::{
    http::{Error, Result},
    jwt::refresh_token,
    oob,
};

pub struct CreatedUser {
    pub id: Uuid,
    pub jwt_secret: [u8; refresh_token::SECRET_LEN],
    pub oob_secret: [u8; oob::SECRET_LEN],
}

pub async fn create_user(
    email: impl AsRef<str>,
    full_name: Option<impl AsRef<str>>,
    db: impl PgExecutor<'_>,
) -> Result<CreatedUser> {
    let id = Uuid::new_v4();
    let jwt_secret = refresh_token::gen_secret();
    let oob_secret = oob::gen_secret();

    let email = email.as_ref();
    let full_name = full_name.as_ref().map(|s| s.as_ref());

    sqlx::query!(
      r#"INSERT INTO users (id, email, full_name, jwt_secret, oob_secret) VALUES ($1, $2, $3, $4, $5)"#,
      id,
      &email,
      full_name,
      &jwt_secret,
      &oob_secret,
  )
  .execute(db)
  .await
  .map_err(|e| match e {
      sqlx::Error::Database(dbe) if dbe.constraint() == Some("users_email_key") => {
          Error::email_in_use()
      }
      e => e.into(),
  })?;

    Ok(CreatedUser {
        id,
        jwt_secret,
        oob_secret,
    })
}
