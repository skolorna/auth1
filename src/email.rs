use std::env;

use lettre::{
    smtp::authentication::{Credentials, Mechanism},
    SendableEmail, SmtpClient, Transport,
};
use lettre_email::{EmailBuilder, Mailbox};

use crate::{result::Result, token::VerificationToken, DbConn};

const FROM: (&str, &str) = ("system@skolorna.com", "Skolorna");
const REPLY_TO: &str = "hej@skolorna.com";

#[derive(Debug, Clone)]
pub enum SmtpConnSpec {
    BasicAuth {
        host: String,
        username: String,
        password: String,
    },
    Testing,
}

impl SmtpConnSpec {
    pub fn from_env() -> Self {
        Self::BasicAuth {
            host: env::var("SMTP_HOST").expect("SMTP_HOST is not set"),
            username: env::var("SMTP_USERNAME").expect("SMTP_USERNAME is not set"),
            password: env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD is not set"),
        }
    }

    pub fn send(&self, email: SendableEmail) -> Result<()> {
        match self {
            SmtpConnSpec::BasicAuth {
                host,
                username,
                password,
            } => {
                let client = SmtpClient::new_simple(host)
                    .expect("couldn't create smtp client")
                    .authentication_mechanism(Mechanism::Plain)
                    .credentials(Credentials::new(username.clone(), password.clone()));

                client.transport().send(email)?;

                Ok(())
            }
            SmtpConnSpec::Testing => Ok(()),
        }
    }
}

pub fn send_email(
    smtp: &SmtpConnSpec,
    mailbox: impl Into<Mailbox>,
    subject: String,
    text: String,
) -> Result<()> {
    let email = EmailBuilder::new()
        .from(FROM)
        .reply_to(REPLY_TO)
        .to(mailbox)
        .subject(subject)
        .text(text)
        .build()?;

    smtp.send(email.into())?;

    Ok(())
}

pub fn send_welcome_email(
    db_conn: &DbConn,
    smtp: &SmtpConnSpec,
    mailbox: impl Into<Mailbox>,
) -> Result<()> {
    let mailbox: Mailbox = mailbox.into();
    let token = VerificationToken::generate(db_conn, &mailbox.address)?;

    println!("generated token: {}", token);

    // FIXME: Don't use localhost...
    send_email(
        smtp,
        mailbox,
        "Bekr\u{e4}fta din e-postadress".into(),
        format!(
            "\
V\u{e4}lkommen till Skolorna!
            
Tryck p\u{e5} l\u{e4}nken nedan f\u{f6}r att bekr\u{e4}fta din e-postadress:
                        
{}",
            token
        ),
    )?;

    Ok(())
}
