use std::{
    env,
    sync::{Arc, Mutex, MutexGuard},
};

use lettre::{
    smtp::authentication::{Credentials, Mechanism},
    Envelope, SendableEmail, SmtpClient, Transport,
};
use lettre_email::{EmailBuilder, Mailbox};

use crate::{models::User, rate_limit::SlidingWindow, result::Result, token::VerificationToken};

const FROM: (&str, &str) = ("system@skolorna.com", "Skolorna");
const REPLY_TO: &str = "hej@skolorna.com";

type TestInbox = Vec<(Envelope, String)>;

#[derive(Debug, Clone)]
pub enum SmtpConnection {
    BasicAuth {
        host: String,
        username: String,
        password: String,
    },
    TestInbox(Arc<Mutex<TestInbox>>),
}

impl SmtpConnection {
    pub fn from_env() -> Self {
        Self::BasicAuth {
            host: env::var("SMTP_HOST").expect("SMTP_HOST is not set"),
            username: env::var("SMTP_USERNAME").expect("SMTP_USERNAME is not set"),
            password: env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD is not set"),
        }
    }

    pub fn send(&self, email: SendableEmail) -> Result<()> {
        match self {
            SmtpConnection::BasicAuth {
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
            SmtpConnection::TestInbox(data) => {
                let mut inbox = data.lock().unwrap();
                inbox.push((
                    email.envelope().to_owned(),
                    email.message_to_string().unwrap(),
                ));
                Ok(())
            }
        }
    }

    pub fn new_test_inbox() -> Self {
        Self::TestInbox(Arc::new(Mutex::new(vec![])))
    }

    pub fn get_test_inbox(&self) -> MutexGuard<TestInbox> {
        if let Self::TestInbox(data) = self {
            data.lock().unwrap()
        } else {
            panic!();
        }
    }
}

pub fn send_email(
    smtp: &SmtpConnection,
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

pub fn send_verification_email(smtp: &SmtpConnection, user: &User) -> Result<()> {
    let mailbox: Mailbox = user.into();
    let token = VerificationToken::generate(user)?;

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

pub const EMAIL_RATE_LIMIT: SlidingWindow = SlidingWindow::new("send_email", 3600, 10);
