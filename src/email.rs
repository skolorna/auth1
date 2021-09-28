use std::{
    env,
    fmt::Debug,
    sync::{Arc, Mutex, MutexGuard},
};

use lettre::{
    message::Mailbox,
    transport::smtp::authentication::{Credentials, Mechanism},
    Message, SmtpTransport, Transport,
};

use crate::{errors::AppResult, models::User, rate_limit::SlidingWindow, token::VerificationToken};

#[derive(Debug, Clone)]
pub struct Emails {
    backend: EmailBackend,
}

impl Emails {
    pub fn from_env() -> Self {
        let backend = EmailBackend::Smtp {
            host: env::var("SMTP_HOST").expect("SMTP_HOST is not set"),
            username: env::var("SMTP_USERNAME").expect("SMTP_USERNAME is not set"),
            password: env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD is not set"),
            from: Mailbox::new(
                Some("Skolorna".into()),
                "system@skolorna.com".parse().unwrap(),
            ),
            reply_to: Some(Mailbox::new(None, "hej@skolorna.com".parse().unwrap())),
        };

        Self { backend }
    }

    pub fn new_in_memory() -> Self {
        Self {
            backend: EmailBackend::Memory {
                mails: Arc::new(Mutex::new(Vec::new())),
            },
        }
    }

    pub fn mails_in_memory(&self) -> Option<MutexGuard<Vec<StoredEmail>>> {
        if let EmailBackend::Memory { mails } = &self.backend {
            Some(mails.lock().unwrap())
        } else {
            None
        }
    }

    pub fn send_user_confirmation(&self, user: &User, token: VerificationToken) -> AppResult<()> {
        self.send(
            &user.mailbox(),
            "Bekräfta din e-postadress",
            format!(
                "\
    V\u{e4}lkommen till Skolorna!
                
    Tryck p\u{e5} l\u{e4}nken nedan f\u{f6}r att bekr\u{e4}fta din e-postadress:
                            
    {}",
                token
            ),
        )
    }

    fn send(&self, recipient: &Mailbox, subject: &str, body: impl ToString) -> AppResult<()> {
        let mut email = Message::builder()
            .to(recipient.clone())
            .from(self.sender_address())
            .subject(subject);

        if let Some(reply_to) = self.reply_to() {
            email = email.reply_to(reply_to.clone());
        }

        let email = email.body(body.to_string())?;

        match &self.backend {
            EmailBackend::Smtp {
                host,
                username,
                password,
                ..
            } => {
                SmtpTransport::relay(host)?
                    .credentials(Credentials::new(username.clone(), password.clone()))
                    .authentication(vec![Mechanism::Plain])
                    .build()
                    .send(&email)?;
            }
            EmailBackend::Memory { mails } => mails.lock().unwrap().push(StoredEmail {
                to: recipient.to_string(),
                subject: subject.into(),
                body: body.to_string(),
            }),
        }

        Ok(())
    }

    fn sender_address(&self) -> Mailbox {
        match &self.backend {
            EmailBackend::Smtp { ref from, .. } => from.clone(),
            EmailBackend::Memory { .. } => Mailbox::new(None, "test@localhost".parse().unwrap()),
        }
    }

    fn reply_to(&self) -> Option<&Mailbox> {
        match &self.backend {
            EmailBackend::Smtp { reply_to, .. } => reply_to.as_ref(),
            EmailBackend::Memory { .. } => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoredEmail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

#[derive(Clone)]
pub enum EmailBackend {
    Smtp {
        host: String,
        username: String,
        password: String,
        from: Mailbox,
        reply_to: Option<Mailbox>,
    },
    Memory {
        mails: Arc<Mutex<Vec<StoredEmail>>>,
    },
}

impl Debug for EmailBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Smtp { host, username, .. } => f
                .debug_struct("Smtp")
                .field("host", host)
                .field("username", username)
                .finish(),
            Self::Memory { mails: _ } => f.write_str("Memory"),
        }
    }
}

pub const EMAIL_RATE_LIMIT: SlidingWindow = SlidingWindow::new("send_email", 3600, 10);
