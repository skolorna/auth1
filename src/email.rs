use std::{
    env,
    fmt::Debug,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

use lettre::{
    message::Mailbox,
    transport::smtp::authentication::{Credentials, Mechanism},
    FileTransport, Message, SmtpTransport, Transport,
};

use crate::{
    errors::{AppError, AppResult},
    models::User,
    rate_limit::SlidingWindow,
    token::VerificationToken,
};

#[derive(Debug, Clone)]
pub struct Emails {
    backend: EmailBackend,
    from: Mailbox,
    reply_to: Option<Mailbox>,
}

impl Emails {
    pub fn from_env() -> Self {
        let backend = match (
            env::var("SMTP_HOST"),
            env::var("SMTP_PASSWORD"),
            env::var("SMTP_PASSWORD"),
        ) {
            (Ok(host), Ok(username), Ok(password)) => EmailBackend::Smtp {
                host,
                username,
                password,
            },
            _ => EmailBackend::FileSystem {
                path: "/tmp".parse().unwrap(),
            },
        };

        Self {
            backend,
            from: Mailbox::new(
                Some("Skolorna".into()),
                "system@skolorna.com".parse().unwrap(),
            ),
            reply_to: Some(Mailbox::new(None, "hej@skolorna.com".parse().unwrap())),
        }
    }

    pub fn new_in_memory() -> Self {
        Self {
            backend: EmailBackend::Memory {
                mails: Arc::new(Mutex::new(Vec::new())),
            },
            from: Mailbox::new(None, "test@localhost".parse().unwrap()),
            reply_to: None,
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
            .from(self.from.clone())
            .subject(subject);

        if let Some(reply_to) = self.reply_to.as_ref() {
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
            EmailBackend::FileSystem { path } => {
                FileTransport::new(path)
                    .send(&email)
                    .map_err(|_| AppError::InternalError {
                        cause: "Failed to save email file".into(),
                    })?;
            }
            EmailBackend::Memory { mails } => mails.lock().unwrap().push(StoredEmail {
                to: recipient.to_string(),
                subject: subject.into(),
                body: body.to_string(),
            }),
        }

        Ok(())
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
    },
    FileSystem {
        path: PathBuf,
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
            Self::FileSystem { path } => f.debug_struct("FileSystem").field("path", path).finish(),
            Self::Memory { mails: _ } => f.write_str("Memory"),
        }
    }
}

pub const EMAIL_RATE_LIMIT: SlidingWindow = SlidingWindow::new("send_email", 3600, 10);
