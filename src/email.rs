use lettre::{
    smtp::authentication::{Credentials, Mechanism},
    SmtpClient, SmtpTransport, Transport,
};
use lettre_email::{EmailBuilder, Mailbox};

use crate::{result::Result, token::VerificationToken, DbConn};

const FROM: (&str, &str) = ("system@skolorna.com", "Skolorna");
const REPLY_TO: &str = "hej@skolorna.com";

#[derive(Debug, Clone)]
pub struct SmtpConnSpec {
    host: String,
    username: String,
    password: String,
}

impl SmtpConnSpec {
    #[must_use]
    pub fn new(host: String, username: String, password: String) -> Self {
        Self {
            host,
            username,
            password,
        }
    }

    #[must_use]
    pub fn create_transport(&self) -> SmtpTransport {
        let client = SmtpClient::new_simple(&self.host)
            .expect("couldn't create smtp client")
            .authentication_mechanism(Mechanism::Plain)
            .credentials(Credentials::new(
                self.username.clone(),
                self.password.clone(),
            ));

        client.transport()
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

    let mut transport = smtp.create_transport();

    transport.send(email.into())?;

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
