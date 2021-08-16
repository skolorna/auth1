use lettre::{
    smtp::authentication::{Credentials, Mechanism},
    SmtpClient, SmtpTransport, Transport,
};
use lettre_email::{EmailBuilder, Mailbox};

use crate::result::Result;

const FROM: (&str, &str) = ("system@skolorna.com", "Skolorna");
const REPLY_TO: &str = "hej@skolorna.com";

#[derive(Debug, Clone)]
pub struct SmtpConnSpec {
    host: String,
    username: String,
    password: String,
}

impl SmtpConnSpec {
    pub fn new(host: String, username: String, password: String) -> Self {
        Self {
            host,
            username,
            password,
        }
    }

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

pub fn send_email_confirmation(smtp: &SmtpConnSpec, mailbox: impl Into<Mailbox>) -> Result<()> {
    send_email(
        smtp,
        mailbox,
        "Bekräfta din e-postadress".into(),
        r#"Välkommen till Skolorna!

Tryck på länken nedan för att bekräfta din e-postadress:

https://www.youtube.com/watch?v=dQw4w9WgXcQ"#
            .into(),
    )?;

    Ok(())
}
