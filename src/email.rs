use lettre::{
    smtp::authentication::{Credentials, Mechanism},
    SmtpClient, SmtpTransport, Transport,
};
use lettre_email::{EmailBuilder, Mailbox};

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

    pub fn transport(&self) -> SmtpTransport {
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

pub fn send_email(smtp: &SmtpConnSpec, mailbox: impl Into<Mailbox>, subject: String, text: String) {
    let email = EmailBuilder::new()
        .from(FROM)
        .reply_to(REPLY_TO)
        .to(mailbox)
        .subject(subject)
        .text(text)
        .build()
        .unwrap();

    let mut transport = smtp.transport();

    transport.send(email.into()).expect("failed to send email");
}

pub fn send_email_confirmation(smtp: &SmtpConnSpec, mailbox: impl Into<Mailbox>) {
    send_email(
        smtp,
        mailbox,
        "Bekräfta din e-postadress".to_owned(),
        r#"Välkommen till Skolorna!

Tryck på länken nedan för att bekräfta din e-postadress:

https://www.youtube.com/watch?v=dQw4w9WgXcQ"#
            .to_owned(),
    );
}
