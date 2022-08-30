use std::collections::HashMap;

use crate::http::{Error, Result};
use indoc::formatdoc;
use lettre::{
    message::{Mailbox, MessageBuilder, SinglePart},
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use strfmt::Format;
use tracing::instrument;

pub enum Transport {
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
    File,
}

impl Transport {
    pub async fn send(&self, message: Message) -> Result<()> {
        match self {
            Transport::Smtp(smtp) => {
                smtp.send(message).await?;
            }
            Transport::File => todo!(),
        }

        Ok(())
    }
}

pub struct Client {
    pub(crate) from: Mailbox,
    pub(crate) reply_to: Option<Mailbox>,
    pub(crate) transport: Transport,
    pub(crate) verification_url: String,
}

impl Client {
    pub async fn send(&self, message: Message) -> Result<()> {
        self.transport.send(message).await
    }

    pub fn msg_builder(&self) -> MessageBuilder {
        let mut builder = Message::builder().from(self.from.clone());

        if let Some(ref reply_to) = self.reply_to {
            builder = builder.reply_to(reply_to.clone());
        }

        builder
    }

    #[instrument(skip_all, fields(self.verification_url), err)]
    pub fn verification_url(&self, token: &str) -> Result<String, strfmt::FmtError> {
        let mut vars = HashMap::new();
        vars.insert("token".to_string(), token);
        self.verification_url.format(&vars)
    }
}

pub async fn send_confirmation_email(
    client: &Client,
    to: Mailbox,
    verification_token: &str,
    welcome: bool,
) -> Result<()> {
    let subject = if welcome {
        "Välkommen till Skolorna"
    } else {
        "Bekräfta din e-postadress"
    };

    let url = client
        .verification_url(verification_token)
        .map_err(|_| Error::internal())?;

    let email = client
        .msg_builder()
        .to(to)
        .subject(subject)
        .singlepart(SinglePart::plain(formatdoc! {"
            Klicka på länken nedan för att bekräfta din e-postadress:

            {url}
        "}))?;

    client.send(email).await?;

    Ok(())
}
