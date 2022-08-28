use crate::http::Result;
use lettre::{
    message::{Mailbox, SinglePart},
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

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
}

impl Client {
    pub async fn send(&self, message: Message) -> Result<()> {
        self.transport.send(message).await
    }
}

pub async fn send_confirmation_email(
    client: &Client,
    to: Mailbox,
    verification_token: &str,
) -> Result<()> {
    let email = Message::builder()
        .from(client.from.clone())
        .to(to)
        .subject("Välkommen")
        .singlepart(SinglePart::plain(format!(
            "Välkommen 🥫 {verification_token}"
        )))?;

    client.send(email).await?;

    Ok(())
}
