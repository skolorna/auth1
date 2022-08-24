use crate::http::Result;
use lettre::{
    message::{Mailbox, SinglePart}, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

pub async fn send_confirmation_email(
    smtp: &AsyncSmtpTransport<Tokio1Executor>,
    to: Mailbox,
) -> Result<()> {
    let email = Message::builder()
        .from("system@skolorna.com".parse().unwrap())
        .to(to)
        .subject("Välkommen")
        .singlepart(SinglePart::plain("Välkommen 🥫".to_string()))?;

    smtp.send(email).await?;

    Ok(())
}
