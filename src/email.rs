use std::collections::HashMap;

use crate::http::{Error, Result};
use handlebars::Handlebars;
use indoc::formatdoc;
use lettre::{
    message::{Mailbox, MessageBuilder, MultiPart, SinglePart},
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::Serialize;
use strfmt::Format;
use tracing::{debug, instrument};

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

pub struct Templates {
    hbs: Handlebars<'static>,
}

impl Default for Templates {
    fn default() -> Self {
        Self::new()
    }
}

impl Templates {
    pub fn new() -> Self {
        Self {
            hbs: Handlebars::new(),
        }
    }

    pub fn insert(&mut self, name: &str, mjml: &str, plain: &str) -> anyhow::Result<()> {
        let html = mrml::parse(mjml)
            .unwrap()
            .render(&Default::default())
            .unwrap();
        self.hbs
            .register_template_string(&format!("{name}-html"), html)?;
        self.hbs
            .register_template_string(&format!("{name}-plain"), plain)?;
        Ok(())
    }

    #[instrument(level = "debug", skip(self), ret)]
    pub fn login(&self, url: &str) -> Result<(String, String)> {
        #[derive(Debug, Serialize)]
        struct Data<'a> {
            url: &'a str,
        }

        let data = Data { url };

        let html = self.hbs.render("login-html", &data)?;
        let plain = self.hbs.render("login-plain", &data)?;

        Ok((html, plain))
    }
}

pub struct Client {
    pub(crate) from: Mailbox,
    pub(crate) reply_to: Option<Mailbox>,
    pub(crate) transport: Transport,
    pub(crate) verification_url: String,
    pub(crate) password_reset_url: String,
    pub(crate) templates: Templates,
}

impl Client {
    pub async fn send(&self, message: Message) -> Result<()> {
        debug!("sending email");

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

    #[instrument(skip_all, fields(self.password_reset_url), err)]
    pub fn password_reset_url(&self, token: &str) -> Result<String, strfmt::FmtError> {
        let mut vars = HashMap::new();
        vars.insert("token".to_string(), token);
        self.password_reset_url.format(&vars)
    }
}

#[instrument(skip_all, fields(%to, first))]
pub async fn send_login_email(
    client: &Client,
    to: Mailbox,
    token: &str,
    first: bool,
) -> Result<()> {
    let subject = if first {
        "Välkommen till Skolorna"
    } else {
        "Bekräfta din e-postadress"
    };

    let url = client
        .verification_url(token)
        .map_err(|_| Error::internal())?;

    let (html, plain) = client.templates.login(&url)?;

    let email = client
        .msg_builder()
        .to(to)
        .subject(subject)
        .multipart(MultiPart::alternative_plain_html(plain, html))?;

    client.send(email).await?;

    Ok(())
}

pub async fn send_password_reset_email(
    client: &Client,
    to: Mailbox,
    reset_token: &str,
) -> Result<()> {
    let url = client
        .password_reset_url(reset_token)
        .map_err(|_| Error::internal())?;

    let email = client
        .msg_builder()
        .to(to)
        .subject("Återställ ditt lösenord")
        .singlepart(SinglePart::plain(formatdoc! {"
            Någon har begärt att ditt lösenord ska återställas. (Du kan ignorera det här meddelandet om det inte var du.)

            Klicka på länken nedan för att återställa ditt lösenord:

            {url}
        "}))?;

    client.send(email).await?;

    Ok(())
}
