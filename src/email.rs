use std::collections::HashMap;

use crate::{
    http::{Error, Result},
    oob::Otp,
};
use handlebars::Handlebars;

use lettre::{
    message::{Mailbox, MessageBuilder, MultiPart},
    AsyncFileTransport, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::Serialize;
use strfmt::Format;
use tracing::{debug, instrument};

pub enum Transport {
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
    File(AsyncFileTransport<Tokio1Executor>),
}

impl Transport {
    pub async fn send(&self, message: Message) -> Result<()> {
        match self {
            Transport::Smtp(transport) => {
                transport.send(message).await?;
            }
            Transport::File(transport) => {
                transport.send(message).await?;
            }
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
    pub fn login(&self, url: &str, otp: Otp) -> Result<(String, String)> {
        #[derive(Debug, Serialize)]
        struct Data<'a> {
            url: &'a str,
            otp: Otp,
        }

        let data = Data { url, otp };

        let html = self.hbs.render("login-html", &data)?;
        let plain = self.hbs.render("login-plain", &data)?;

        Ok((html, plain))
    }
}

pub struct Client {
    pub(crate) from: Mailbox,
    pub(crate) reply_to: Option<Mailbox>,
    pub(crate) transport: Transport,
    pub(crate) login_url: String,
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
    pub fn login_url(&self, otp: &str) -> Result<String, strfmt::FmtError> {
        let mut vars = HashMap::new();
        vars.insert("otp".to_string(), otp);
        self.login_url.format(&vars)
    }
}

#[instrument(skip_all, fields(%to, first))]
pub async fn send_login_email(client: &Client, to: Mailbox, otp: Otp) -> Result<()> {
    let url = client
        .login_url(&otp.to_string())
        .map_err(|_| Error::internal())?;

    let (html, plain) = client.templates.login(&url, otp)?;

    let email = client
        .msg_builder()
        .to(to)
        .subject("Logga in på Skolorna")
        .multipart(MultiPart::alternative_plain_html(plain, html))?;

    client.send(email).await?;

    Ok(())
}
