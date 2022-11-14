use std::{fmt::Display, str::FromStr};

use crate::{http::Result, oob::Otp};
use handlebars::Handlebars;

use lettre::{
    message::{Mailbox, MessageBuilder, MultiPart},
    AsyncFileTransport, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::Serialize;
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
    login_url: LoginUrl,
}

impl Templates {
    pub fn new(login_url: LoginUrl) -> Self {
        Self {
            hbs: Handlebars::new(),
            login_url,
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
    pub fn login(&self, otp: Otp) -> Result<(String, String)> {
        #[derive(Debug, Serialize)]
        struct Data<'a> {
            url: &'a str,
            otp: Otp,
        }

        let url = &self.login_url.format(otp);

        let data = Data { url, otp };

        let html = self.hbs.render("login-html", &data)?;
        let plain = self.hbs.render("login-plain", &data)?;

        Ok((html, plain))
    }
}

#[derive(Debug, Clone)]
pub struct LoginUrl {
    before: String,
    after: String,
}

#[derive(Debug, thiserror::Error)]
pub struct ParseLoginUrlError;

impl Display for ParseLoginUrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "missing `{{otp}}`")
    }
}

impl FromStr for LoginUrl {
    type Err = ParseLoginUrlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (before, after) = s.split_once("{otp}").ok_or(ParseLoginUrlError)?;
        Ok(Self {
            before: before.into(),
            after: after.into(),
        })
    }
}

impl LoginUrl {
    fn format(&self, otp: Otp) -> String {
        format!("{}{otp}{}", self.before, self.after)
    }
}

pub struct Client {
    pub(crate) from: Mailbox,
    pub(crate) reply_to: Option<Mailbox>,
    pub(crate) transport: Transport,
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
}

#[instrument(skip_all, fields(%to, first))]
pub async fn send_login_email(client: &Client, to: Mailbox, otp: Otp) -> Result<()> {
    let (html, plain) = client.templates.login(otp)?;

    let email = client
        .msg_builder()
        .to(to)
        .subject("Logga in på Skolorna")
        .multipart(MultiPart::alternative_plain_html(plain, html))?;

    client.send(email).await?;

    Ok(())
}
