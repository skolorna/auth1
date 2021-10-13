use std::{
    fmt::Display,
    str::{Chars, FromStr},
    string::FromUtf8Error,
};

use base64::display::Base64Display;
use mime::Mime;
use serde::{de, Deserialize};
use thiserror::Error;

#[derive(Debug)]
pub struct DataUri {
    pub media_type: Option<Mime>,
    pub body: Body,
}

#[derive(Debug, Error)]
pub enum FromStrError {
    #[error("invalid scheme")]
    InvalidScheme,

    #[error("invalid media type: {0}")]
    InvalidMediaType(#[from] mime::FromStrError),

    #[error("decode base64 error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("unicode parse error: {0}")]
    UnicodeError(#[from] FromUtf8Error),
}

macro_rules! require {
    ($condition:expr) => {
        if !$condition {
            return None;
        }
    };
}

fn consume_scheme(iter: &mut Chars) -> Option<()> {
    require!(iter.next()? == 'd');
    require!(iter.next()? == 'a');
    require!(iter.next()? == 't');
    require!(iter.next()? == 'a');
    require!(iter.next()? == ':');

    Some(())
}

fn before_comma(iter: &mut Chars) -> String {
    let mut str = String::new();

    for c in iter {
        if c == ',' {
            break;
        }

        str.push(c);
    }

    str
}

impl FromStr for DataUri {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.chars();

        consume_scheme(&mut iter).ok_or(FromStrError::InvalidScheme)?;

        let before_comma = before_comma(&mut iter);

        let b64 = before_comma.ends_with(";base64");

        let end = before_comma.len() - if b64 { 7 } else { 0 };
        let mime_str = &before_comma[0..end];
        let media_type: Option<Mime> = if mime_str.is_empty() {
            None
        } else {
            Some(mime_str.parse().map_err(FromStrError::InvalidMediaType)?)
        };

        let raw_body: String = iter.collect();

        let body = if b64 {
            Body::Binary(base64::decode(&raw_body).map_err(FromStrError::Base64DecodeError)?)
        } else {
            let text = urlencoding::decode(&raw_body)?;
            Body::Text(text.into_owned())
        };

        Ok(Self { media_type, body })
    }
}

impl Display for DataUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "data:")?;

        if let Some(mime) = &self.media_type {
            write!(f, "{}", mime.essence_str())?;

            for (param, value) in mime.params() {
                write!(f, ";{}={}", param, value)?;
            }
        }

        if self.body.is_b64() {
            write!(f, ";base64")?;
        }

        write!(f, ",{}", self.body)
    }
}

impl<'de> Deserialize<'de> for DataUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Body {
    Binary(Vec<u8>),
    Text(String),
}

impl Body {
    pub fn is_b64(&self) -> bool {
        match self {
            Body::Binary(_) => true,
            Body::Text(_) => false,
        }
    }
}

impl Display for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Body::Binary(vec) => {
                write!(f, "{}", Base64Display::with_config(vec, base64::STANDARD))
            }
            Body::Text(text) => write!(f, "{}", urlencoding::encode(text)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode() {
        assert!(DataUri::from_str("data :image/webp,").is_err());
        assert!(DataUri::from_str("data:application/json;base64,invalidbase64!").is_err());
        assert!(DataUri::from_str("data:image/jpeg;ohnowhereismyequalsign,mydata").is_err());

        assert_eq!(
            DataUri::from_str("data:text/plain;charset=UTF-8,Hello%20There")
                .unwrap()
                .body,
            Body::Text("Hello There".into())
        );

        assert!(DataUri::from_str("data:,").unwrap().media_type.is_none());
    }

    #[test]
    fn encode() {
        assert_eq!(
            DataUri {
                media_type: Some(mime::APPLICATION_PDF),
                body: Body::Binary(vec![0, 1, 2, 3]),
            }
            .to_string(),
            "data:application/pdf;base64,AAECAw=="
        );

        assert_eq!(
            DataUri {
                media_type: Some(mime::TEXT_PLAIN_UTF_8),
                body: Body::Text("Hello There".to_string()),
            }
            .to_string(),
            "data:text/plain;charset=utf-8,Hello%20There"
        );
    }
}
