use std::{
    fmt::Display,
    str::{Chars, FromStr},
};

use base64::display::Base64Display;
use mime::Mime;
use serde::{de, Deserialize};
use thiserror::Error;

#[derive(Debug)]
pub struct DataUri {
    pub media_type: Option<Mime>,
    pub b64: bool,
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
            Body::Str(raw_body)
        };

        Ok(Self {
            media_type,
            b64,
            body,
        })
    }
}

impl Display for DataUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "data:")?;

        if let Some(mime) = &self.media_type {
            write!(f, "{}", mime)?;
        }

        if self.b64 {
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

#[derive(Debug)]
pub enum Body {
    Binary(Vec<u8>),
    Str(String),
}

impl Display for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Body::Binary(vec) => {
                write!(f, "{}", Base64Display::with_config(vec, base64::STANDARD))
            }
            Body::Str(str) => write!(f, "{}", str),
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
            DataUri::from_str("data:text/plain;charset=UTF-8,Hello")
                .unwrap()
                .body
                .to_string(),
            "Hello"
        );
    }
}
