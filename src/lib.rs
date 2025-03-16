//! Parse and validate initData for Telegram Mini Apps

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde::Deserialize;

pub enum Error {
    InvalidHash,
    MissingField(&'static str),
    InvalidJson(&'static str, serde_json::Error),
    InvalidNumericField(&'static str),
}

#[derive(Debug)]
pub struct WebAppInitData {
    // query_id: Option<String>,
    user: Option<WebAppUser>,
    receiver: Option<WebAppUser>,
    // chat: Option<String>,
    // chat_type: Option<String>,
    // chat_instance: Option<String>,
    // start_param: Option<String>,
    // can_send_after: Option<i64>,
    auth_date: u64,
}

#[derive(Debug, Deserialize)]
pub struct WebAppUser {
    id: i64,
    is_bot: Option<bool>,
    first_name: String,
    last_name: Option<String>,
    username: Option<String>,
    language_code: Option<String>,
    #[serde(default)]
    is_premium: bool,
    #[serde(default)]
    added_to_attachment_menu: bool,
    #[serde(default)]
    allows_write_to_pm: bool,
    photo_url: Option<String>,
}

impl WebAppInitData {
    pub fn new(token: &str, raw: &[u8]) -> Result<Self, Error> {
        let mut decoded: BTreeMap<_, _> = form_urlencoded::parse(raw).collect();
        let hash = decoded.remove("hash").ok_or(Error::MissingField("hash"))?;

        let mut data_check_string = String::new();
        for (k, v) in &decoded {
            if !data_check_string.is_empty() {
                data_check_string.push('\n');
            }
            data_check_string.push_str(k);
            data_check_string.push('=');
            data_check_string.push_str(v);
        }

        let secret_key = hmac_sha256::HMAC::mac(token, "WebAppData");
        let actual_hash = hmac_sha256::HMAC::mac(&data_check_string, secret_key);
        if hex(&actual_hash) != *hash {
            return Err(Error::InvalidHash);
        }

        Ok(WebAppInitData {
            user: decoded
                .remove("user")
                .map(|x| serde_json::from_str(&x))
                .transpose()
                .map_err(|e| Error::InvalidJson("user", e))?,
            receiver: decoded
                .remove("receiver")
                .map(|x| serde_json::from_str(&x))
                .transpose()
                .map_err(|e| Error::InvalidJson("receiver", e))?,
            auth_date: decoded
                .remove("auth_date")
                .ok_or(Error::MissingField("auth_date"))?
                .parse()
                .map_err(|_e| Error::InvalidNumericField("auth_date"))?,
        })
    }

    pub fn user(&self) -> Option<&WebAppUser> {
        self.user.as_ref()
    }

    pub fn receiver(&self) -> Option<&WebAppUser> {
        self.receiver.as_ref()
    }

    pub fn elapsed_since_auth(&self) -> Option<Duration> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()?
            .as_secs();
        let secs = now.checked_sub(self.auth_date)?;
        Some(Duration::from_secs(secs))
    }
}

impl WebAppUser {
    pub fn id(&self) -> i64 {
        self.id
    }

    pub fn is_bot(&self) -> Option<bool> {
        self.is_bot
    }

    pub fn first_name(&self) -> &str {
        &self.first_name
    }

    pub fn last_name(&self) -> Option<&str> {
        self.last_name.as_deref()
    }

    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub fn language_code(&self) -> Option<&str> {
        self.language_code.as_deref()
    }

    pub fn is_premium(&self) -> bool {
        self.is_premium
    }

    pub fn added_to_attachment_menu(&self) -> bool {
        self.added_to_attachment_menu
    }

    pub fn allows_write_to_pm(&self) -> bool {
        self.allows_write_to_pm
    }

    pub fn photo_url(&self) -> Option<&str> {
        self.photo_url.as_deref()
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(result, "{byte:02x}");
    }
    result
}
