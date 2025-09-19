use serde::Deserialize;
use std::net::IpAddr;

const POST_URL: &str = "https://www.google.com/recaptcha/api/siteverify";

/// Error returned when ReCaptcha verification fails
#[derive(Debug)]
pub enum RecaptchaError {
    Unknown(Option<String>),
    HttpError(reqwest::Error),
    MissingInputSecret,
    InvalidInputSecret,
    MissingInputResponse,
    InvalidInputResponse,
    BadRequest,
    TimeoutOrDuplicate,
}

impl TryFrom<String> for RecaptchaError {
    type Error = RecaptchaError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(match value.as_str() {
            "missing-input-secret" => RecaptchaError::MissingInputSecret,
            "invalid-input-secret" => RecaptchaError::InvalidInputSecret,
            "missing-input-response" => RecaptchaError::MissingInputResponse,
            "invalid-input-response" => RecaptchaError::InvalidInputResponse,
            "bad-request" => RecaptchaError::BadRequest,
            "timeout-or-duplicate" => RecaptchaError::TimeoutOrDuplicate,
            _ => RecaptchaError::Unknown(Some(value)),
        })
    }
}

#[derive(Deserialize, Debug, Clone)]
struct RecaptchaResult {
    success: bool,
    // challenge_ts: Option<String>,
    // hostname: Option<String>,
    // apk_package_name: Option<String>,
    #[serde(rename(deserialize = "error-codes"))]
    error_codes: Option<Vec<String>>,
}

/// # Verify ReCaptcha V2 and V3
///
/// This is supposed to be a (near) drop-in replacement for recaptcha-rs but using more recent
/// versions of tokio, reqwest and serde.
///
/// ## Minimalist Example
///
/// Basic starting point.
///
/// ```ignore
/// use recaptcha_verify::{RecaptchaError, verify_v3};
///
/// let res:Result<(), RecaptchaError> = verify_v3("secret", "token", None).await;
/// ```
///
/// ## Full Example
///
/// End-to-end real-life use with actix and result handling.
///
/// ```rust
/// #[tokio::main]
/// async fn main() {
///     use std::net::IpAddr;
///     use recaptcha_verify::{RecaptchaError, verify_v3 as recaptcha_verify};
///
///     let recaptcha_secret_key = "secret"; // from env or config
///     let recaptcha_token = "token"; // from request
///     let realip_remote_addr = Some("1.1.1.1"); // actix_web::info::ConnectionInfo
///
///     let ip_addr;
///     let mut ip: Option<&IpAddr> = None;
///
///     if let Some(remote_addr) = realip_remote_addr {
///         if let Ok(ip_addr_res) = remote_addr.to_string().parse::<IpAddr>() {
///             ip_addr = ip_addr_res;
///             ip = Some(&ip_addr);
///         }
///     }
///
///     let res = recaptcha_verify(recaptcha_secret_key, recaptcha_token, ip).await;
///
///     if res.is_ok() {
///         assert!(matches!(res, Ok(())));
///     } else {
///         assert!(matches!(res, Err(RecaptchaError::InvalidInputResponse)));
///     }
/// }
/// ```
///
pub async fn verify_v3(
    secret: &str,
    response: &str,
    remoteip: Option<&IpAddr>,
) -> Result<(), RecaptchaError> {
    let mut params = vec![("secret", secret), ("response", response)];

    let ip_str;
    if let Some(ip) = remoteip {
        ip_str = ip.to_string();
        params.push(("remoteip", ip_str.as_str()));
    }

    let client = reqwest::Client::new();
    let response = client
        .post(POST_URL)
        .form(&params)
        .send()
        .await
        .map_err(RecaptchaError::HttpError)?;

    if let Ok(result) = response.json::<RecaptchaResult>().await {
        if result.success {
            return Ok(());
        } else if let Some(errs) = result.error_codes {
            return Err(errs
                .first()
                .ok_or(RecaptchaError::Unknown(None))?
                .to_string()
                .try_into()?);
        }
    }

    Err(RecaptchaError::Unknown(None))
}

/// # Verify ReCaptcha
///
/// This is supposed to be a (near) drop-in replacement for recaptcha-rs but using more recent
/// versions of tokio, reqwest and serde.
///
/// ## Minimalist Example
///
/// Basic starting point.
///
/// ```ignore
/// use recaptcha_verify::{RecaptchaError, verify};
///
/// let res:Result<(), RecaptchaError> = verify("secret", "token", None).await;
/// ```
///
/// ## Full Example
///
/// End-to-end real-life use with actix and result handling.
///
/// ```rust
/// #[tokio::main]
/// async fn main() {
///     #![allow(deprecated)]
///     use std::net::IpAddr;
///     use recaptcha_verify::{RecaptchaError, verify as recaptcha_verify};
///
///     let recaptcha_secret_key = "secret"; // from env or config
///     let recaptcha_token = "token"; // from request
///     let realip_remote_addr = Some("1.1.1.1"); // actix_web::info::ConnectionInfo
///
///     let ip_addr;
///     let mut ip: Option<&IpAddr> = None;
///
///     if let Some(remote_addr) = realip_remote_addr {
///         if let Ok(ip_addr_res) = remote_addr.to_string().parse::<IpAddr>() {
///             ip_addr = ip_addr_res;
///             ip = Some(&ip_addr);
///         }
///     }
///
///     let res = recaptcha_verify(recaptcha_secret_key, recaptcha_token, ip).await;
///
///     if res.is_ok() {
///         assert!(matches!(res, Ok(())));
///     } else {
///         assert!(matches!(res, Err(RecaptchaError::InvalidInputResponse)));
///     }
/// }
/// ```
///
#[deprecated(
    since = "0.2.0",
    note = "Use `recaptcha_verify::verify_v3` instead. Or migrate to enterprise and use `recaptcha_verify::verify_enterprise`."
)]
pub async fn verify(
    secret: &str,
    response: &str,
    remoteip: Option<&IpAddr>,
) -> Result<(), RecaptchaError> {
    verify_v3(secret, response, remoteip).await
}
