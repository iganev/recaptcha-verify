use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashMap, fmt::Display};

/// Optional user action for additional verification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecaptchaUserAction {
    /// Sign up on the website.
    Signup,
    /// Log in to the website.
    Login,
    /// Request to reset the password.
    PasswordReset,
    /// Fetch price for an item.
    GetPrice,
    /// Add items to the cart.
    CartAdd,
    /// View the contents of the cart.
    CartView,
    /// Add or update payment information (e.g. card details or address).
    PaymentAdd,
    /// Check out from the website.
    Checkout,
    /// Confirmation that a transaction was processed.
    TransactionConfirmed,
    /// Play a song from a list.
    PlaySong,
}

impl TryFrom<String> for RecaptchaUserAction {
    type Error = RecaptchaEntError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "signup" => Ok(RecaptchaUserAction::Signup),
            "login" => Ok(RecaptchaUserAction::Login),
            "password_reset" => Ok(RecaptchaUserAction::PasswordReset),
            "get_price" => Ok(RecaptchaUserAction::GetPrice),
            "cart_add" => Ok(RecaptchaUserAction::CartAdd),
            "cart_view" => Ok(RecaptchaUserAction::CartView),
            "payment_add" => Ok(RecaptchaUserAction::PaymentAdd),
            "checkout" => Ok(RecaptchaUserAction::Checkout),
            "transaction_confirmed" => Ok(RecaptchaUserAction::TransactionConfirmed),
            "play_song" => Ok(RecaptchaUserAction::PlaySong),
            _ => Err(RecaptchaEntError::InvalidUserAction(value)),
        }
    }
}

impl Display for RecaptchaUserAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecaptchaUserAction::Signup => write!(f, "signup"),
            RecaptchaUserAction::Login => write!(f, "login"),
            RecaptchaUserAction::PasswordReset => write!(f, "password_reset"),
            RecaptchaUserAction::GetPrice => write!(f, "get_price"),
            RecaptchaUserAction::CartAdd => write!(f, "cart_add"),
            RecaptchaUserAction::CartView => write!(f, "cart_view"),
            RecaptchaUserAction::PaymentAdd => write!(f, "payment_add"),
            RecaptchaUserAction::Checkout => write!(f, "checkout"),
            RecaptchaUserAction::TransactionConfirmed => write!(f, "transaction_confirmed"),
            RecaptchaUserAction::PlaySong => write!(f, "play_song"),
        }
    }
}

/// Reason why the verification failed
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecaptchaInvalidReason {
    /// The interaction matches the behavior of an automated agent.
    Automation,
    /// The event originated from an illegitimate environment.
    UnexpectedEnvironment,
    /// Traffic volume from the event source is higher than normal.
    TooMuchTraffic,
    /// The interaction with your site was significantly different from expected patterns.
    UnexpectedUsagePatterns,
    /// Too little traffic was received from this site to generate quality risk analysis.
    LowConfidenceScore,
    /// This one is not in the documentation, but basically means invalid token
    Malformed,
}

impl TryFrom<String> for RecaptchaInvalidReason {
    type Error = RecaptchaEntError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "AUTOMATION" => Ok(RecaptchaInvalidReason::Automation),
            "UNEXPECTED_ENVIRONMENT" => Ok(RecaptchaInvalidReason::UnexpectedEnvironment),
            "TOO_MUCH_TRAFFIC" => Ok(RecaptchaInvalidReason::TooMuchTraffic),
            "UNEXPECTED_USAGE_PATTERNS" => Ok(RecaptchaInvalidReason::UnexpectedUsagePatterns),
            "LOW_CONFIDENCE_SCORE" => Ok(RecaptchaInvalidReason::LowConfidenceScore),
            "MALFORMED" => Ok(RecaptchaInvalidReason::Malformed),
            _ => Err(RecaptchaEntError::UnknownReason),
        }
    }
}

impl Display for RecaptchaInvalidReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecaptchaInvalidReason::Automation => write!(f, "AUTOMATION"),
            RecaptchaInvalidReason::UnexpectedEnvironment => write!(f, "UNEXPECTED_ENVIRONMENT"),
            RecaptchaInvalidReason::TooMuchTraffic => write!(f, "TOO_MUCH_TRAFFIC"),
            RecaptchaInvalidReason::UnexpectedUsagePatterns => {
                write!(f, "UNEXPECTED_USAGE_PATTERNS")
            }
            RecaptchaInvalidReason::LowConfidenceScore => write!(f, "LOW_CONFIDENCE_SCORE"),
            RecaptchaInvalidReason::Malformed => write!(f, "MALFORMED"),
        }
    }
}

/// Error returned when ReCaptcha verification fails
#[derive(Debug)]
pub enum RecaptchaEntError {
    InvalidUserAction(String),
    InvalidReason(RecaptchaInvalidReason),
    UnknownReason,
    ApiError(RecaptchaEntApiResponse),
    HttpError(reqwest::Error),
    DecodingError(serde_json::Error),
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RecaptchaEntApiResponse {
    pub error: RecaptchaEntApiError,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RecaptchaEntApiError {
    pub code: u32,
    pub message: String,
    pub status: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RecaptchaEntEvent {
    pub token: String,
    pub site_key: String,
    pub user_agent: String,
    pub user_ip_address: String,
    pub expected_action: Option<RecaptchaUserAction>,
    #[serde(flatten)]
    pub extras: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RecaptchaEntRiskAnalysis {
    pub score: f32,
    pub challenge: String,
    pub reasons: Vec<String>,
    #[serde(flatten)]
    pub extras: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RecaptchaEntTokenProps {
    pub valid: bool,
    pub invalid_reason: Option<RecaptchaInvalidReason>,
    pub action: Option<RecaptchaUserAction>,
    #[serde(flatten)]
    pub extras: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RecaptchaEntResult {
    pub name: String,
    pub event: RecaptchaEntEvent,
    pub risk_analysis: RecaptchaEntRiskAnalysis,
    pub token_properties: RecaptchaEntTokenProps,
}

pub async fn verify_enterprise(
    project: &str,
    api_key: &str,
    site_key: &str,
    token: &str,
    action: Option<RecaptchaUserAction>,
) -> Result<(), RecaptchaEntError> {
    let result = verify_enterprise_detailed(project, api_key, site_key, token, action).await?;

    if result.token_properties.valid {
        Ok(())
    } else if let Some(reason) = result.token_properties.invalid_reason {
        Err(RecaptchaEntError::InvalidReason(reason))
    } else {
        Err(RecaptchaEntError::UnknownReason)
    }
}

pub async fn verify_enterprise_detailed(
    project: &str,
    api_key: &str,
    site_key: &str,
    token: &str,
    action: Option<RecaptchaUserAction>,
) -> Result<RecaptchaEntResult, RecaptchaEntError> {
    let request = json!({
        "event": {
            "token": &token,
            "site_key": &site_key,
            "expected_action": action.map(|a| a.to_string())
        }
    });

    let client = reqwest::Client::new();
    let response = client
        .post(format!("https://recaptchaenterprise.googleapis.com/v1/projects/{project}/assessments?key={api_key}"))
        .json(&request)
        .send()
        .await
        .map_err(RecaptchaEntError::HttpError)?;

    let response_body = response
        .text()
        .await
        .map_err(RecaptchaEntError::HttpError)?;

    match serde_json::from_str::<RecaptchaEntResult>(&response_body) {
        Ok(result) => Ok(result),
        Err(_) => {
            let err_response = serde_json::from_str::<RecaptchaEntApiResponse>(&response_body)
                .map_err(RecaptchaEntError::DecodingError)?;

            Err(RecaptchaEntError::ApiError(err_response))
        }
    }
}
