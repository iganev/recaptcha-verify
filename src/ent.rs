use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

/// Error returned when ReCaptcha verification fails
#[derive(Debug)]
pub enum RecaptchaEntError {
    InvalidReason(String),
    UnknownReason,
    ApiError(RecaptchaEntApiResponse),
    HttpError(reqwest::Error),
    DecodingError(serde_json::Error),
    UnexpectedResponse(String, String, String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecaptchaEntApiResponse {
    pub error: RecaptchaEntApiError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecaptchaEntApiError {
    pub code: u32,
    pub message: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecaptchaEntEvent {
    pub token: String,
    pub site_key: String,
    pub user_agent: String,
    pub user_ip_address: String,
    pub expected_action: Option<String>,
    #[serde(flatten)]
    pub extras: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecaptchaEntRiskAnalysis {
    pub score: f32,
    pub challenge: String,
    pub reasons: Vec<String>,
    #[serde(flatten)]
    pub extras: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecaptchaEntTokenProps {
    pub valid: bool,
    pub invalid_reason: Option<String>,
    pub action: Option<String>,
    #[serde(flatten)]
    pub extras: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    action: Option<&str>,
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
    action: Option<&str>,
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
        Err(result_decoding) => {
            match serde_json::from_str::<RecaptchaEntApiResponse>(&response_body)
                .map_err(RecaptchaEntError::DecodingError)
            {
                Ok(err_response) => Err(RecaptchaEntError::ApiError(err_response)),
                Err(err_decoding) => Err(RecaptchaEntError::UnexpectedResponse(
                    response_body,
                    format!("Error while parsing result response: {:?}", result_decoding),
                    format!("Error while parsing error response: {:?}", err_decoding),
                )),
            }
        }
    }
}
