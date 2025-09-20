mod ent;
mod v3;

#[allow(deprecated)]
pub use v3::verify;
pub use v3::verify_v3;
pub use v3::RecaptchaError;

pub use ent::verify_enterprise;
pub use ent::verify_enterprise_detailed;
pub use ent::RecaptchaEntError;
pub use ent::RecaptchaEntResult;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Check https://developers.google.com/recaptcha/docs/faq#id-like-to-run-automated-tests-with-recaptcha.-what-should-i-do
    const GOOGLE_MOCK_SECRET: &str = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe";

    const UNKNOWN_ERROR: &str = "trololo-detected";

    #[tokio::test]
    #[allow(deprecated)]
    async fn it_works_v3() {
        assert!(matches!(
            "missing-input-secret".to_string().try_into(),
            Ok(RecaptchaError::MissingInputSecret)
        ));
        assert!(matches!(
            "invalid-input-secret".to_string().try_into(),
            Ok(RecaptchaError::InvalidInputSecret)
        ));
        assert!(matches!(
            "missing-input-response".to_string().try_into(),
            Ok(RecaptchaError::MissingInputResponse)
        ));
        assert!(matches!(
            "invalid-input-response".to_string().try_into(),
            Ok(RecaptchaError::InvalidInputResponse)
        ));
        assert!(matches!(
            "bad-request".to_string().try_into(),
            Ok(RecaptchaError::BadRequest)
        ));
        assert!(matches!(
            "timeout-or-duplicate".to_string().try_into(),
            Ok(RecaptchaError::TimeoutOrDuplicate)
        ));

        assert!(
            matches!(UNKNOWN_ERROR.to_string().try_into(), Ok(RecaptchaError::Unknown(Some(s))) if s == UNKNOWN_ERROR )
        );

        //

        let res: Result<(), RecaptchaError> = verify("test", "test", None).await;

        assert!(matches!(res, Err(RecaptchaError::InvalidInputResponse)));

        //

        let localhost_v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let res: Result<(), RecaptchaError> =
            verify(GOOGLE_MOCK_SECRET, "test", Some(&localhost_v4)).await;

        assert!(matches!(res, Ok(())));

        //

        let res: Result<(), RecaptchaError> = verify_v3("test", "test", None).await;

        assert!(matches!(res, Err(RecaptchaError::InvalidInputResponse)));

        //

        let localhost_v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let res: Result<(), RecaptchaError> =
            verify_v3(GOOGLE_MOCK_SECRET, "test", Some(&localhost_v4)).await;

        assert!(matches!(res, Ok(())));
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn it_works_ent() {
        let result =
            verify_enterprise_detailed("project", "api_key", "site_key", "token", Some("login"))
                .await;

        assert!(
            matches!(result, Err(RecaptchaEntError::ApiError(api_error)) if api_error.error.code >= 400)
        );

        let result =
            verify_enterprise("project", "api_key", "site_key", "token", Some("test")).await;

        assert!(
            matches!(result, Err(RecaptchaEntError::ApiError(api_error)) if api_error.error.code >= 400)
        );
    }
}
