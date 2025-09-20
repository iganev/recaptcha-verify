[![Crates.io](https://img.shields.io/crates/v/recaptcha-verify?color=4d76ae)](https://crates.io/crates/recaptcha-verify)
[![API](https://docs.rs/recaptcha-verify/badge.svg)](https://docs.rs/recaptcha-verify)
[![dependency status](https://deps.rs/repo/github/iganev/recaptcha-verify/status.svg)](https://deps.rs/repo/github/iganev/recaptcha-verify)
[![build and test](https://github.com/iganev/recaptcha-verify/actions/workflows/rust.yml/badge.svg)](https://github.com/iganev/recaptcha-verify/actions/workflows/rust.yml)
[![codecov](https://codecov.io/github/iganev/recaptcha-verify/graph/badge.svg?token=B5P2TAV5BB)](https://codecov.io/github/iganev/recaptcha-verify)


# recaptcha-verify
Simple, bare-minimum recaptcha verifier helper compatible with v2, v3 and Enterprise.

## Quick Start

This library is supposed to be a (near) drop-in replacement for [recaptcha-rs](https://crates.io/crates/recaptcha).
The usage is nearly (but not completely) identical. 
Here however we use `rustls` by default, but you could choose from the following features:  
- default-tls - enforces default-tls feature in reqwest
- native-tls - enforces native-tls feature in reqwest
- rustls-tls - enabled by default

Another key difference is that this library uses tokio 1 as dev dependency and more recent versions of reqwest and serde. 

## Changes in 0.1.3

One important change in 0.1.3 is the fact that instead of string we now pass the whole `reqwest::Error` in `RecaptchaError::HttpError`.
If you previously used the String containing variant, please migrate to using `reqwest::Error`.  

## Changes in 0.2.0

Introducing enterprise support. Legacy v2 and v3 verification should continue to work and is backwards compatible.  
The `verify` function is **deprecated** and should be replaced with `verify_v3` to avoid deprecation warnings.  
Enterprise support is provided by `recaptcha_verify::verify_enterprise` and works in a similar way to `verify_v3`.  
For more granular control over the response properties you can use `recaptcha_verify::verify_enterprise_detailed`.  

## Example

ReCAPTCHA v2 and v3:  

```rust
use recaptcha_verify::{RecaptchaError, verify};

let res:Result<(), RecaptchaError> = verify("secret", "token", None).await;
```

ReCAPTCHA Enterprise:  

```rust
use recaptcha_verify::{RecaptchaEntError, verify_enterprise};

let res:Result<(), RecaptchaEntError> = verify_enterprise(
        "project",     // your google cloud project identifier
        "api_key",     // your google cloud project API key with access to the recaptcha service
        "site_key",    // your site key setup within the same project
        "token",       // the user challenge token
        Some("login"), // optional action
    )
    .await;
```

## License

This library (recaptcha-verify) is open sourced under the MIT License. 
