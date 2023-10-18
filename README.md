[![Crates.io](https://img.shields.io/crates/v/recaptcha-verify?color=4d76ae)](https://crates.io/crates/recaptcha-verify)
[![API](https://docs.rs/recaptcha-verify/badge.svg)](https://docs.rs/recaptcha-verify)
[![Build and Test](https://github.com/iganev/recaptcha-verify/actions/workflows/rust.yml/badge.svg)](https://github.com/iganev/recaptcha-verify/actions/workflows/rust.yml)
[![dependency status](https://deps.rs/repo/github/iganev/recaptcha-verify/status.svg)](https://deps.rs/repo/github/iganev/recaptcha-verify)

# recaptcha-verify
Simple, bare-minimum recaptcha verifier helper

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

## Example

```rust
use recaptcha_verify::{RecaptchaError, verify};

let res:Result<(), RecaptchaError> = verify("secret", "token", None).await;
```

## License

This library (recaptcha-verify) is open sourced under the MIT License. 