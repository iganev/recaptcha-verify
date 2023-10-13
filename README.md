# recaptcha-verify
Simple, bare-minimum recaptcha verifier helper

## Quick Start

This library is supposed to be a (near) drop-in replacement for [recaptcha-rs](https://crates.io/crates/recaptcha).
The usage is nearly (bot not completely) identical. 
Here however we use `rustls` by default, but you could choose from the following features:  
- default-tls - enforces default-tls feature in reqwest
- native-tls - enforces native-tls feature in reqwest
- rustls-tls - enabled by default

Another key difference is that this library uses tokio 1 as dev dependency and more recent versions of reqwest and serde. 

## Example

```rust
use recaptcha_verify::{RecaptchaError, verify};

let res:Result<(), RecaptchaError> = verify("secret", "token", None).await;
```

## License

This library (recaptcha-verify) is open sourced under the MIT License. 