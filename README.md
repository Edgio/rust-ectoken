![CI](https://github.com/EdgeCast/rust-ectoken/workflows/CI/badge.svg)
[![crates.io](https://img.shields.io/crates/v/ectoken.svg)](https://crates.io/crates/ectoken)
[![Docs](https://docs.rs/ectoken/badge.svg)](https://docs.rs/ectoken)

<img src="assets/edgecast_black.png" width="300"/>

# rust-ectoken
> _Token Generator for EdgeCast Token-Based Authentication implemented in Rust_

Token-Based Authentication safeguards against hotlinking by adding a token requirement to requests for content secured by it. This token, which must be defined in the request URL's query string, defines the criteria that must be met before the requested content may be served via the CDN. This repository contains source code for a Rust implementation.

Written against Rust 2021. (Minimum rustc version 1.60.0).

## Table of Contents

- [Build](#Build)
- [Test](#Test)
- [Usage](#usage)
- [Contribute](#contribute)
- [License](#license)

## Build
```
cargo build --release
```

## Test
```
cargo test
```

## Usage

### Library
Add the following to your Cargo.toml.
```toml
[dependencies]
ectoken = "0.5"
```

### CLI
```
To Encrypt:
  ec_encrypt <key> <text>
or:
  ec_encrypt encrypt <key> <text>

To Decrypt:
  ec_encrypt decrypt <key> <text>
```

#### Example
```rust
use ectoken;

fn example() {

    let encrypted = ectoken::encrypt_v3("mykey", "mymessage");

    let decrypted = ectoken::decrypt_v3("mykey", &encrypted).unwrap();

    assert_eq!("mymessage", decrypted);
}
```

## Contribute

- We welcome issues, questions and pull requests.


## License

This project is licensed under the terms of the Apache 2.0 open source license. Please refer to the `LICENSE-APACHE` file for the full terms.
