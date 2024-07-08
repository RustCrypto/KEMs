#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(clippy::pedantic)] // Be pedantic by default
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    // We shall stick to the naming as reference implementation
    // especially for variables
    clippy::unreadable_literal,
    clippy::many_single_char_names,
    clippy::similar_names,
)]

pub mod const_time;