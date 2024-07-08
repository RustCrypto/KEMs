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
extern crate alloc;

mod algebra;
pub mod const_time;
mod core;
pub mod encoded;
pub mod params;
use hybrid_array::sizes::{U1013, U1277, U653, U761, U857, U953};
use params::{Lpr, Streamlined};

pub type Sntrup653 = Streamlined<U653>;
pub type Sntrup761 = Streamlined<U761>;
pub type Sntrup857 = Streamlined<U857>;
pub type Sntrup953 = Streamlined<U953>;
pub type Sntrup1013 = Streamlined<U1013>;
pub type Sntrup1277 = Streamlined<U1277>;
pub type Ntrulpr653 = Lpr<U653>;
pub type Ntrulpr761 = Lpr<U761>;
pub type Ntrulpr857 = Lpr<U857>;
pub type Ntrulpr953 = Lpr<U953>;
pub type Ntrulpr1013 = Lpr<U1013>;
pub type Ntrulpr1277 = Lpr<U1277>;
