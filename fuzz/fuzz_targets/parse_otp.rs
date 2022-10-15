#![no_main]
use libfuzzer_sys::fuzz_target;
use auth1::oob::Otp;
use std::str::FromStr;

fuzz_target!(|s: &str| {
    let _ = Otp::from_str(s);
});
