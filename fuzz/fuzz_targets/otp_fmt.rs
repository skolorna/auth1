#![no_main]
use libfuzzer_sys::fuzz_target;
use auth1::oob::Otp;
use std::str::FromStr;

fuzz_target!(|otp: Otp| {
    let s = otp.to_string();
    assert_eq!(s.parse::<Otp>().unwrap(), otp);
});
