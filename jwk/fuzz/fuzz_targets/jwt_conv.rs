#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|key: jwk::Key| {
    let _ = key.to_jwt_key();
});
