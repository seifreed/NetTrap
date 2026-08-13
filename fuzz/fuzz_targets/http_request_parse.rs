#![no_main]

use libfuzzer_sys::fuzz_target;
use nettrap_proto_http::HttpRequestParsed;

fuzz_target!(|data: &[u8]| {
    let _ = HttpRequestParsed::parse(data);
});
