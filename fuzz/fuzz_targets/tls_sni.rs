#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = nettrap_proto_tls::fingerprint::extract_sni(data);
    let _ = nettrap_proto_tls::ja3::ja3_from_handshake(data);
    let _ = nettrap_proto_tls::ja3::ja4_from_handshake(data);
});
