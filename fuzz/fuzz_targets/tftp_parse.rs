#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = nettrap_proto_tftp::TftpPacket::parse(data);
});
