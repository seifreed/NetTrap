#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let h = nettrap_proto_redis::RedisHandler::new();
    let _ = h.handle_command(data);
});
