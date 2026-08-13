#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let h = nettrap_proto_ldap::LdapHandler::new();
    let _ = h.handle(data);
});
