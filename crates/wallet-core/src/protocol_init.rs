use std::sync::Once;

use protocol::setup::{install_once, new_standard_protocol_setup};
use sys::calculate_hash;

static PROTOCOL_INIT: Once = Once::new();

/// Install global protocol registries required for L1/Type4 signing and validation.
pub fn ensure_protocol_setup() {
    PROTOCOL_INIT.call_once(|| {
        let setup = new_standard_protocol_setup(|_, stuff| calculate_hash(stuff));
        install_once(setup);
    });
}