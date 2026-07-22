use std::sync::Once;

use protocol::setup::{install_once, new_standard_protocol_setup};
use sys::calculate_hash;

static PROTOCOL_INIT: Once = Once::new();

/// Install global protocol registries required for L1/Type4 signing and validation.
pub fn ensure_protocol_setup() {
    PROTOCOL_INIT.call_once(|| {
        let mut setup = new_standard_protocol_setup(|_, stuff| calculate_hash(stuff));
        // Channel and HACD inscription actions live in the consensus mint crate.
        // They must be registered anywhere the wallet decodes an unsigned body.
        mint::action::register(&mut setup);
        // Register Istanbul HVM/P2SH action codecs for decode, intent binding and
        // signing inspection. Do not install VM runtime hooks or execute code in
        // the wallet; execution and state simulation remain node responsibilities.
        vm::action::register(&mut setup);
        install_once(setup);
    });
}
