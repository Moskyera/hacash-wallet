use std::sync::Once;

use protocol::setup::{install_once, new_standard_protocol_setup};
use sys::calculate_hash;

static PROTOCOL_INIT: Once = Once::new();

/// Installs the single consensus codec registry shared by the wallet and Hub.
pub fn ensure_hacash_protocol_setup() {
    PROTOCOL_INIT.call_once(|| {
        let mut setup = new_standard_protocol_setup(|_, stuff| calculate_hash(stuff));
        mint::action::register(&mut setup);
        vm::action::register(&mut setup);
        install_once(setup);
    });
}
