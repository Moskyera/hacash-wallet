use std::sync::Once;

use protocol::setup::{new_standard_protocol_setup, try_install_once};
use sys::calculate_hash;

static PROTOCOL_INIT: Once = Once::new();

/// Installs the single consensus codec registry shared by the wallet and Hub.
///
/// There is one registry per process. If something in this process has already
/// installed one - a fullnode, or the fullnode's own in-memory chain harness
/// when the wallet's exact signed bytes are being executed against real blocks,
/// that registry is the process's registry and this is a no-op. Claiming the
/// slot twice was never something the wallet wanted; it just used to be fatal
/// instead of shared.
pub fn ensure_hacash_protocol_setup() {
    PROTOCOL_INIT.call_once(|| {
        let mut setup = new_standard_protocol_setup(|_, stuff| calculate_hash(stuff));
        mint::action::register(&mut setup);
        vm::action::register(&mut setup);
        try_install_once(setup);
    });
}
