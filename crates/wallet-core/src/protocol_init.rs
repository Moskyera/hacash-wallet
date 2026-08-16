/// Install the one process-wide consensus codec registry used by both wallet and Hub.
pub fn ensure_protocol_setup() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
}
