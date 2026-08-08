use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use hpay_agent_connector::{
    AgentId, AgentRequest, AgentWalletId, FrameCodec, ProtocolEnvelope, SessionId,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("hpay-agentctl: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [command, agent_id, wallet_id, session_id, sequence] if command == "encode-status" => {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let envelope = ProtocolEnvelope::request(
                AgentId::parse(agent_id.clone())?,
                AgentWalletId::parse(wallet_id.clone())?,
                SessionId::parse(session_id.clone())?,
                sequence.parse()?,
                now,
                now.checked_add(60).ok_or("clock overflow")?,
                AgentRequest::GetStatus,
            )?;
            let frame = FrameCodec::default().encode(&envelope.to_json_bytes()?)?;
            std::io::stdout().write_all(&frame)?;
            Ok(())
        }
        [command] if command == "decode-stdin" => {
            let mut frame = Vec::new();
            std::io::stdin().read_to_end(&mut frame)?;
            let payload = FrameCodec::default().decode_exact(&frame)?;
            let envelope = ProtocolEnvelope::from_json_bytes(&payload)?;
            println!("{}", serde_json::to_string_pretty(&envelope)?);
            Ok(())
        }
        _ => {
            eprintln!(
                "Usage:\n  hpay-agentctl encode-status <agent_id> <wallet_id> <session_id> <sequence> > request.frame\n  hpay-agentctl decode-stdin < request.frame\n\nThis skeleton only encodes/decodes the authenticated protocol. It opens no listener and stores no credential."
            );
            Ok(())
        }
    }
}
