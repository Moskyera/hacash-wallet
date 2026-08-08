use hpay_companion_protocol::{
    AdminCommand, AdminCommandKind, CompanionMessage, CompanionPayload, DeviceId, PROTOCOL_VERSION,
};

#[test]
fn emergency_command_uses_the_exact_command_type_name() {
    let command = AdminCommand {
        command_version: 2,
        command_id: "command_one".to_owned(),
        command_type: AdminCommandKind::SuspendAgentPayments,
        agent_wallet_id: "wallet_one".to_owned(),
        mobile_device_id: DeviceId::parse("mobile_one").unwrap(),
        device_authorization_epoch: 1,
        desktop_device_id: DeviceId::parse("desktop_one").unwrap(),
        policy_epoch: 3,
        command_sequence: 1,
        nonce: "ab".repeat(16),
        issued_at: 100,
        expires_at: 200,
    };
    let json = serde_json::to_value(command).unwrap();
    assert_eq!(
        json.get("command_type").and_then(|value| value.as_str()),
        Some("suspend_agent_payments")
    );
}

#[test]
fn unknown_message_and_payload_fields_are_rejected() {
    let message = CompanionMessage {
        protocol_version: PROTOCOL_VERSION,
        message_id: "message_one".to_owned(),
        session_id: "session_one".to_owned(),
        sender_device_id: DeviceId::parse("desktop_one").unwrap(),
        recipient_device_id: DeviceId::parse("mobile_one").unwrap(),
        sequence: 1,
        issued_at: 100,
        expires_at: 200,
        payload: CompanionPayload::Ping,
    };
    let mut root = serde_json::to_value(&message).unwrap();
    root.as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<CompanionMessage>(root).is_err());

    let mut nested = serde_json::to_value(&message).unwrap();
    nested
        .get_mut("payload")
        .and_then(|value| value.as_object_mut())
        .unwrap()
        .insert("unknown".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<CompanionMessage>(nested).is_err());
}
