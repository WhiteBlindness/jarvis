//! Property tests for the decoder: it is the first code that touches bytes
//! from an untrusted worker.

use jarvis_protocol::{
    ErrorCode, Hello, JobId, Label, RequestId, ToolName, ToolRequest, WorkerMessage,
    decode_rpc_request, decode_worker_message, encode_worker_message,
};
use proptest::prelude::*;

proptest! {
    /// Arbitrary bytes never panic the decoders and always produce either a
    /// message or a classified error.
    #[test]
    fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Err(error) = decode_rpc_request(&bytes) {
            prop_assert!(matches!(
                error.code(),
                ErrorCode::MalformedFrame | ErrorCode::UnsupportedProtocolVersion
            ));
        }
        if let Err(error) = decode_worker_message(&bytes) {
            prop_assert!(matches!(
                error.code(),
                ErrorCode::MalformedFrame | ErrorCode::UnsupportedProtocolVersion
            ));
        }
    }

    /// Arbitrary JSON objects with a valid version never panic either, and
    /// anything that decodes re-encodes to an equivalent frame.
    #[test]
    fn decode_of_json_objects_is_total(
        fields in proptest::collection::btree_map("[a-z_]{1,12}", any_json(), 0..6),
    ) {
        let mut object = serde_json::Map::new();
        object.insert("protocol".into(), 2.into());
        object.extend(fields);
        let bytes = serde_json::to_vec(&object).unwrap();
        if let Ok(message) = decode_worker_message(&bytes) {
            let again = decode_worker_message(&encode_worker_message(&message).unwrap()).unwrap();
            prop_assert_eq!(again, message);
        }
    }

    /// Valid requests survive an encode/decode round trip unchanged.
    #[test]
    fn valid_requests_round_trip(
        id in "[A-Za-z0-9_-]{1,64}",
        tool in "[a-z][a-z0-9_]{0,10}\\.[a-z][a-z0-9_]{0,10}",
        key in "[a-z]{1,8}",
        number in any::<i64>(),
    ) {
        let message = WorkerMessage::ToolRequest(ToolRequest {
            request_id: RequestId::try_from(id).unwrap(),
            job_id: JobId::new(),
            tool: ToolName::try_from(tool).unwrap(),
            args: serde_json::json!({ key: number }),
        });
        let bytes = encode_worker_message(&message).unwrap();
        prop_assert_eq!(decode_worker_message(&bytes).unwrap(), message);
    }

    #[test]
    fn hello_labels_round_trip(worker in "[A-Za-z0-9._+-]{1,64}", version in "[0-9.]{1,16}") {
        let message = WorkerMessage::Hello(Hello {
            worker: Label::try_from(worker).unwrap(),
            worker_version: Label::try_from(version).unwrap(),
        });
        let bytes = encode_worker_message(&message).unwrap();
        prop_assert_eq!(decode_worker_message(&bytes).unwrap(), message);
    }
}

fn any_json() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::from),
        any::<i64>().prop_map(serde_json::Value::from),
        prop_oneof![
            Just("hello".to_owned()),
            Just("tool_request".to_owned()),
            Just("system.info".to_owned()),
            "[ -~]{0,16}",
        ]
        .prop_map(serde_json::Value::from),
    ];
    leaf.prop_recursive(3, 16, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(serde_json::Value::from),
            proptest::collection::btree_map("[a-z_]{1,8}", inner, 0..4)
                .prop_map(|map| serde_json::Value::Object(map.into_iter().collect())),
        ]
    })
}
