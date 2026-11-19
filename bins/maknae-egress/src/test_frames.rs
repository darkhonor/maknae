use crate::serve::{serve_one, MintFrames, ServeError, FRAME_IO_TIMEOUT};
use maknae_config::EgressBounds;
use maknae_proto::{
    ContentBlock, EgressFrame, EgressFrameReply, EgressFrameRequest, EgressSocketReply, SecretText,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;

pub(crate) const ALICE: &str = "maknae/users/alice/openai/personal";
pub(crate) fn canned(
    _a: &maknae_deputy::handle::Admitted<'_>,
) -> Result<EgressFrameReply, ServeError> {
    Ok(EgressFrameReply::Reply(maknae_proto::PromptReply {
        reasoning: None,
        blocks: vec![],
        tool_calls: vec![],
        usage: None,
    }))
}

pub(crate) fn bounds() -> EgressBounds {
    EgressBounds {
        call_timeout_ms: maknae_config::DEFAULT_CALL_TIMEOUT_MS,
        kv_mount: "maknae-kv".into(),
        user_prefix: "maknae/users".into(),
        agent_prefix: None,
        vault_addr: "https://vault.example:8200".into(),
    }
}

pub(crate) fn request(key: &str) -> EgressFrameRequest {
    EgressFrameRequest {
        deadline_ms: None,
        destination: "provider:openai".into(),
        endpoint: "https://api.example.test/v1".into(),
        model: "m".into(),
        key_vault_path: key.into(),
        key_field: "api_key".into(),
        reasoning_effort: None,
        conversation: "conv1".into(),
        turns: vec![maknae_proto::Turn::User {
            content: vec![ContentBlock::Text {
                text: SecretText(zeroize::Zeroizing::new("hi".into())),
            }],
        }],
        output_tokens: None,
        output_tokens_field: None,
        sealed_key: maknae_proto::SealedKey::new(vec![7u8; maknae_proto::SEALED_KEY_MIN_BYTES])
            .unwrap(),
    }
}

pub(crate) fn encoded_frame(f: &EgressFrame) -> Vec<u8> {
    maknae_proto::encode_egress_frame(f, maknae_proto::EGRESS_REQUEST_FRAME_ENCODE_BYTES)
        .unwrap()
        .to_vec()
}

pub(crate) fn prefixed(body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

pub(crate) fn prompt_frame() -> EgressFrame {
    EgressFrame::Prompt(request(ALICE))
}

pub(crate) fn canned_reply() -> EgressSocketReply {
    EgressSocketReply::Prompt(EgressFrameReply::Reply(maknae_proto::PromptReply {
        reasoning: None,
        blocks: vec![],
        tool_calls: vec![],
        usage: None,
    }))
}

/// One connection carrying `frame`, served with `minting` and the canned provider.
pub(crate) fn served_frame(
    frame: &EgressFrame,
    minting: Option<&dyn MintFrames>,
) -> (Result<(), ServeError>, Option<EgressSocketReply>) {
    let (a, b) = UnixStream::pair().unwrap();
    let bytes = prefixed(&encoded_frame(frame));
    let h = std::thread::spawn(move || {
        let mut c = a;
        c.write_all(&bytes).unwrap();
        let mut back = Vec::new();
        c.read_to_end(&mut back).unwrap();
        back
    });
    let me = nix::unistd::getuid().as_raw();
    let out = serve_one(
        b,
        me,
        &bounds(),
        FRAME_IO_TIMEOUT,
        &AtomicBool::new(false),
        minting,
        canned,
    );
    let back = h.join().unwrap();
    let reply = (!back.is_empty()).then(|| {
        let n = u32::from_be_bytes(back[..4].try_into().unwrap()) as usize;
        assert_eq!(back.len(), 4 + n);
        maknae_proto::decode_egress_socket_reply(&back[4..]).unwrap()
    });
    (out, reply)
}
