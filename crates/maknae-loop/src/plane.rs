//! The real Plane: one authenticated client, one connection per verb. Needs a
//! live daemon, Vault and certificates, so it is T3; every decision it feeds
//! is T1 in `maknae_agent::wire`.
use crate::keys::KeySupply;
use crate::send::{send_verb, write_request};
use maknae_agent::plane::{Plane, PlaneError, ReadBasis, ReadOutcome, WriteOutcome};
use maknae_agent::wire::{check_for, prompt_outcome, read_outcome, write_outcome, WireOutcome};
use maknae_config::TransportConfig;
use maknae_proto::{ProviderChoice, Turn, Verb};
use maknae_vault::{CaBundle, PlaneClient};

/// A wrapped key whose frame was refused as too large before it was sent, so it is unconsumed.
pub struct Spare {
    conversation: String,
    minted_at: u64,
    choice: ProviderChoice,
}

pub const SPARE_MAX_AGE_SECS: u64 = maknae_vault::USER_KEY_WRAP_TTL.as_secs() / 2;

fn take_spare(spare: &mut Option<Spare>, conversation: &str, now: u64) -> Option<Spare> {
    let s = spare.take()?;
    (s.conversation == conversation && now <= s.minted_at + SPARE_MAX_AGE_SECS).then_some(s)
}

/// Measured against the frame cap before sending (ADR-0023 d7).
fn frame_fits(verb: &Verb, cap: usize) -> bool {
    maknae_proto::encode_request_zeroizing(
        &maknae_proto::Request {
            protocol_version: maknae_proto::PROTOCOL_VERSION,
            verb: verb.clone(),
        },
        cap,
    )
    .is_ok()
}

fn now_unix() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "the system clock reads before 1970; set the clock, then retry".to_string())
}

/// Each loop owns its client: `PlaneClient::shutdown` consumes it, and one
/// loop's token lifecycle must not reach another's.
pub struct LoopPlane<K: KeySupply> {
    transport: TransportConfig,
    client: PlaneClient,
    ca: CaBundle,
    output_tokens: Option<u64>,
    write_max: usize,
    keys: K,
    spare: Option<Spare>,
    diagnostics: Vec<String>,
}

impl<K: KeySupply> LoopPlane<K> {
    pub fn new(
        transport: TransportConfig,
        client: PlaneClient,
        ca: CaBundle,
        output_tokens: Option<u64>,
        write_max: usize,
        keys: K,
    ) -> Self {
        LoopPlane {
            transport,
            client,
            ca,
            output_tokens,
            write_max,
            keys,
            spare: None,
            diagnostics: vec![],
        }
    }

    pub fn into_client(self) -> PlaneClient {
        self.client
    }
}

impl<K: KeySupply> Plane for LoopPlane<K> {
    async fn prompt(
        &mut self,
        conversation: &str,
        turns: &[Turn],
    ) -> Result<maknae_proto::PromptReply, PlaneError> {
        let mut verb = Verb::SessionPrompt {
            conversation: conversation.to_string(),
            turns: turns.to_vec(),
            output_tokens: self.output_tokens,
            choice: None,
        };
        // Checked before the key is wrapped, so a retry after shedding reasoning costs no Vault call.
        if !frame_fits(&verb, self.transport.prompt_max_bytes) {
            return Err(PlaneError::FrameTooLarge);
        }
        let now = now_unix().map_err(PlaneError::Transport)?;
        let (choice, minted_at) = match take_spare(&mut self.spare, conversation, now) {
            Some(s) => (s.choice, s.minted_at),
            None => {
                let c = self
                    .keys
                    .choice(conversation, now)
                    .await
                    .map_err(PlaneError::Transport)?;
                (c, now)
            }
        };
        if let Verb::SessionPrompt { choice: c, .. } = &mut verb {
            *c = Some(choice);
        }
        if !frame_fits(&verb, self.transport.prompt_max_bytes) {
            if let Verb::SessionPrompt {
                choice: Some(choice),
                ..
            } = verb
            {
                self.spare = Some(Spare {
                    conversation: conversation.to_string(),
                    minted_at,
                    choice,
                });
            }
            return Err(PlaneError::FrameTooLarge);
        }
        let diagnostics = &mut self.diagnostics;
        prompt_outcome(
            send_verb(
                verb,
                None,
                crate::mutation::WriteCheck::Unchecked,
                &self.transport,
                &self.client,
                &self.ca,
                &mut |l| diagnostics.push(l),
            )
            .await
            .map(WireOutcome::from),
        )
    }
    async fn read(
        &mut self,
        conversation: &str,
        path: &str,
        page: maknae_proto::PageRequest,
    ) -> ReadOutcome {
        let diagnostics = &mut self.diagnostics;
        read_outcome(
            send_verb(
                Verb::Read {
                    path: path.to_string(),
                    conversation: Some(conversation.to_string()),
                    page: Some(page),
                },
                None,
                crate::mutation::WriteCheck::Unchecked,
                &self.transport,
                &self.client,
                &self.ca,
                &mut |l| diagnostics.push(l),
            )
            .await
            .map(WireOutcome::from),
        )
    }
    async fn write(
        &mut self,
        conversation: &str,
        path: &str,
        content: &[u8],
        basis: ReadBasis,
    ) -> WriteOutcome {
        // The prompt-budget refusal is LOCAL and pre-send — nothing left
        // the process, nothing is on the trail, the file is untouched.
        let Ok((verb, content)) = write_request(
            path.to_string(),
            zeroize::Zeroizing::new(content.to_vec()),
            Some(conversation.to_string()),
            self.write_max,
        ) else {
            return WriteOutcome::NotSent;
        };
        let diagnostics = &mut self.diagnostics;
        write_outcome(
            send_verb(
                verb,
                Some(content),
                check_for(basis),
                &self.transport,
                &self.client,
                &self.ca,
                &mut |l| diagnostics.push(l),
            )
            .await
            .map(WireOutcome::from),
        )
    }
    fn take_diagnostics(&mut self) -> Vec<String> {
        std::mem::take(&mut self.diagnostics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::SealedKey;

    struct FakeKeys;
    impl KeySupply for FakeKeys {
        async fn choice(&mut self, _c: &str, _now: u64) -> Result<ProviderChoice, String> {
            Err("unused".into())
        }
    }

    #[test]
    fn loop_plane_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<LoopPlane<FakeKeys>>();
    }

    #[test]
    fn the_loops_same_content_agrees_with_the_file_versions() {
        let base = maknae_io::FileVersion {
            dev: 1,
            ino: 2,
            size: 3,
            mtime: 4,
            mtime_nsec: 5,
            ctime: 6,
            ctime_nsec: 7,
        };
        let changed: [fn(&mut maknae_io::FileVersion); 7] = [
            |v| v.dev += 1,
            |v| v.ino += 1,
            |v| v.size += 1,
            |v| v.mtime += 1,
            |v| v.mtime_nsec += 1,
            |v| v.ctime += 1,
            |v| v.ctime_nsec += 1,
        ];
        for (i, change) in changed.iter().enumerate() {
            let mut v = base;
            change(&mut v);
            assert_eq!(
                maknae_agent::plane::same_content(&base.key(), &v.key()),
                base.same_content(&v),
                "field {i}"
            );
        }
    }

    #[test]
    fn frame_fits_is_the_encoders_cap_check() {
        let verb = |n: usize| Verb::SessionPrompt {
            conversation: "c".into(),
            turns: vec![Turn::User {
                content: vec![maknae_proto::ContentBlock::Text {
                    text: maknae_proto::SecretText(zeroize::Zeroizing::new("a".repeat(n))),
                }],
            }],
            output_tokens: None,
            choice: None,
        };
        assert!(frame_fits(&verb(10), 65_536));
        assert!(!frame_fits(&verb(70_000), 65_536));
    }

    #[test]
    fn the_prompt_frame_is_sized_before_the_key_is_wrapped() {
        let src = include_str!("plane.rs");
        let body = &src[src.find(concat!("async fn ", "prompt(")).unwrap()..];
        let fits = body.find(concat!("frame_fits(", "&verb")).unwrap();
        let wrap = body
            .find(concat!(".choice(", "conversation, now)"))
            .unwrap();
        assert!(fits < wrap);
    }

    fn a_choice() -> ProviderChoice {
        ProviderChoice {
            provider: "p".into(),
            model: "m".into(),
            key_subpath: "k".into(),
            key_field: "f".into(),
            sealed_key: SealedKey::new(vec![7; maknae_proto::SEALED_KEY_MIN_BYTES]).unwrap(),
        }
    }

    #[test]
    fn a_spare_choice_is_reused_once_for_its_conversation_while_its_wrap_is_young() {
        let mut spare = Some(Spare {
            conversation: "c".into(),
            minted_at: 100,
            choice: a_choice(),
        });
        assert!(take_spare(&mut spare, "other", 101).is_none());
        assert!(spare.is_none());

        let mut spare = Some(Spare {
            conversation: "c".into(),
            minted_at: 100,
            choice: a_choice(),
        });
        assert!(take_spare(&mut spare, "c", 100 + SPARE_MAX_AGE_SECS + 1).is_none());

        let mut spare = Some(Spare {
            conversation: "c".into(),
            minted_at: 100,
            choice: a_choice(),
        });
        let s = take_spare(&mut spare, "c", 100 + SPARE_MAX_AGE_SECS).unwrap();
        assert_eq!((s.choice, s.minted_at), (a_choice(), 100));
        assert!(take_spare(&mut spare, "c", 101).is_none());
    }

    #[test]
    fn a_spare_is_never_older_than_half_the_wrap() {
        assert_eq!(
            SPARE_MAX_AGE_SECS * 2,
            maknae_vault::USER_KEY_WRAP_TTL.as_secs()
        );
    }
}
