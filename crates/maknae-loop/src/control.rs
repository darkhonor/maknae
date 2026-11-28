//! The agent's control-channel client (#746): one notice poll per connection to
//! the control socket. It decides nothing; the reply is mapped by
//! `maknae_agent::notice::read_reply`.
use crate::plane::Dial;
use crate::send::class_wait;
use maknae_agent::notice::{read_reply, ControlPlane, PollAnswer, PollFailure};
use maknae_config::TransportConfig;
use maknae_proto::{
    control_reply_cap, decode_control_response, encode_control_request, read_frame_of_class,
    write_frame, AgentNotice, ControlRequest, ControlVerb, FrameCaps, FrameClass, PROTOCOL_VERSION,
};
use std::time::Duration;

pub struct ControlLink<D: Dial> {
    dial: D,
    transport: TransportConfig,
}

impl<D: Dial> ControlLink<D> {
    pub fn new(dial: D, transport: TransportConfig) -> Self {
        Self { dial, transport }
    }

    async fn poll(&self) -> Result<PollAnswer, PollFailure> {
        let t = &self.transport;
        let mut stream = tokio::time::timeout(
            Duration::from_millis(t.handshake_timeout_ms),
            self.dial.dial(),
        )
        .await
        .map_err(|_| PollFailure::Handshake)?
        .map_err(|_| PollFailure::Dial)?;
        let body = encode_control_request(&ControlRequest {
            protocol_version: PROTOCOL_VERSION,
            verb: ControlVerb::NoticePoll {},
        })
        .map_err(|_| PollFailure::Write)?;
        tokio::time::timeout(
            Duration::from_millis(t.read_timeout_ms),
            write_frame(&mut stream, FrameClass::Control, &body),
        )
        .await
        .map_err(|_| PollFailure::Timeout)?
        .map_err(|_| PollFailure::Write)?;
        let caps = FrameCaps {
            control: control_reply_cap::<AgentNotice>(),
            attempt: 0,
            prompt: 0,
        };
        let reply = tokio::time::timeout(
            class_wait(FrameClass::Control, t),
            read_frame_of_class(&mut stream, FrameClass::Control, &caps),
        )
        .await
        .map_err(|_| PollFailure::Timeout)?
        .map_err(|_| PollFailure::Undecodable)?;
        let reply =
            decode_control_response::<AgentNotice>(&reply).map_err(|_| PollFailure::Undecodable)?;
        Ok(read_reply(reply))
    }
}

impl<D: Dial> ControlPlane for ControlLink<D> {
    async fn notice_poll(&mut self) -> PollAnswer {
        self.poll().await.unwrap_or_else(PollAnswer::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{Notice, NoticeId, ProtoErrCode, ProtoError, TaskId};
    use maknae_vault::VaultError;
    use std::future::Future;
    use std::sync::{Arc, Mutex};

    enum Reply {
        Answer(Box<maknae_proto::ControlResponse<AgentNotice>>),
        Frame(FrameClass, Vec<u8>),
        Header(u32, FrameClass),
        Hold,
        HangUp,
    }

    enum Dialled {
        Served(Reply),
        Refused,
        NeverConnects,
        NeverReads,
        Gone,
    }

    /// One connection per dial; reads the control request and answers as scripted.
    struct FakeControl {
        dialled: Mutex<Option<Dialled>>,
        seen: Arc<Mutex<Vec<(FrameClass, ControlRequest)>>>,
        servers: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    }

    impl FakeControl {
        fn new(dialled: Dialled) -> Self {
            FakeControl {
                dialled: Mutex::new(Some(dialled)),
                seen: Arc::default(),
                servers: Mutex::default(),
            }
        }

        fn serving(reply: Reply) -> Self {
            Self::new(Dialled::Served(reply))
        }
    }

    impl Dial for FakeControl {
        type Stream = tokio::io::DuplexStream;
        fn dial(&self) -> impl Future<Output = Result<Self::Stream, VaultError>> + Send {
            let dialled = self.dialled.lock().unwrap().take();
            let reply = match dialled {
                Some(Dialled::Served(reply)) => reply,
                Some(Dialled::Refused) | None => {
                    return Box::pin(std::future::ready(Err(VaultError::Io {
                        path: "control.sock".into(),
                        source: std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
                    }))) as Connecting
                }
                Some(Dialled::NeverConnects) => return Box::pin(std::future::pending()),
                Some(Dialled::NeverReads) => {
                    let (client, server) = tokio::io::duplex(1);
                    self.servers.lock().unwrap().push(tokio::spawn(async move {
                        let _held = server;
                        std::future::pending::<()>().await
                    }));
                    return Box::pin(std::future::ready(Ok(client)));
                }
                Some(Dialled::Gone) => {
                    let (client, server) = tokio::io::duplex(1);
                    drop(server);
                    return Box::pin(std::future::ready(Ok(client)));
                }
            };
            let (client, mut server) = tokio::io::duplex(1 << 16);
            let seen = Arc::clone(&self.seen);
            self.servers.lock().unwrap().push(tokio::spawn(async move {
                let caps = FrameCaps {
                    control: 1 << 20,
                    attempt: 1 << 20,
                    prompt: 1 << 20,
                };
                let Ok((class, body)) =
                    maknae_proto::read_frame_zeroizing(&mut server, &caps).await
                else {
                    return;
                };
                let request = maknae_proto::decode_control_request(&body).unwrap();
                seen.lock().unwrap().push((class, request));
                match reply {
                    Reply::Answer(r) => {
                        let body = maknae_proto::encode_control_response(&r).unwrap();
                        let _ = write_frame(&mut server, FrameClass::Control, &body).await;
                    }
                    Reply::Frame(class, body) => {
                        let _ = write_frame(&mut server, class, &body).await;
                    }
                    Reply::Header(len, class) => {
                        let mut header = len.to_be_bytes().to_vec();
                        header.push(class as u8);
                        let _ = tokio::io::AsyncWriteExt::write_all(&mut server, &header).await;
                        std::future::pending::<()>().await;
                    }
                    Reply::Hold => std::future::pending::<()>().await,
                    Reply::HangUp => {}
                }
            }));
            Box::pin(std::future::ready(Ok(client)))
        }
    }

    type Connecting =
        std::pin::Pin<Box<dyn Future<Output = Result<tokio::io::DuplexStream, VaultError>> + Send>>;

    fn link(fake: FakeControl) -> ControlLink<FakeControl> {
        ControlLink::new(fake, TransportConfig::default())
    }

    fn answer(result: Result<Vec<Notice<AgentNotice>>, ProtoError>) -> Reply {
        Reply::Answer(Box::new(maknae_proto::ControlResponse {
            protocol_version: PROTOCOL_VERSION,
            result,
        }))
    }

    fn stop(n: u8) -> Notice<AgentNotice> {
        Notice {
            id: NoticeId([n; 16]),
            task: Some(TaskId([n; 16])),
            body: AgentNotice::Stop,
        }
    }

    #[tokio::test]
    async fn a_poll_sends_one_control_frame_with_no_task_and_reads_the_notices() {
        let notices = vec![stop(1), stop(2)];
        let mut link = link(FakeControl::serving(answer(Ok(notices.clone()))));
        assert_eq!(link.notice_poll().await, PollAnswer::Notices(notices));
        let servers = std::mem::take(&mut *link.dial.servers.lock().unwrap());
        for s in servers {
            s.await.unwrap();
        }
        let seen = link.dial.seen.lock().unwrap();
        assert_eq!(
            *seen,
            [(
                FrameClass::Control,
                ControlRequest {
                    protocol_version: PROTOCOL_VERSION,
                    verb: ControlVerb::NoticePoll {},
                }
            )]
        );
    }

    #[tokio::test]
    async fn a_refused_reply_is_mapped_by_read_reply() {
        let refused = |code| {
            answer(Err(ProtoError {
                code,
                message: "sentinel-746".into(),
            }))
        };
        let mut l = link(FakeControl::serving(refused(ProtoErrCode::Unauthorized)));
        assert_eq!(l.notice_poll().await, PollAnswer::Refused);
        let mut l = link(FakeControl::serving(refused(ProtoErrCode::Internal)));
        assert_eq!(
            l.notice_poll().await,
            PollAnswer::Failed(PollFailure::Code(ProtoErrCode::Internal))
        );
    }

    #[tokio::test]
    async fn an_oversized_reply_is_undecodable() {
        let over = control_reply_cap::<AgentNotice>() as u32 + 1;
        let mut l = link(FakeControl::serving(Reply::Header(
            over,
            FrameClass::Control,
        )));
        assert_eq!(
            l.notice_poll().await,
            PollAnswer::Failed(PollFailure::Undecodable)
        );
    }

    #[tokio::test]
    async fn a_reply_of_another_class_is_undecodable() {
        let body =
            maknae_proto::encode_control_response(&maknae_proto::ControlResponse::<AgentNotice> {
                protocol_version: PROTOCOL_VERSION,
                result: Ok(vec![stop(3)]),
            })
            .unwrap();
        for class in [FrameClass::Attempt, FrameClass::Prompt] {
            let mut l = link(FakeControl::serving(Reply::Frame(class, body.clone())));
            assert_eq!(
                l.notice_poll().await,
                PollAnswer::Failed(PollFailure::Undecodable),
                "{class:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_closed_connection_with_no_reply_is_undecodable() {
        let mut l = link(FakeControl::serving(Reply::HangUp));
        assert_eq!(
            l.notice_poll().await,
            PollAnswer::Failed(PollFailure::Undecodable)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_write_times_out_at_the_read_timeout() {
        let mut l = link(FakeControl::new(Dialled::NeverReads));
        let start = tokio::time::Instant::now();
        assert_eq!(
            l.notice_poll().await,
            PollAnswer::Failed(PollFailure::Timeout)
        );
        assert_eq!(
            start.elapsed(),
            Duration::from_millis(TransportConfig::default().read_timeout_ms)
        );
    }

    #[tokio::test]
    async fn a_failed_write_is_a_write_failure() {
        let mut l = link(FakeControl::new(Dialled::Gone));
        assert_eq!(
            l.notice_poll().await,
            PollAnswer::Failed(PollFailure::Write)
        );
    }

    #[tokio::test]
    async fn a_dial_failure_is_a_dial_failure() {
        let mut l = link(FakeControl::new(Dialled::Refused));
        assert_eq!(l.notice_poll().await, PollAnswer::Failed(PollFailure::Dial));
    }

    #[tokio::test(start_paused = true)]
    async fn a_handshake_that_never_completes_fails_at_the_handshake_timeout() {
        let mut l = link(FakeControl::new(Dialled::NeverConnects));
        let start = tokio::time::Instant::now();
        assert_eq!(
            l.notice_poll().await,
            PollAnswer::Failed(PollFailure::Handshake)
        );
        assert_eq!(
            start.elapsed(),
            Duration::from_millis(TransportConfig::default().handshake_timeout_ms)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_reply_times_out_within_the_control_wait() {
        let mut l = link(FakeControl::serving(Reply::Hold));
        let start = tokio::time::Instant::now();
        assert_eq!(
            l.notice_poll().await,
            PollAnswer::Failed(PollFailure::Timeout)
        );
        assert_eq!(
            start.elapsed(),
            class_wait(FrameClass::Control, &TransportConfig::default())
        );
    }
}
