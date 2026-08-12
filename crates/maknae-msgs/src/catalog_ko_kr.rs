//! ko_KR catalog strings. Declaration-only string-table match arms — see
//! `coverage-tiers.toml` T3 justification.
//!
//! ko_KR strings pending native-speaker confirmation before ship (spec §10.7).
//! Drafted in polite 해요체, operator-facing register.

use crate::MsgId;

pub(crate) fn text(id: MsgId) -> &'static str {
    match id {
        MsgId::EnrollStarted => "등록을 시작해요",
        MsgId::EnrollGroupAdded => "{user}님을 maknae 그룹에 추가했어요",
        MsgId::EnrollAlreadyMember => "{user}님은 이미 maknae 그룹의 구성원이에요",
        MsgId::EnrollFailed => "등록에 실패했어요",
        MsgId::AuthzDenied => "접근이 거부됐어요",
        MsgId::AuthzPostureRefused => "요청이 거부됐어요: 상태 요구사항을 충족하지 못했어요",
        MsgId::AuthzUnknownSubject => "알 수 없는 주체예요",
        MsgId::DaemonNotRunning => "maknae 데몬이 실행 중이 아니에요",
        MsgId::DaemonStartFailed => "maknae 데몬 시작에 실패했어요",
        MsgId::AuthzConfigRefused => {
            "maknae 데몬이 시작을 거부했어요: 권한 정책을 불러올 수 없어요"
        }
        MsgId::PostureDegraded => {
            "경고: 이번 부팅의 자격 증명 상태가 하드웨어 신뢰 루트로 봉인되지 않았어요"
        }
    }
}
