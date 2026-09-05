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
        MsgId::AuditOffloadUnsupported => {
            "maknae 데몬이 시작을 거부했어요: audit.siem이 설정되어 있지만 외부 감사 전송은 아직 구현되지 않았어요"
        }
        MsgId::PostureDegraded => {
            "경고: 이번 부팅의 자격 증명 상태가 하드웨어 신뢰 루트로 봉인되지 않았어요"
        }
        MsgId::EnrollPreflightFailed => "등록 사전 점검에 실패했어요",
        MsgId::EnrollProbeStarted => {
            "이 호스트가 사용자 컨텍스트에서 자격 증명을 봉인할 수 있는지 확인하고 있어요"
        }
        MsgId::EnrollProbeFailed => {
            "자격 증명 봉인 기능 확인에 실패했어요 — Vault에는 아무 변경도 없었어요"
        }
        MsgId::EnrollProbeOk => "자격 증명 봉인 기능을 확인했어요",
        MsgId::EnrollTokenPrompt => "Vault 토큰: ",
        MsgId::EnrollVaultOpsStarted => "Vault에서 자격 증명을 요청하고 있어요",
        MsgId::EnrollWritingDaemonConfig => "데몬 설정을 기록하고 있어요",
        MsgId::EnrollSealingDaemonCredential => "데몬 자격 증명을 봉인하고 있어요",
        MsgId::EnrollProvisioningCli => "CLI 자격 증명을 준비하고 있어요",
        MsgId::EnrollPostureSummary => "등록이 완료됐어요. CLI 설정: {cli_dir}",
        MsgId::EnrollReloginNote => {
            "CLI를 사용하기 전에 로그아웃 후 다시 로그인하거나 `newgrp maknae`를 실행하세요"
        }
        MsgId::EnrollEnableDaemonHint => {
            "다음 명령으로 데몬을 시작하세요: systemctl enable --now maknaed"
        }
        MsgId::EnrollRotating => "기존 등록을 발견했어요 — 자격 증명을 교체하고 있어요",
        MsgId::EnrollRollbackDestroyed => "등록에 실패했어요 — 방금 발급된 자격 증명을 폐기했어요",
        MsgId::EnrollRollbackDestroyPartial => {
            "등록에 실패했어요 — 방금 발급된 자격 증명을 폐기하려 했지만 일부는 실패했어요 (아래 내용을 확인하세요)"
        }
        MsgId::HelperContextMismatch => "운영자 컨텍스트 헬퍼가 예상된 신원으로 전환되지 않았어요",
        MsgId::HelperStillPrivileged => {
            "운영자 컨텍스트 헬퍼가 여전히 root의 그룹 소속을 갖고 있어요 — 거부해요"
        }
    }
}
