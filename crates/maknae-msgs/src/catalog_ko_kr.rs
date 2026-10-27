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
        MsgId::EnrollTokenPrompt => "Vault 토큰: ",
        MsgId::EnrollVaultOpsStarted => "Vault에서 자격 증명을 요청하고 있어요",
        MsgId::EnrollWritingDaemonConfig => "데몬 설정을 기록하고 있어요",
        MsgId::EnrollSealingDaemonCredential => "데몬 자격 증명을 봉인하고 있어요",
        MsgId::EnrollSealKeyGenerated => {
            "Egress Daemon의 봉인 키를 만들고 공개 키를 {path}에 게시했어요. 이미 실행 중인 Egress Daemon은 이전 키를 그대로 쓰고 있으니 `sudo {restart}`로 다시 시작하세요"
        }
        MsgId::EnrollSealKeyKept => {
            "Egress Daemon의 기존 봉인 키와 게시된 공개 키를 유지했어요. 교체하려면 --rotate-seal-key를 사용하세요"
        }
        MsgId::EnrollGraphKeyCreated => "커널 그래프 키를 {path}에 만들었어요",
        MsgId::EnrollGraphKeyKept => {
            "{path}의 커널 그래프 키를 유지했어요. 새 키로는 기존 그래프 저장소를 읽을 수 없어서 이 키는 교체하지 않아요"
        }
        MsgId::EnrollGraphStoreExists => {
            "커널 그래프 저장소가 이미 있어서 새 키로는 열 수 없어요. sudo maknae reseed를 실행하세요"
        }
        MsgId::EnrollProvisioningCli => "CLI 설정을 기록하고 있어요",
        MsgId::EnrollPostureSummary => "등록이 완료됐어요. CLI 설정: {cli_dir}",
        MsgId::EnrollReloginNote => {
            "CLI를 사용하기 전에 로그아웃 후 다시 로그인하거나 `newgrp maknae`를 실행한 다음, `maknae login`을 실행하세요"
        }
        MsgId::EnrollEgressBoundsHint => {
            "maknae-egress: 등록이 /etc/maknae/egress-bounds.yaml을 기록했어요. 다음 명령으로 대리자를 시작하세요: systemctl enable --now maknae-egress.socket — 소켓 유닛은 기본적으로 꺼져 있고, 켜기 전까지 허용된 프롬프트는 모두 준비되지 않음으로 거부돼요"
        }
        MsgId::EnrollEnableDaemonHint => {
            "다음 명령으로 데몬을 시작하세요: systemctl enable --now maknaed"
        }
        MsgId::EnrollEgressBoundsHintMacos => {
            "maknae-egress: 등록이 /etc/maknae/egress-bounds.yaml을 기록했어요. 다음 명령으로 대리자를 시작하세요: sudo launchctl enable system/io.maknae.maknae-egress && sudo launchctl bootstrap system /Library/LaunchDaemons/io.maknae.maknae-egress.plist — 이 작업은 비활성 상태로 설치되고, 켜기 전까지 허용된 프롬프트는 모두 준비되지 않음으로 거부돼요"
        }
        MsgId::EnrollEnableDaemonHintMacos => {
            "다음 명령으로 데몬을 시작하세요: sudo launchctl enable system/io.maknae.maknaed && sudo launchctl bootstrap system /Library/LaunchDaemons/io.maknae.maknaed.plist"
        }
        MsgId::EnrollRotating => "기존 등록을 발견했어요 — 자격 증명을 교체하고 있어요",
        MsgId::EnrollRotatePreviousDestroyed => "이전 등록의 자격 증명을 폐기했어요",
        MsgId::EnrollRollbackDestroyed => "등록에 실패했어요 — 방금 발급된 자격 증명을 폐기했어요",
        MsgId::EnrollRollbackDestroyPartial => {
            "등록에 실패했어요 — 방금 발급된 자격 증명을 폐기하려 했지만 일부는 실패했어요 (아래 내용을 확인하세요)"
        }
        MsgId::EnrollBindingsWritten => {
            "bindings.yaml에 {user}님을 admin으로 기록했어요"
        }
        MsgId::EnrollBindingsAlreadyAdmin => {
            "{user}님은 이미 bindings.yaml에서 admin이에요. bindings.yaml은 바꾸지 않았어요"
        }
        MsgId::EnrollBindingsLost => {
            "maknaed가 명시적 바인딩을 적용 중인데 bindings.yaml이 없거나 bindings: 키가 없어요. 먼저 터미널에서 sudo maknae policy sync로 복원한 뒤 다시 등록하세요"
        }
        MsgId::EnrollBindingsOtherRole => {
            "{user}님은 {role} 역할을 갖고 있어요. enroll은 다른 역할이 없는 사용자에게만 admin을 추가해요. {user}님이 admin이어야 한다면 먼저 그 바인딩을 바꾸세요"
        }
        MsgId::EnrollBindingsReloadHint => {
            "maknaed가 실행 중이라면 다시 불러와서 bindings.yaml을 적용하세요: sudo systemctl reload maknaed"
        }
        MsgId::EnrollBindingsReloadHintMacos => {
            "maknaed가 실행 중이라면 다시 불러와서 bindings.yaml을 적용하세요: sudo launchctl kill SIGHUP system/io.maknae.maknaed"
        }
        MsgId::EnrollBindingsContained => {
            "{user}님은 격리되어 있어요. enroll은 격리를 바꾸지 않아요. 의도한 것이라면 먼저 격리를 해제하세요"
        }
        MsgId::EnrollBindingsLookupFailed => {
            "바인딩에 있는 계정 {name}을(를) 조회할 수 없어요: {error}. 아무것도 기록하지 않았어요"
        }
        MsgId::EnrollAgentStarted => "에이전트 데몬 {agent}을(를) 등록하고 있어요",
        MsgId::EnrollAgentEnrolled => {
            "에이전트 데몬 {agent} 등록이 완료됐어요. {role}의 SecretID를 이 호스트에 봉인했고, {cidrs}에서만 사용할 수 있어요"
        }
        MsgId::EnrollAgentRetired => "이 에이전트의 이전 SecretID {count}개를 폐기했어요",
        MsgId::HelperContextMismatch => "운영자 컨텍스트 헬퍼가 예상된 신원으로 전환되지 않았어요",
        MsgId::HelperStillPrivileged => {
            "운영자 컨텍스트 헬퍼가 여전히 root의 그룹 소속을 갖고 있어요 — 거부해요"
        }
        MsgId::CryptoFipsUnavailable => "시작 거부: FIPS 암호 제공자가 활성화되어 있지 않습니다",
        MsgId::CryptoKxGroupsDrift => "시작 거부: TLS 제공자에 필요한 키 교환 그룹이 없습니다",
    }
}
