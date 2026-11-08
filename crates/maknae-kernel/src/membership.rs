//! The `maknae`-group admission answer for a resolved host account.
use maknae_io::HostAccount;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub in_group: bool,
    pub user: String,
    pub dir: std::path::PathBuf,
}

pub(crate) fn membership(account: HostAccount, maknae_gid: Option<u32>) -> Membership {
    Membership {
        in_group: maknae_gid.is_some_and(|g| account.named_groups.contains(&g)),
        user: account.name,
        dir: account.dir,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(groups: &[u32]) -> HostAccount {
        HostAccount {
            uid: 1000,
            name: "ann".into(),
            primary_gid: 100,
            shell: "/bin/zsh".into(),
            dir: "/home/ann".into(),
            named_groups: groups.to_vec(),
        }
    }

    fn answered(in_group: bool) -> Membership {
        Membership {
            in_group,
            user: "ann".into(),
            dir: "/home/ann".into(),
        }
    }

    #[test]
    fn a_member_of_the_maknae_group_is_in_group() {
        assert_eq!(membership(account(&[100, 900]), Some(900)), answered(true));
    }

    #[test]
    fn a_non_member_is_not_in_group_and_keeps_the_identity() {
        assert_eq!(membership(account(&[100]), Some(900)), answered(false));
    }

    #[test]
    fn a_host_without_a_maknae_group_has_no_members() {
        assert_eq!(membership(account(&[100, 900]), None), answered(false));
    }
}
