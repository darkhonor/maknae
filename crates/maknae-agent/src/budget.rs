//! The conversation's context budget (#372): the user declares the model's
//! window, and the loop meters each turn against it before sending, so a
//! conversation stops cleanly rather than being refused by the provider.
use maknae_proto::{Usage, DEFAULT_BYTES_PER_TOKEN, MAX_CONTEXT_TOKENS, PREAMBLE_ALLOWANCE_TOKENS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextBudget {
    context_tokens: u64,
    output_tokens: Option<u64>,
}

impl ContextBudget {
    /// `context_tokens` ≤ `MAX_CONTEXT_TOKENS`, `output_tokens` in `1..context_tokens`, and
    /// the prompt budget must exceed `PREAMBLE_ALLOWANCE_TOKENS`, so the floor is 1,537.
    pub fn new(context_tokens: u64, output_tokens: Option<u64>) -> Result<Self, String> {
        if context_tokens > MAX_CONTEXT_TOKENS {
            return Err(format!(
                "context_tokens {context_tokens} is above the {MAX_CONTEXT_TOKENS} ceiling"
            ));
        }
        let prompt_budget = match output_tokens {
            Some(0) => return Err("output_tokens must be at least 1".into()),
            Some(o) => context_tokens.checked_sub(o),
            None => Some(context_tokens),
        };
        match prompt_budget {
            Some(p) if p > PREAMBLE_ALLOWANCE_TOKENS => Ok(ContextBudget {
                context_tokens,
                output_tokens,
            }),
            _ => Err(format!(
                "context_tokens less output_tokens must exceed the {PREAMBLE_ALLOWANCE_TOKENS}-token preamble allowance"
            )),
        }
    }
    pub fn prompt_budget(&self) -> u64 {
        self.context_tokens - self.output_tokens.unwrap_or(0)
    }
    pub fn context_tokens(&self) -> u64 {
        self.context_tokens
    }
    pub fn output_tokens(&self) -> Option<u64> {
        self.output_tokens
    }
}

pub fn prompt_cap(context_tokens: u64) -> usize {
    context_tokens.saturating_mul(6).clamp(65_536, 16_777_216) as usize
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notice {
    pub percent: u64,
    pub tokens: u64,
    pub budget: u64,
    pub estimated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Send(Option<Notice>),
    Stop,
}

pub struct Meter {
    budget: ContextBudget,
    first: Option<(u64, u64)>,
    last: Option<(u64, u64)>,
    warned_80: bool,
    warned_95: bool,
}

impl Meter {
    pub fn new(budget: ContextBudget) -> Self {
        Meter {
            budget,
            first: None,
            last: None,
            warned_80: false,
            warned_95: false,
        }
    }

    pub fn record(&mut self, bytes_sent: u64, usage: Option<Usage>) {
        let Some(u) = usage.filter(|u| u.prompt_tokens > 0) else {
            return;
        };
        let m = (bytes_sent, u.prompt_tokens.min(MAX_CONTEXT_TOKENS));
        self.first.get_or_insert(m);
        self.last = Some(m);
    }

    fn ratio(&self) -> u128 {
        match (self.first, self.last) {
            (Some((bf, tf)), Some((bl, tl))) if bl > bf && tl > tf => {
                let observed = u128::from(bl - bf) / u128::from(tl - tf);
                observed.clamp(1, u128::from(DEFAULT_BYTES_PER_TOKEN))
            }
            _ => u128::from(DEFAULT_BYTES_PER_TOKEN),
        }
    }

    /// A measured projection never falls below the bytes at the default ratio,
    /// so a provider that under-reports usage cannot switch the meter off.
    fn projected(&self, bytes: u64) -> (u128, bool) {
        let floor = u128::from(bytes).div_ceil(u128::from(DEFAULT_BYTES_PER_TOKEN));
        match self.last {
            Some((bl, tl)) => (
                (u128::from(tl) + u128::from(bytes.saturating_sub(bl)).div_ceil(self.ratio()))
                    .max(floor),
                false,
            ),
            None => (u128::from(PREAMBLE_ALLOWANCE_TOKENS) + floor, true),
        }
    }

    pub fn gate(&mut self, bytes: u64) -> Gate {
        let (projected, estimated) = self.projected(bytes);
        let budget = self.budget.prompt_budget();
        if projected > u128::from(budget) {
            return Gate::Stop;
        }
        let percent = projected * 100 / u128::from(budget);
        let notice = Notice {
            percent: percent as u64,
            tokens: projected as u64,
            budget,
            estimated,
        };
        if percent >= 95 && !self.warned_95 {
            self.warned_95 = true;
            self.warned_80 = true;
            Gate::Send(Some(notice))
        } else if percent >= 80 && !self.warned_80 {
            self.warned_80 = true;
            Gate::Send(Some(notice))
        } else {
            Gate::Send(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{
        Usage, DEFAULT_BYTES_PER_TOKEN, MAX_CONTEXT_TOKENS, PREAMBLE_ALLOWANCE_TOKENS,
    };
    fn meter(ctx: u64, out: Option<u64>) -> Meter {
        Meter::new(ContextBudget::new(ctx, out).unwrap())
    }
    fn measured(m: &mut Meter, bytes: u64, tokens: u64) {
        m.record(
            bytes,
            Some(Usage {
                prompt_tokens: tokens,
                completion_tokens: None,
            }),
        );
    }
    fn warns(g: Gate) -> Option<(u64, u64, bool)> {
        match g {
            Gate::Send(Some(n)) => Some((n.percent, n.tokens, n.estimated)),
            _ => None,
        }
    }

    #[test]
    fn a_context_budget_is_validated() {
        assert!(ContextBudget::new(1_023, None).is_err());
        assert!(ContextBudget::new(PREAMBLE_ALLOWANCE_TOKENS, None).is_err());
        let b = ContextBudget::new(PREAMBLE_ALLOWANCE_TOKENS + 1, None).unwrap();
        assert_eq!(
            (b.context_tokens(), b.output_tokens(), b.prompt_budget()),
            (1_537, None, 1_537)
        );
        assert!(ContextBudget::new(MAX_CONTEXT_TOKENS, None).is_ok());
        assert!(ContextBudget::new(MAX_CONTEXT_TOKENS + 1, None).is_err());
        assert!(ContextBudget::new(4_096, Some(4_096)).is_err());
        assert!(ContextBudget::new(4_096, Some(5_000)).is_err());
        assert!(ContextBudget::new(4_096, Some(0)).is_err());
        assert!(ContextBudget::new(4_096, Some(2_600)).is_err());
        let o = ContextBudget::new(4_096, Some(2_000)).unwrap();
        assert_eq!(
            (o.context_tokens(), o.output_tokens(), o.prompt_budget()),
            (4_096, Some(2_000), 2_096)
        );
        let edge = ContextBudget::new(4_096, Some(4_096 - 1_537)).unwrap();
        assert_eq!(edge.prompt_budget(), 1_537);
    }

    #[test]
    fn the_prompt_cap_follows_the_declared_context() {
        assert_eq!(prompt_cap(1_537), 65_536);
        assert_eq!(prompt_cap(128_000), 768_000);
        assert_eq!(prompt_cap(MAX_CONTEXT_TOKENS), 16_777_216);
    }

    #[test]
    fn the_thresholds_fire_once_each_at_80_and_95_and_stop_past_the_budget() {
        let mut m = meter(2_000, None);
        measured(&mut m, 4_000, 1_000);
        assert_eq!(m.gate(4_000 + 4 * 580), Gate::Send(None));
        assert_eq!(warns(m.gate(4_000 + 4 * 600)), Some((80, 1_600, false)));
        assert_eq!(m.gate(4_000 + 4 * 610), Gate::Send(None));
        assert_eq!(m.gate(4_000 + 4 * 880), Gate::Send(None));
        assert_eq!(warns(m.gate(4_000 + 4 * 900)), Some((95, 1_900, false)));
        assert_eq!(m.gate(4_000 + 4 * 1_000), Gate::Send(None));
        assert_eq!(m.gate(4_000 + 4 * 1_001), Gate::Stop);
    }

    #[test]
    fn a_jump_past_95_suppresses_the_later_80_warning() {
        let mut m = meter(10_000, None);
        measured(&mut m, 0, 1);
        assert_eq!(warns(m.gate(4 * 9_600)), Some((96, 9_601, false)));
        assert_eq!(m.gate(4 * 8_500), Gate::Send(None));
    }

    #[test]
    fn output_tokens_come_out_of_the_prompt_budget() {
        let mut m = meter(10_000, Some(2_000));
        measured(&mut m, 0, 1);
        assert_eq!(
            m.gate(4 * 7_999),
            Gate::Send(Some(Notice {
                percent: 100,
                tokens: 8_000,
                budget: 8_000,
                estimated: false
            }))
        );
        assert_eq!(m.gate(4 * 8_000), Gate::Stop);
    }

    #[test]
    fn the_first_turn_counts_the_preamble_allowance() {
        let budget = PREAMBLE_ALLOWANCE_TOKENS + 1_000;
        assert_eq!(
            meter(budget, None).gate(DEFAULT_BYTES_PER_TOKEN * 1_001),
            Gate::Stop
        );
        assert_eq!(
            warns(meter(budget, None).gate(DEFAULT_BYTES_PER_TOKEN * 1_000)),
            Some((100, budget, true))
        );
        assert_eq!(
            warns(meter(budget, None).gate(DEFAULT_BYTES_PER_TOKEN * 1_000 - 3)),
            Some((100, budget, true)),
            "a partial token rounds up"
        );
    }

    #[test]
    fn a_small_first_turn_then_a_large_read_is_not_overcounted() {
        let mut m = meter(32_000, None);
        measured(&mut m, 30, 820);
        assert_eq!(m.gate(30 + 60_000), Gate::Send(None));
    }

    #[test]
    fn the_observed_ratio_is_used_below_the_default_and_clamped_at_it() {
        let mut m = meter(32_000, None);
        measured(&mut m, 0, 100);
        measured(&mut m, 30_000, 10_100);
        assert_eq!(m.gate(60_000), Gate::Send(None));
        assert_eq!(
            m.gate(76_500),
            Gate::Send(Some(Notice {
                percent: 80,
                tokens: 25_600,
                budget: 32_000,
                estimated: false
            }))
        );
        let mut offset = meter(32_000, None);
        measured(&mut offset, 12_000, 1_000);
        measured(&mut offset, 42_000, 11_000);
        assert_eq!(
            warns(offset.gate(42_000 + 3 * 14_600)),
            Some((80, 25_600, false))
        );
        let mut dense = meter(10_000, None);
        measured(&mut dense, 100, 1_600);
        measured(&mut dense, 6_100, 2_600);
        assert_eq!(
            warns(dense.gate(6_100 + 24_000)),
            Some((86, 8_600, false)),
            "6 bytes/token observed, clamped to 4, above the 7,525 floor"
        );
    }

    #[test]
    fn an_observed_ratio_below_one_byte_per_token_is_clamped_to_one() {
        let mut m = meter(10_000, None);
        measured(&mut m, 0, 100);
        measured(&mut m, 100, 300);
        assert_eq!(warns(m.gate(7_800)), Some((80, 8_000, false)));
    }

    #[test]
    fn a_ratio_without_growth_on_both_sides_falls_back_to_the_default() {
        for (first, last) in [((100, 1_000), (5, 2_000)), ((100, 1_000), (100, 2_000))] {
            let mut m = meter(10_000, None);
            measured(&mut m, first.0, first.1);
            measured(&mut m, last.0, last.1);
            assert_eq!(
                m.gate(last.0 + 6_000),
                Gate::Send(None),
                "{first:?} {last:?}"
            );
        }
        let mut flat = meter(10_000, None);
        measured(&mut flat, 100, 1_000);
        measured(&mut flat, 6_000, 1_000);
        assert_eq!(flat.gate(6_000 + 24_000), Gate::Send(None));
    }

    #[test]
    fn a_provider_that_under_reports_usage_cannot_switch_the_meter_off() {
        for (name, report) in [
            ("constant", (|_k: u64| 1_000) as fn(u64) -> u64),
            ("falling", |k: u64| {
                5_000u64.saturating_sub(k * 1_000).max(1)
            }),
            ("tiny", |_k: u64| 1),
        ] {
            let mut m = meter(10_000, None);
            let mut stopped = false;
            for k in 1..=20u64 {
                let bytes = 6_000 * k;
                if m.gate(bytes) == Gate::Stop {
                    stopped = true;
                    assert_eq!(
                        bytes, 42_000,
                        "{name}: the first bytes past 4 per token of 10,000"
                    );
                    break;
                }
                measured(&mut m, bytes, report(k));
            }
            assert!(stopped, "{name}: the meter never stopped");
        }
    }

    #[test]
    fn a_provider_without_usage_is_estimated_throughout() {
        let mut m = meter(10_000, None);
        m.record(40_000, None);
        assert_eq!(warns(m.gate(4 * 7_000)), Some((85, 8_536, true)));
    }

    #[test]
    fn hostile_usage_is_clamped_and_never_overflows_or_disables_the_meter() {
        let mut m = meter(MAX_CONTEXT_TOKENS, None);
        measured(&mut m, 100, u64::MAX);
        assert_eq!(
            m.gate(100),
            Gate::Send(Some(Notice {
                percent: 100,
                tokens: MAX_CONTEXT_TOKENS,
                budget: MAX_CONTEXT_TOKENS,
                estimated: false
            }))
        );
        assert_eq!(m.gate(u64::MAX), Gate::Stop);
        let mut z = meter(10_000, None);
        measured(&mut z, 100, 0);
        assert_eq!(warns(z.gate(4 * 7_000)), Some((85, 8_536, true)));
        let mut f = meter(10_000, None);
        measured(&mut f, 100, 1_000);
        measured(&mut f, 5, 2_000);
        assert_eq!(f.gate(100), Gate::Send(None));
    }
}
