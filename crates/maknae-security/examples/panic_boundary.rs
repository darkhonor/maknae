//! Release-profile proof that the composition's panic boundary holds (#544):
//! run by `ci/gates/panic-strategy.sh --release-proof`. Under `panic = "abort"`
//! the process dies inside the first `guarded_decide_cited` call.

use std::process::ExitCode;

use maknae_security::{
    compose_decide_cited, decide_each_cited, finalize, guarded_decide_cited, Action, Attributes,
    Authorizer, Context, Decided, Decision, Request, Resource, Subject, Verdict,
};

struct Panics;

impl Authorizer for Panics {
    fn decide(&self, _: &Request) -> Verdict {
        panic!("panic_boundary: operand panics by design")
    }
    fn decide_cited_all(&self, reqs: &[Request]) -> Vec<Decided> {
        decide_each_cited(self, reqs)
    }
}

struct Permits;

impl Authorizer for Permits {
    fn decide(&self, _: &Request) -> Verdict {
        Verdict::Permit {
            obligations: vec![],
        }
    }
    fn decide_cited_all(&self, reqs: &[Request]) -> Vec<Decided> {
        decide_each_cited(self, reqs)
    }
}

fn main() -> ExitCode {
    let req = Request {
        subject: Subject(Attributes::new()),
        resource: Resource(Attributes::new()),
        action: Action("panic_boundary".into()),
        context: Context(Attributes::new()),
    };
    let operand = guarded_decide_cited(&Panics, &req);
    let expected_operand = Decided {
        verdict: Verdict::Indeterminate,
        role: None,
        rule: None,
    };
    if operand != expected_operand {
        eprintln!("panic_boundary: the guarded operand gave {operand:?}, not {expected_operand:?}");
        return ExitCode::FAILURE;
    }
    let composed = compose_decide_cited(&[&Permits, &Panics], &req).verdict;
    let expected_composed = Verdict::Deny {
        reason: "indeterminate operand blocks (fail-closed)".into(),
    };
    if composed != expected_composed {
        eprintln!("panic_boundary: the composition gave {composed:?}, not {expected_composed:?}");
        return ExitCode::FAILURE;
    }
    if !matches!(finalize(composed), Decision::Deny { .. }) {
        eprintln!("panic_boundary: finalize did not deny");
        return ExitCode::FAILURE;
    }
    if !cfg!(panic = "unwind") {
        eprintln!("panic_boundary: built without panic = \"unwind\"");
        return ExitCode::FAILURE;
    }
    println!("panic boundary: unwind; operand Indeterminate; composition Deny");
    ExitCode::SUCCESS
}
