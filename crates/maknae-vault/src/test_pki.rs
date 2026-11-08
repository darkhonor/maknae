//! A test CA and the plane identities it issues (#609).
use crate::agent_enroll::AgentId;
use crate::{agent_uri_san, CaBundle, Plane, PlaneIdentity, TrustBundle};
use maknae_crypto::plane_key::PlaneKey;
use maknae_crypto::rcgen;
use std::sync::Arc;

pub const TRUST_DOMAIN: &str = "d";

pub struct TestCa {
    pem: String,
    der: Vec<u8>,
    kp: rcgen::KeyPair,
    params: rcgen::CertificateParams,
}

/// A leaf's validity as (not-before year, not-after year), each on 1 January.
pub type Years = (i32, i32);

impl TestCa {
    pub fn new(alg: PlaneKey) -> Self {
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let kp = rcgen::KeyPair::generate_for(alg.rcgen_algorithm()).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        TestCa {
            pem: cert.pem(),
            der: cert.der().to_vec(),
            kp,
            params,
        }
    }

    pub fn trust(&self) -> Arc<TrustBundle> {
        TrustBundle::from_pins(&[&CaBundle {
            root_der: self.der.clone(),
            int_der: self.der.clone(),
        }])
        .unwrap()
    }

    pub fn leaf(&self, uri: &str, alg: PlaneKey, years: Option<Years>) -> PlaneIdentity {
        let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().unwrap())];
        if let Some((from, to)) = years {
            p.not_before = rcgen::date_time_ymd(from, 1, 1);
            p.not_after = rcgen::date_time_ymd(to, 1, 1);
        }
        let kp = rcgen::KeyPair::generate_for(alg.rcgen_algorithm()).unwrap();
        let issuer = rcgen::Issuer::from_params(&self.params, &self.kp);
        let leaf = p.signed_by(&kp, &issuer).unwrap();
        PlaneIdentity::from_parts_for_test(
            alg,
            leaf.pem(),
            vec![self.pem.clone()],
            kp.serialize_der().into(),
        )
    }

    pub fn kernel(&self, alg: PlaneKey, years: Option<Years>) -> PlaneIdentity {
        self.leaf(&Plane::Kernel.uri_san(TRUST_DOMAIN), alg, years)
    }

    pub fn cli(&self, alg: PlaneKey) -> PlaneIdentity {
        self.leaf(&Plane::Cli.uri_san(TRUST_DOMAIN), alg, None)
    }

    pub fn agent(&self, agent: &AgentId, alg: PlaneKey) -> PlaneIdentity {
        self.leaf(&agent_uri_san(TRUST_DOMAIN, agent), alg, None)
    }
}
