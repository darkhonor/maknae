# Third-party notices

Two kinds of third-party material are recorded here.

## Adapted or copied code

Code or substantial implementation portions taken into the Maknae source tree from elsewhere, beyond ordinary package-manager dependencies. Each entry names the upstream, its license, and the copyright holder, and reproduces the notice the upstream's license requires.

None at present. Add an entry here in the same PR that brings adapted code in.

## Dependency inventory

Generated from `cargo deny list -f json -l crate` over the locked dependency graph (Cargo.lock). Where a crate offers a choice of licenses, Maknae takes it under the first Apache-2.0-compatible option listed. Full license texts are in each crate's source at the pinned version. Regenerate this file when Cargo.lock changes.

| crate | version | license expression |
|---|---|---|
| aho-corasick | 1.1.5 | Unlicense OR MIT |
| anstream | 1.0.0 | MIT OR Apache-2.0 |
| anstyle | 1.0.14 | MIT OR Apache-2.0 |
| anstyle-parse | 1.0.0 | MIT OR Apache-2.0 |
| anstyle-query | 1.1.5 | MIT OR Apache-2.0 |
| anstyle-wincon | 3.0.11 | MIT OR Apache-2.0 |
| anyhow | 1.0.104 | MIT OR Apache-2.0 |
| arc-swap | 1.9.2 | MIT OR Apache-2.0 |
| arraydeque | 0.5.1 | MIT OR Apache-2.0 |
| asn1-rs | 0.6.2 | MIT OR Apache-2.0 |
| asn1-rs-derive | 0.5.1 | MIT OR Apache-2.0 |
| asn1-rs-impl | 0.2.0 | MIT OR Apache-2.0 |
| async-trait | 0.1.92 | MIT OR Apache-2.0 |
| atomic-waker | 1.1.2 | Apache-2.0 OR MIT |
| autocfg | 1.5.1 | Apache-2.0 OR MIT |
| aws-lc-fips-sys | 0.14.1 | ISC OR Apache-2.0 OR OpenSSL |
| aws-lc-rs | 1.18.0 | ISC OR Apache-2.0 |
| aws-lc-sys | 0.44.0 | ISC OR Apache-2.0 OR MIT OR BSD-3-Clause OR MIT-0 |
| base64 | 0.22.1 | MIT OR Apache-2.0 |
| bindgen | 0.72.1 | BSD-3-Clause |
| bitflags | 2.13.1 | MIT OR Apache-2.0 |
| bumpalo | 3.20.3 | MIT OR Apache-2.0 |
| bytes | 1.12.1 | MIT |
| cc | 1.4.2 | MIT OR Apache-2.0 |
| cexpr | 0.6.0 | Apache-2.0 OR MIT |
| cfg-if | 1.0.4 | MIT OR Apache-2.0 |
| cfg_aliases | 0.2.2 | MIT |
| ciborium | 0.2.2 | Apache-2.0 |
| ciborium-io | 0.2.2 | Apache-2.0 |
| ciborium-ll | 0.2.2 | Apache-2.0 |
| clang-sys | 1.9.1 | Apache-2.0 |
| clap | 4.6.6 | MIT OR Apache-2.0 |
| clap_builder | 4.6.6 | MIT OR Apache-2.0 |
| clap_derive | 4.6.4 | MIT OR Apache-2.0 |
| clap_lex | 1.1.0 | MIT OR Apache-2.0 |
| cmake | 0.1.58 | MIT OR Apache-2.0 |
| colorchoice | 1.0.5 | MIT OR Apache-2.0 |
| core-foundation | 0.10.1 | MIT OR Apache-2.0 |
| core-foundation-sys | 0.8.7 | MIT OR Apache-2.0 |
| crunchy | 0.2.4 | MIT |
| darling | 0.14.4 | MIT |
| darling_core | 0.14.4 | MIT |
| darling_macro | 0.14.4 | MIT |
| data-encoding | 2.11.1 | MIT |
| der-parser | 9.0.0 | MIT OR Apache-2.0 |
| deranged | 0.5.8 | MIT OR Apache-2.0 |
| derive_builder | 0.12.0 | MIT OR Apache-2.0 |
| derive_builder_core | 0.12.0 | MIT OR Apache-2.0 |
| derive_builder_macro | 0.12.0 | MIT OR Apache-2.0 |
| displaydoc | 0.2.7 | MIT OR Apache-2.0 |
| dunce | 1.0.5 | CC0-1.0 OR MIT-0 OR Apache-2.0 |
| either | 1.17.0 | MIT OR Apache-2.0 |
| encoding_rs | 0.8.35 | Apache-2.0 OR MIT OR BSD-3-Clause |
| errno | 0.3.14 | MIT OR Apache-2.0 |
| find-msvc-tools | 0.1.10 | MIT OR Apache-2.0 |
| fnv | 1.0.7 | Apache-2.0 OR MIT |
| foldhash | 0.2.0 | Zlib |
| form_urlencoded | 1.2.2 | MIT OR Apache-2.0 |
| fs_extra | 1.3.0 | MIT |
| futures-channel | 0.3.33 | MIT OR Apache-2.0 |
| futures-core | 0.3.33 | MIT OR Apache-2.0 |
| futures-task | 0.3.33 | MIT OR Apache-2.0 |
| futures-util | 0.3.33 | MIT OR Apache-2.0 |
| getrandom | 0.2.17 | MIT OR Apache-2.0 |
| getrandom | 0.4.3 | MIT OR Apache-2.0 |
| glob | 0.3.4 | MIT OR Apache-2.0 |
| half | 2.7.1 | MIT OR Apache-2.0 |
| hashbrown | 0.16.1 | MIT OR Apache-2.0 |
| hashlink | 0.11.1 | MIT OR Apache-2.0 |
| heck | 0.5.0 | MIT OR Apache-2.0 |
| http | 1.5.0 | MIT OR Apache-2.0 |
| http-body | 1.1.0 | MIT |
| http-body-util | 0.1.4 | MIT |
| httparse | 1.10.1 | MIT OR Apache-2.0 |
| hyper | 1.11.0 | MIT |
| hyper-rustls | 0.27.9 | Apache-2.0 OR ISC OR MIT |
| hyper-util | 0.1.20 | MIT |
| icu_collections | 2.2.0 | Unicode-3.0 |
| icu_locale_core | 2.2.0 | Unicode-3.0 |
| icu_normalizer | 2.2.0 | Unicode-3.0 |
| icu_normalizer_data | 2.2.0 | Unicode-3.0 |
| icu_properties | 2.2.0 | Unicode-3.0 |
| icu_properties_data | 2.2.0 | Unicode-3.0 |
| icu_provider | 2.2.0 | Unicode-3.0 |
| ident_case | 1.0.1 | MIT OR Apache-2.0 |
| idna | 1.1.0 | MIT OR Apache-2.0 |
| idna_adapter | 1.2.2 | Apache-2.0 OR MIT |
| ipnet | 2.12.1 | MIT OR Apache-2.0 |
| is_terminal_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| itertools | 0.13.0 | MIT OR Apache-2.0 |
| itoa | 1.0.18 | MIT OR Apache-2.0 |
| jobserver | 0.1.35 | MIT OR Apache-2.0 |
| js-sys | 0.3.104 | MIT OR Apache-2.0 |
| lazy_static | 1.5.0 | MIT OR Apache-2.0 |
| libc | 0.2.189 | MIT OR Apache-2.0 |
| libloading | 0.8.9 | ISC |
| linux-raw-sys | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| litemap | 0.8.2 | Unicode-3.0 |
| log | 0.4.33 | MIT OR Apache-2.0 |
| maknae 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/bins/maknae | Apache-2.0 |
| maknae-audit 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-audit | Apache-2.0 |
| maknae-audit-append 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-audit-append | Apache-2.0 |
| maknae-authz-basic 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-authz-basic | Apache-2.0 |
| maknae-classification-aus 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-classification-aus | Apache-2.0 |
| maknae-config 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-config | Apache-2.0 |
| maknae-io 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-io | Apache-2.0 |
| maknae-kernel 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-kernel | Apache-2.0 |
| maknae-llm 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-llm | Apache-2.0 |
| maknae-mcp 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-mcp | Apache-2.0 |
| maknae-msgs 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-msgs | Apache-2.0 |
| maknae-plane 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-plane | Apache-2.0 |
| maknae-proto 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-proto | Apache-2.0 |
| maknae-security 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-security | Apache-2.0 |
| maknae-spif 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-spif | Apache-2.0 |
| maknae-spif-compile 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-spif-compile | Apache-2.0 |
| maknae-spifc 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/bins/maknae-spifc | Apache-2.0 |
| maknae-subject-ctx 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-subject-ctx | Apache-2.0 |
| maknae-subject-ctx-mint 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-subject-ctx-mint | Apache-2.0 |
| maknae-vault 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/crates/maknae-vault | Apache-2.0 |
| maknaed 0.0.0 path+file:///Users/aackerman/Development/Agents/maknae/bins/maknaed | Apache-2.0 |
| memchr | 2.8.3 | Unlicense OR MIT |
| memoffset | 0.9.1 | MIT |
| minimal-lexical | 0.2.1 | MIT OR Apache-2.0 |
| mio | 1.2.2 | MIT |
| nix | 0.31.3 | MIT |
| nom | 7.1.3 | MIT |
| num-bigint | 0.4.8 | MIT OR Apache-2.0 |
| num-conv | 0.2.2 | MIT OR Apache-2.0 |
| num-integer | 0.1.46 | MIT OR Apache-2.0 |
| num-traits | 0.2.19 | MIT OR Apache-2.0 |
| oid-registry | 0.7.1 | MIT OR Apache-2.0 |
| once_cell | 1.21.4 | MIT OR Apache-2.0 |
| once_cell_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| pem | 3.0.6 | MIT |
| percent-encoding | 2.3.2 | MIT OR Apache-2.0 |
| pin-project-lite | 0.2.17 | Apache-2.0 OR MIT |
| pkg-config | 0.3.33 | MIT OR Apache-2.0 |
| potential_utf | 0.1.5 | Unicode-3.0 |
| powerfmt | 0.2.0 | MIT OR Apache-2.0 |
| prettyplease | 0.2.37 | MIT OR Apache-2.0 |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 |
| quote | 1.0.47 | MIT OR Apache-2.0 |
| r-efi | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| rcgen | 0.13.2 | MIT OR Apache-2.0 |
| regex | 1.13.1 | MIT OR Apache-2.0 |
| regex-automata | 0.4.18 | MIT OR Apache-2.0 |
| regex-syntax | 0.8.11 | MIT OR Apache-2.0 |
| reqwest | 0.12.28 | MIT OR Apache-2.0 |
| ring | 0.17.14 | Apache-2.0 OR ISC |
| rpassword | 7.5.4 | Apache-2.0 |
| rtoolbox | 0.0.5 | Apache-2.0 |
| rustc-hash | 2.1.3 | Apache-2.0 OR MIT |
| rusticata-macros | 4.1.0 | MIT OR Apache-2.0 |
| rustify | 0.6.1 | MIT |
| rustify_derive | 0.5.5 | MIT |
| rustix | 1.1.4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| rustls | 0.23.43 | Apache-2.0 OR ISC OR MIT |
| rustls-pki-types | 1.15.1 | MIT OR Apache-2.0 |
| rustls-webpki | 0.103.13 | ISC |
| rustversion | 1.0.23 | MIT OR Apache-2.0 |
| ryu | 1.0.23 | Apache-2.0 OR BSL-1.0 |
| security-framework | 3.7.0 | MIT OR Apache-2.0 |
| security-framework-sys | 2.17.0 | MIT OR Apache-2.0 |
| serde | 1.0.229 | MIT OR Apache-2.0 |
| serde_core | 1.0.229 | MIT OR Apache-2.0 |
| serde_derive | 1.0.229 | MIT OR Apache-2.0 |
| serde_json | 1.0.151 | MIT OR Apache-2.0 |
| serde_urlencoded | 0.7.1 | MIT OR Apache-2.0 |
| shlex | 1.3.0 | MIT OR Apache-2.0 |
| shlex | 2.0.1 | MIT OR Apache-2.0 |
| signal-hook-registry | 1.4.8 | MIT OR Apache-2.0 |
| slab | 0.4.12 | MIT |
| smallvec | 1.15.2 | MIT OR Apache-2.0 |
| socket2 | 0.6.5 | MIT OR Apache-2.0 |
| stable_deref_trait | 1.2.1 | MIT OR Apache-2.0 |
| strsim | 0.10.0 | MIT |
| strsim | 0.11.1 | MIT |
| subtle | 2.6.1 | BSD-3-Clause |
| syn | 1.0.109 | MIT OR Apache-2.0 |
| syn | 2.0.119 | MIT OR Apache-2.0 |
| syn | 3.0.3 | MIT OR Apache-2.0 |
| sync_wrapper | 1.0.2 | Apache-2.0 |
| synstructure | 0.12.6 | MIT |
| synstructure | 0.13.2 | MIT |
| thiserror | 1.0.69 | MIT OR Apache-2.0 |
| thiserror-impl | 1.0.69 | MIT OR Apache-2.0 |
| time | 0.3.55 | MIT OR Apache-2.0 |
| time-core | 0.1.9 | MIT OR Apache-2.0 |
| time-macros | 0.2.32 | MIT OR Apache-2.0 |
| tinystr | 0.8.3 | Unicode-3.0 |
| tokio | 1.53.1 | MIT |
| tokio-macros | 2.7.2 | MIT |
| tokio-rustls | 0.26.4 | MIT OR Apache-2.0 |
| tower | 0.5.3 | MIT |
| tower-http | 0.6.11 | MIT |
| tower-layer | 0.3.3 | MIT |
| tower-service | 0.3.3 | MIT |
| tracing | 0.1.44 | MIT |
| tracing-attributes | 0.1.31 | MIT |
| tracing-core | 0.1.36 | MIT |
| try-lock | 0.2.5 | MIT |
| unicode-ident | 1.0.24 | MIT OR Apache-2.0 OR Unicode-3.0 |
| unicode-xid | 0.2.6 | MIT OR Apache-2.0 |
| untrusted | 0.9.0 | ISC |
| url | 2.5.8 | MIT OR Apache-2.0 |
| utf8_iter | 1.0.4 | Apache-2.0 OR MIT |
| utf8parse | 0.2.2 | Apache-2.0 OR MIT |
| vaultrs | 0.7.4 | MIT |
| want | 0.3.1 | MIT |
| wasi | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasm-bindgen | 0.2.127 | MIT OR Apache-2.0 |
| wasm-bindgen-futures | 0.4.77 | MIT OR Apache-2.0 |
| wasm-bindgen-macro | 0.2.127 | MIT OR Apache-2.0 |
| wasm-bindgen-macro-support | 0.2.127 | MIT OR Apache-2.0 |
| wasm-bindgen-shared | 0.2.127 | MIT OR Apache-2.0 |
| web-sys | 0.3.104 | MIT OR Apache-2.0 |
| webpki-roots | 1.0.9 | CDLA-Permissive-2.0 |
| windows-link | 0.2.1 | MIT OR Apache-2.0 |
| windows-sys | 0.52.0 | MIT OR Apache-2.0 |
| windows-sys | 0.59.0 | MIT OR Apache-2.0 |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 |
| windows-targets | 0.52.6 | MIT OR Apache-2.0 |
| windows_aarch64_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_aarch64_msvc | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_gnu | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_msvc | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_gnu | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_msvc | 0.52.6 | MIT OR Apache-2.0 |
| writeable | 0.6.3 | Unicode-3.0 |
| x509-parser | 0.16.0 | MIT OR Apache-2.0 |
| yaml-rust2 | 0.11.0 | MIT OR Apache-2.0 |
| yasna | 0.5.2 | MIT OR Apache-2.0 |
| yoke | 0.8.3 | Unicode-3.0 |
| yoke-derive | 0.8.2 | Unicode-3.0 |
| zerocopy | 0.8.56 | BSD-2-Clause OR Apache-2.0 OR MIT |
| zerocopy-derive | 0.8.56 | BSD-2-Clause OR Apache-2.0 OR MIT |
| zerofrom | 0.1.8 | Unicode-3.0 |
| zerofrom-derive | 0.1.7 | Unicode-3.0 |
| zeroize | 1.9.0 | Apache-2.0 OR MIT |
| zerotrie | 0.2.4 | Unicode-3.0 |
| zerovec | 0.11.6 | Unicode-3.0 |
| zerovec-derive | 0.11.3 | Unicode-3.0 |
| zmij | 1.0.23 | MIT |
