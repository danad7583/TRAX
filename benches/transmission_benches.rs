use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use ed25519_dalek::SigningKey;
use trax::config::{HashAlgorithm, TransmissionProfile};
use trax::crypto::{ed25519_sign, hash_domain};
use trax::encoding::encode_deterministic;
use trax::genesis::{accept_genesis_offer, confirm_genesis, create_genesis_offer, VerifiedGenesis};
use trax::merkle::merkle_root;
use trax::session::Relationship;

struct Fixture {
    genesis: VerifiedGenesis,
    key: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let key = SigningKey::from_bytes(&[61; 32]);
        let peer = SigningKey::from_bytes(&[62; 32]);
        let a = key.verifying_key().to_bytes();
        let b = peer.verifying_key().to_bytes();
        let offer = create_genesis_offer(&key, [63; 32], TransmissionProfile::default()).unwrap();
        let acceptance = accept_genesis_offer(&offer, &peer, |k| k == &a).unwrap();
        let confirmation = confirm_genesis(&offer, &acceptance, &key, |k| k == &b).unwrap();
        let genesis =
            VerifiedGenesis::verify([offer, acceptance, confirmation], |k| k == &a || k == &b)
                .unwrap();
        Self { genesis, key }
    }
    fn relationship(&self) -> Relationship {
        Relationship::new(self.genesis.clone()).unwrap()
    }
    fn session(&self) -> Relationship {
        let mut relationship = self.relationship();
        relationship
            .begin_session(self.key.verifying_key().to_bytes(), [64; 32])
            .unwrap();
        relationship
    }
}
fn benches(c: &mut Criterion) {
    let fixture = Fixture::new();
    let sizes = [1, 8, 17, 100, 138, 1024];
    let mut roots = c.benchmark_group("transmission/root_sha512256");
    for count in sizes {
        let messages = vec![vec![42; 1024]; count];
        roots.throughput(Throughput::Bytes((count * 1024) as u64));
        roots.bench_with_input(
            BenchmarkId::from_parameter(count),
            &messages,
            |b, messages| {
                b.iter(|| {
                    black_box(merkle_root(HashAlgorithm::Sha512256, black_box(messages)).unwrap())
                });
            },
        );
    }
    roots.finish();

    let mut build = c.benchmark_group("transmission/build_signed");
    for count in sizes {
        let chunks = vec![vec![42; 1024]; count];
        let session = fixture.session();
        build.throughput(Throughput::Bytes((count * 1024) as u64));
        build.bench_with_input(BenchmarkId::from_parameter(count), &chunks, |b, chunks| {
            b.iter(|| {
                black_box(
                    session
                        .build_transmission(&fixture.key, "request", black_box(chunks))
                        .unwrap(),
                )
            });
        });
    }
    build.finish();

    let mut verify = c.benchmark_group("transmission/verify_typed");
    for count in sizes {
        let packets = fixture
            .session()
            .build_transmission(&fixture.key, "request", &vec![vec![42; 1024]; count])
            .unwrap();
        verify.throughput(Throughput::Bytes((count * 1024) as u64));
        verify.bench_function(BenchmarkId::from_parameter(count), |b| {
            b.iter_batched(
                || {
                    let mut session = fixture.relationship();
                    session.start_receive().unwrap();
                    (session, packets.clone())
                },
                |(mut session, packets)| {
                    let mut verified = None;
                    for packet in packets {
                        verified = session.stage_packet(black_box(packet)).unwrap();
                    }
                    assert!(verified.is_some());
                    black_box((session, verified))
                },
                BatchSize::SmallInput,
            );
        });
    }
    verify.finish();

    let mut wire = c.benchmark_group("transmission/verify_wire");
    for count in sizes {
        let packets = fixture
            .session()
            .build_transmission(&fixture.key, "request", &vec![vec![42; 1024]; count])
            .unwrap();
        let encoded = packets
            .iter()
            .map(encode_deterministic)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        wire.throughput(Throughput::Bytes((count * 1024) as u64));
        wire.bench_function(BenchmarkId::from_parameter(count), |b| {
            b.iter_batched(
                || {
                    let mut session = fixture.relationship();
                    session.start_receive().unwrap();
                    session
                },
                |mut session| {
                    let mut verified = None;
                    for bytes in &encoded {
                        verified = session.stage_encoded_packet(black_box(bytes)).unwrap();
                    }
                    assert!(verified.is_some());
                    black_box((session, verified))
                },
                BatchSize::SmallInput,
            );
        });
    }
    wire.finish();

    let packets = fixture
        .session()
        .build_transmission(&fixture.key, "request", &vec![vec![42; 1024]; 8])
        .unwrap();
    c.bench_function("transmission/stage_first_nonfinal", |b| {
        b.iter_batched(
            || {
                let mut session = fixture.relationship();
                session.start_receive().unwrap();
                (session, packets[0].clone())
            },
            |(mut session, packet)| {
                assert!(session.stage_packet(black_box(packet)).unwrap().is_none());
                black_box(session)
            },
            BatchSize::SmallInput,
        );
    });
    c.bench_function("transmission/stage_final_after7", |b| {
        b.iter_batched(
            || {
                let mut session = fixture.relationship();
                session.start_receive().unwrap();
                for packet in &packets[..7] {
                    session.stage_packet(packet.clone()).unwrap();
                }
                (session, packets[7].clone())
            },
            |(mut session, packet)| {
                let verified = session.stage_packet(black_box(packet)).unwrap().unwrap();
                black_box((session, verified))
            },
            BatchSize::SmallInput,
        );
    });
    let mut signing_bytes = b"TRAX:TRANSMISSION:V3\0".to_vec();
    signing_bytes.extend_from_slice(
        &encode_deterministic(&packets[7].authentication.as_ref().unwrap().commitment).unwrap(),
    );
    c.bench_function("transmission/signature_only", |b| {
        b.iter(|| black_box(ed25519_sign(&fixture.key, black_box(&signing_bytes))))
    });

    let mut hashes = c.benchmark_group("transmission/payload_hash_sha512256");
    for size in [1024, 65536, 1048576] {
        let bytes = vec![42; size];
        hashes.throughput(Throughput::Bytes(size as u64));
        hashes.bench_with_input(BenchmarkId::from_parameter(size), &bytes, |b, bytes| {
            b.iter(|| {
                black_box(
                    hash_domain(
                        HashAlgorithm::Sha512256,
                        b"TRAX:PAYLOAD:V3\0",
                        &[black_box(bytes)],
                    )
                    .unwrap(),
                )
            })
        });
    }
    hashes.finish();
    let messages = vec![vec![42; 1024]; 8];
    #[cfg(feature = "hash-blake3")]
    c.bench_function("transmission/root_blake3_8_packets", |b| {
        b.iter(|| black_box(merkle_root(HashAlgorithm::Blake3, black_box(&messages)).unwrap()))
    });
}

criterion_group! { name = group; config = Criterion::default().without_plots(); targets = benches }
criterion_main!(group);
