use sha2::{Digest, Sha512_256};
use trax::config::HashAlgorithm;
use trax::crypto::{hash_domain, Hash};
use trax::merkle::{merkle_root, MerkleAccumulator, MAX_MERKLE_LEAVES};
use trax::TraxError;
fn reference_hash(algorithm: HashAlgorithm, parts: &[&[u8]]) -> Hash {
    let bytes = parts.concat();
    match algorithm {
        HashAlgorithm::Sha512256 => Sha512_256::digest(bytes).into(),
        #[cfg(feature = "hash-blake3")]
        HashAlgorithm::Blake3 => blake3::hash(&bytes).into(),
        #[cfg(not(feature = "hash-blake3"))]
        HashAlgorithm::Blake3 => panic!("unavailable test profile"),
    }
}

fn reference_tree(algorithm: HashAlgorithm, messages: &[Vec<u8>], offset: usize) -> Hash {
    if messages.len() == 1 {
        return reference_hash(
            algorithm,
            &[
                b"TRAX:MERKLE:LEAF:V2\0",
                &(offset as u64).to_be_bytes(),
                &(messages[0].len() as u64).to_be_bytes(),
                &messages[0],
            ],
        );
    }
    let mut at = 1;
    while at * 2 < messages.len() {
        at *= 2;
    }
    let left = reference_tree(algorithm, &messages[..at], offset);
    let right = reference_tree(algorithm, &messages[at..], offset + at);
    reference_hash(algorithm, &[b"TRAX:MERKLE:NODE:V2\0", &left, &right])
}

fn reference_root(algorithm: HashAlgorithm, messages: &[Vec<u8>]) -> Hash {
    let tree = reference_tree(algorithm, messages, 0);
    reference_hash(
        algorithm,
        &[
            b"TRAX:MERKLE:ROOT:V2\0",
            &(messages.len() as u64).to_be_bytes(),
            &tree,
        ],
    )
}

fn algorithms() -> Vec<HashAlgorithm> {
    let mut result = vec![HashAlgorithm::Sha512256];
    if cfg!(feature = "hash-blake3") {
        result.push(HashAlgorithm::Blake3);
    }
    result
}

fn messages(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|index| format!("packet {index} {}", "x".repeat(index % 19)).into_bytes())
        .collect()
}

#[test]
fn streaming_and_bulk_match_independent_recursive_trees() {
    for algorithm in algorithms() {
        for count in [1, 2, 3, 7, 8, 9, 17, 35, 100, 138, 1024] {
            let messages = messages(count);
            let expected = reference_root(algorithm, &messages);
            let mut accumulator = MerkleAccumulator::new(algorithm).unwrap();
            assert!(accumulator.is_empty());
            assert!(accumulator.root().is_err());
            for (index, message) in messages.iter().enumerate() {
                accumulator.push(message).unwrap();
                assert_eq!(accumulator.len(), index + 1);
                if count <= 138 || (index + 1).is_power_of_two() {
                    assert_eq!(
                        accumulator.root().unwrap(),
                        reference_root(algorithm, &messages[..=index])
                    );
                }
            }
            assert_eq!(accumulator.root().unwrap(), expected);
            assert_eq!(merkle_root(algorithm, &messages).unwrap(), expected);
        }
    }
}

#[test]
fn golden_root_matches_independent_node_crypto_vector() {
    let messages = vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()];
    assert_eq!(
        hex::encode(merkle_root(HashAlgorithm::Sha512256, &messages).unwrap()),
        "5ca1323396a3987ffaeb77119e20d18f2761cb8be7ef8e758c328e742e8c055c"
    );
}

#[test]
fn domains_order_lengths_and_exact_count_are_bound() {
    for algorithm in algorithms() {
        assert_eq!(
            hash_domain(algorithm, b"domain\0", &[b"ab", b"c"]).unwrap(),
            reference_hash(algorithm, &[b"domain\0", b"abc"])
        );
        assert_ne!(
            hash_domain(algorithm, b"domain\0", &[b"abc"]).unwrap(),
            hash_domain(algorithm, b"other\0", &[b"abc"]).unwrap()
        );
        let original = messages(9);
        let expected = merkle_root(algorithm, &original).unwrap();
        for index in 0..original.len() {
            let mut changed = original.clone();
            changed[index].push(0);
            assert_ne!(merkle_root(algorithm, &changed).unwrap(), expected);
        }
        let mut reordered = original.clone();
        reordered.swap(0, 1);
        assert_ne!(merkle_root(algorithm, &reordered).unwrap(), expected);
        assert_ne!(merkle_root(algorithm, &original[..8]).unwrap(), expected);
        // A raw inner tree cannot substitute for the count-bound outer root.
        assert_ne!(reference_tree(algorithm, &original, 0), expected);
        let mut extended = original;
        extended.push(extended.last().unwrap().clone());
        assert_ne!(merkle_root(algorithm, &extended).unwrap(), expected);
    }
}

#[test]
fn empty_payloads_are_indexed_leaves_without_padding_or_duplication() {
    for algorithm in algorithms() {
        let roots = [1, 2, 3].map(|count| merkle_root(algorithm, &vec![vec![]; count]).unwrap());
        assert_ne!(roots[0], roots[1]);
        assert_ne!(roots[1], roots[2]);
        assert_ne!(roots[0], roots[2]);
    }
}

#[test]
fn bounds_reject_empty_and_oversized_trees() {
    assert!(matches!(
        merkle_root(HashAlgorithm::Sha512256, &[]),
        Err(TraxError::MerkleLeafCount)
    ));
    let oversized = vec![Vec::new(); MAX_MERKLE_LEAVES + 1];
    assert!(matches!(
        merkle_root(HashAlgorithm::Sha512256, &oversized),
        Err(TraxError::MerkleLeafCount)
    ));
}

#[test]
fn hash_profile_selection_never_falls_back() {
    #[cfg(not(feature = "hash-blake3"))]
    {
        assert!(matches!(
            MerkleAccumulator::new(HashAlgorithm::Blake3),
            Err(TraxError::UnsupportedAlgorithm)
        ));
        assert!(matches!(
            hash_domain(HashAlgorithm::Blake3, b"domain", &[b"data"]),
            Err(TraxError::UnsupportedAlgorithm)
        ));
    }
    #[cfg(feature = "hash-blake3")]
    assert_ne!(
        merkle_root(HashAlgorithm::Blake3, &messages(3)).unwrap(),
        merkle_root(HashAlgorithm::Sha512256, &messages(3)).unwrap()
    );
}
