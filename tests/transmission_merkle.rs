use ciborium::value::Value;
use sha2::{Digest, Sha512_256};
use trax::config::{HashAlgorithm, SegmentConfig};
use trax::encoding::{decode, encode_deterministic};
use trax::transmission_crypto::{
    hash_v2, merkle_root_and_proofs_v2, merkle_root_v2, verify_merkle_inclusion_v2, Hash,
    InclusionProofV2, MerkleAccumulatorV2, MAX_MERKLE_LEAVES,
};
#[cfg(not(feature = "hash-blake3"))]
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
fn streaming_bulk_and_every_inclusion_match_independent_recursive_trees() {
    for algorithm in algorithms() {
        for count in [1, 2, 3, 7, 8, 9, 17, 35, 100, 138] {
            let messages = messages(count);
            let expected = reference_root(algorithm, &messages);
            let mut accumulator = MerkleAccumulatorV2::new(algorithm).unwrap();
            assert!(accumulator.is_empty());
            assert!(accumulator.root().is_err());
            for (index, message) in messages.iter().enumerate() {
                accumulator.push(message).unwrap();
                assert_eq!(accumulator.len(), index + 1);
                assert_eq!(
                    accumulator.root().unwrap(),
                    reference_root(algorithm, &messages[..=index])
                );
            }
            assert_eq!(merkle_root_v2(algorithm, &messages).unwrap(), expected);
            let (root, proofs) = merkle_root_and_proofs_v2(algorithm, &messages).unwrap();
            assert_eq!(root, expected);
            assert_eq!(proofs.len(), count);
            for (index, (message, proof)) in messages.iter().zip(&proofs).enumerate() {
                assert_eq!(proof.leaf_index as usize, index);
                assert_eq!(proof.leaf_count as usize, count);
                assert!(verify_merkle_inclusion_v2(algorithm, message, proof, &root).unwrap());
            }
        }
    }
}

#[test]
fn sha512_256_golden_root_matches_independent_node_crypto_vector() {
    // Independently computed with node:crypto SHA-512/256 and a recursive tree.
    let messages = vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()];
    assert_eq!(
        hex::encode(merkle_root_v2(HashAlgorithm::Sha512256, &messages).unwrap()),
        "5ca1323396a3987ffaeb77119e20d18f2761cb8be7ef8e758c328e742e8c055c"
    );
}

#[test]
fn hash_parts_are_borrowed_ordered_and_domain_separated() {
    for algorithm in algorithms() {
        assert_eq!(
            hash_v2(algorithm, b"domain\0", &[b"ab", b"c"]).unwrap(),
            reference_hash(algorithm, &[b"domain\0", b"abc"])
        );
        assert_ne!(
            hash_v2(algorithm, b"domain\0", &[b"ab", b"c"]).unwrap(),
            hash_v2(algorithm, b"other\0", &[b"abc"]).unwrap()
        );
        assert_ne!(
            hash_v2(algorithm, b"domain\0", &[b"a", b"bc"]).unwrap(),
            hash_v2(algorithm, b"domain\0", &[b"bc", b"a"]).unwrap()
        );
    }
}

#[test]
fn count_index_message_and_exact_sibling_path_are_bound() {
    let algorithm = HashAlgorithm::Sha512256;
    let messages = messages(9);
    let (root, proofs) = merkle_root_and_proofs_v2(algorithm, &messages).unwrap();
    for (index, proof) in proofs.iter().enumerate() {
        let mut longer = messages[index].clone();
        longer.push(0);
        assert!(!verify_merkle_inclusion_v2(algorithm, &longer, proof, &root).unwrap());
        let mut changed = proof.clone();
        changed.leaf_index = ((index + 1) % messages.len()) as u32;
        assert!(
            !verify_merkle_inclusion_v2(algorithm, &messages[index], &changed, &root)
                .unwrap_or(false)
        );
        let mut changed = proof.clone();
        changed.leaf_count += 1;
        assert!(
            !verify_merkle_inclusion_v2(algorithm, &messages[index], &changed, &root)
                .unwrap_or(false)
        );
        let mut changed = proof.clone();
        changed.siblings.push([0; 32]);
        assert!(verify_merkle_inclusion_v2(algorithm, &messages[index], &changed, &root).is_err());
        let mut changed = proof.clone();
        changed.siblings.pop();
        assert!(verify_merkle_inclusion_v2(algorithm, &messages[index], &changed, &root).is_err());
        let mut changed = proof.clone();
        changed.siblings[0][0] ^= 1;
        assert!(!verify_merkle_inclusion_v2(algorithm, &messages[index], &changed, &root).unwrap());
    }
    let mut reordered = messages.clone();
    reordered.swap(0, 1);
    assert_ne!(merkle_root_v2(algorithm, &reordered).unwrap(), root);
}

#[test]
fn empty_leaves_are_real_indexed_events_not_padding_or_tree_duplication() {
    let algorithm = HashAlgorithm::Sha512256;
    let one = vec![vec![]];
    let two = vec![vec![], vec![]];
    let three = vec![vec![], vec![], vec![]];
    assert_ne!(
        merkle_root_v2(algorithm, &one).unwrap(),
        merkle_root_v2(algorithm, &two).unwrap()
    );
    assert_ne!(
        merkle_root_v2(algorithm, &two).unwrap(),
        merkle_root_v2(algorithm, &three).unwrap()
    );
    let (root, proofs) = merkle_root_and_proofs_v2(algorithm, &one).unwrap();
    assert!(proofs[0].siblings.is_empty());
    assert!(verify_merkle_inclusion_v2(algorithm, b"", &proofs[0], &root).unwrap());
}

#[test]
fn legacy_roots_cannot_verify_as_v2() {
    let messages = messages(8);
    let (root, proofs) = merkle_root_and_proofs_v2(HashAlgorithm::Sha512256, &messages).unwrap();
    let legacy = trax::crypto::merkle_root(SegmentConfig::new(8).unwrap(), &messages).unwrap();
    assert_ne!(legacy, root);
    for (message, proof) in messages.iter().zip(&proofs) {
        assert!(
            !verify_merkle_inclusion_v2(HashAlgorithm::Sha512256, message, proof, &legacy).unwrap()
        );
    }
}

#[test]
fn bounds_reject_empty_oversized_or_impossible_proofs() {
    let algorithm = HashAlgorithm::Sha512256;
    assert!(merkle_root_v2(algorithm, &[]).is_err());
    assert!(merkle_root_and_proofs_v2(algorithm, &[]).is_err());
    let oversized = vec![Vec::new(); MAX_MERKLE_LEAVES + 1];
    assert!(merkle_root_v2(algorithm, &oversized).is_err());
    assert!(merkle_root_and_proofs_v2(algorithm, &oversized).is_err());
    for (index, count, siblings) in [
        (0, 0, vec![]),
        (1, 1, vec![]),
        (0, MAX_MERKLE_LEAVES as u32 + 1, vec![]),
        (0, 1, vec![[0; 32]; 21]),
    ] {
        let proof = InclusionProofV2 {
            leaf_index: index,
            leaf_count: count,
            siblings,
        };
        assert!(verify_merkle_inclusion_v2(algorithm, b"x", &proof, &[0; 32]).is_err());
    }
}

#[test]
fn proof_wire_hashes_are_exact_byte_strings_and_unknown_fields_fail() {
    let (_, proofs) = merkle_root_and_proofs_v2(HashAlgorithm::Sha512256, &messages(3)).unwrap();
    let proof = &proofs[0];
    let bytes = encode_deterministic(proof).unwrap();
    assert_eq!(decode::<InclusionProofV2>(&bytes).unwrap(), *proof);
    let mut value: Value = decode(&bytes).unwrap();
    let fields = value.as_map_mut().unwrap();
    let (_, siblings) = fields
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some("siblings"))
        .unwrap();
    assert!(siblings
        .as_array()
        .unwrap()
        .iter()
        .all(|hash| hash.as_bytes().is_some_and(|b| b.len() == 32)));
    siblings.as_array_mut().unwrap()[0] = Value::Bytes(vec![0; 31]);
    assert!(decode::<InclusionProofV2>(&encode_deterministic(&value).unwrap()).is_err());
    let mut value: Value = decode(&bytes).unwrap();
    value
        .as_map_mut()
        .unwrap()
        .push((Value::Text("unknown".into()), Value::Null));
    assert!(decode::<InclusionProofV2>(&encode_deterministic(&value).unwrap()).is_err());
}

#[test]
fn unsupported_profile_is_rejected_without_fallback() {
    #[cfg(not(feature = "hash-blake3"))]
    {
        assert!(matches!(
            MerkleAccumulatorV2::new(HashAlgorithm::Blake3),
            Err(TraxError::UnsupportedAlgorithm)
        ));
        assert!(matches!(
            hash_v2(HashAlgorithm::Blake3, b"domain", &[b"data"]),
            Err(TraxError::UnsupportedAlgorithm)
        ));
    }
    #[cfg(feature = "hash-blake3")]
    {
        let messages = messages(3);
        assert_ne!(
            merkle_root_v2(HashAlgorithm::Blake3, &messages).unwrap(),
            merkle_root_v2(HashAlgorithm::Sha512256, &messages).unwrap()
        );
    }
}
