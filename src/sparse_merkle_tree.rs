use crate::common::*;

/// Node in the SMT can be:
/// - Empty: no data (has zero digest).
/// - Leaf: stores a key digest and a value.
/// - Branch: has left child and right child, each is a Node.
#[derive(Clone, Debug)]
enum Node {
    Empty,
    Leaf { key_digest: Digest, value: String },
    Branch { left: Box<Node>, right: Box<Node> },
}

/// Direction enum to represent path direction in the tree
#[derive(Debug, Clone, PartialEq)]
pub enum Direction {
    Left,
    Right,
}

impl Node {
    /// Compute the digest of this node (recursive).
    /// - Empty => zero_digest()
    /// - Leaf => hash_two_things(key_digest, value)
    /// - Branch => hash_two_things(left_digest, right_digest)
    fn digest(&self) -> Digest {
        match self {
            Node::Empty => zero_digest(),
            Node::Leaf { key_digest, value } => {
                hash_two_things("leaf_key", "leaf_val", key_digest, value)
            }
            Node::Branch { left, right } => {
                let ld = left.digest();
                let rd = right.digest();
                hash_two_things("branch_left", "branch_right", ld, rd)
            }
        }
    }

    /// Print tree structure (recursive).
    fn debug_print(&self, indent: usize) {
        let spacer = " ".repeat(indent);
        match self {
            Node::Empty => {
                let digest = self.digest();
                let short_digest = format!("{:?}", digest);
                let short_digest =
                    &short_digest[0..std::cmp::min(16, short_digest.len())];
                println!("{}Empty (digest: {})", spacer, short_digest);
            }
            Node::Leaf { key_digest, value } => {
                let node_digest = self.digest();
                let short_kd = format!("{:?}", key_digest);
                let short_kd = &short_kd[0..std::cmp::min(16, short_kd.len())];
                let short_digest = format!("{:?}", node_digest);
                let short_digest =
                    &short_digest[0..std::cmp::min(16, short_digest.len())];
                println!(
                    "{}Leaf {{ key_digest: {}, value: {}, node_digest: {} }}",
                    spacer, short_kd, value, short_digest
                );
            }
            Node::Branch { left, right } => {
                let node_digest = self.digest();
                let short_digest = format!("{:?}", node_digest);
                let short_digest =
                    &short_digest[0..std::cmp::min(16, short_digest.len())];
                println!("{}Branch (digest: {})", spacer, short_digest);
                println!("{}  left:", spacer);
                left.debug_print(indent + 4);
                println!("{}  right:", spacer);
                right.debug_print(indent + 4);
            }
        }
    }
}

/// Store proof data as:
/// - `path`: directions from root to the node (Left/Right)
/// - `siblings`: sibling digests in parallel
#[derive(Debug, Clone)]
pub struct SparseMerkleTreeProof {
    pub path: Vec<Direction>,
    pub siblings: Vec<Digest>,
}

/// SMT has a root Node
/// Each Node in the SMT can be Empty, Leaf, or Branch
#[derive(Debug, Clone)]
pub struct SparseMerkleTree {
    root: Node,
}

impl SparseMerkleTree {
    /// Print out the entire SMT structure.
    pub fn debug_print(&self) {
        println!("=== SparseMerkleTree ===");
        self.root.debug_print(0);
        println!("========================");
    }

    /// Convert a key to a 256-bit digest used in path traversal.
    fn key_to_digest(key: &str) -> Digest {
        hash_one_thing("key", key)
    }

    /// Returns the i-th bit direction of a digest
    /// i = 0 => most significant bit; or i = 255 => least significant bit
    fn bit_at(d: &Digest, i: usize) -> Direction {
        // We interpret the digest as a 32-byte array = 256 bits total.
        // If bit is set => Right, else Left
        // We'll say i=0 => leftmost bit of d[0].
        let byte_index = i / 8;
        let bit_index_in_byte = 7 - (i % 8); // for "most significant bit first"
        let b = d.as_ref()[byte_index];
        if (b >> bit_index_in_byte) & 1 == 1 {
            Direction::Right
        } else {
            Direction::Left
        }
    }

    /// Find the first differing bit (>= start_bit) between two 256-bit digests.
    /// Returns `None` if they do not differ from `start_bit` onward (i.e. all remaining bits match).
    fn find_first_differing_bit(
        d1: &Digest,
        d2: &Digest,
        start_bit: usize,
    ) -> Option<usize> {
        for i in start_bit..256 {
            if Self::bit_at(d1, i) != Self::bit_at(d2, i) {
                return Some(i);
            }
        }
        None
    }

    /// Insert helper top-down approach (recursive):
    /// - If the node is empty, create a leaf
    /// - If the node is a leaf, update the value if the key matches
    /// - If the node is a branch, descend into the correct side
    fn insert_node(
        node: Node,
        key_digest: Digest,
        value: String,
        depth: usize,
    ) -> Node {
        match node {
            Node::Empty => {
                // No node here => create a leaf
                Node::Leaf { key_digest, value }
            }
            Node::Leaf {
                key_digest: existing_kd,
                value: existing_val,
            } => {
                // If it's the same key, update the value
                if existing_kd == key_digest {
                    Node::Leaf { key_digest, value }
                } else {
                    // They differ => find the exact bit where they diverge
                    let mismatch_bit = Self::find_first_differing_bit(
                        &existing_kd,
                        &key_digest,
                        depth,
                    )
                    .expect("We know they differ, so mismatch_bit must exist!");

                    // Build a minimal subtree that branches at 'mismatch_bit'
                    Self::create_branch(
                        existing_kd,
                        existing_val,
                        key_digest,
                        value,
                        depth,
                        mismatch_bit,
                    )
                }
            }
            Node::Branch { left, right } => {
                // Descend into the correct side
                let dir = Self::bit_at(&key_digest, depth);
                match dir {
                    Direction::Left => {
                        let new_left = Box::new(Self::insert_node(
                            *left,
                            key_digest,
                            value,
                            depth + 1,
                        ));
                        Node::Branch {
                            left: new_left,
                            right,
                        }
                    }
                    Direction::Right => {
                        let new_right = Box::new(Self::insert_node(
                            *right,
                            key_digest,
                            value,
                            depth + 1,
                        ));
                        Node::Branch {
                            left,
                            right: new_right,
                        }
                    }
                }
            }
        }
    }

    /// Create a branch path (recursive) that distinguishes two different leaves,
    /// given that they first differ at bit index `mismatch_bit`.
    fn create_branch(
        kd1: Digest,
        val1: String,
        kd2: Digest,
        val2: String,
        depth: usize,
        mismatch_bit: usize,
    ) -> Node {
        // If mismatch_bit == depth, they diverge right at this level => single Branch node.
        if mismatch_bit == depth {
            let dir1 = Self::bit_at(&kd1, depth);
            let dir2 = Self::bit_at(&kd2, depth);
            let leaf1 = Node::Leaf {
                key_digest: kd1,
                value: val1,
            };
            let leaf2 = Node::Leaf {
                key_digest: kd2,
                value: val2,
            };
            match (dir1, dir2) {
                (Direction::Left, Direction::Right) => Node::Branch {
                    left: Box::new(leaf1),
                    right: Box::new(leaf2),
                },
                (Direction::Right, Direction::Left) => Node::Branch {
                    left: Box::new(leaf2),
                    right: Box::new(leaf1),
                },
                _ => unreachable!("We already know they differ at this bit."),
            }
        } else {
            // We haven't reached mismatch_bit yet => create a branch node at `depth`,
            // but only fill in one side. Recurse deeper until we reach mismatch_bit.
            let dir1 = Self::bit_at(&kd1, depth);
            let subtree = Self::create_branch(
                kd1,
                val1,
                kd2,
                val2,
                depth + 1,
                mismatch_bit,
            );
            match dir1 {
                Direction::Left => Node::Branch {
                    left: Box::new(subtree),
                    right: Box::new(Node::Empty),
                },
                Direction::Right => Node::Branch {
                    left: Box::new(Node::Empty),
                    right: Box::new(subtree),
                },
            }
        }
    }

    /// Remove helper top-down approach (recursive).  
    /// Then call `try_compress_branch` at the end.
    fn remove_node(node: Node, key_digest: Digest, depth: usize) -> Node {
        match node {
            Node::Empty => Node::Empty,
            Node::Leaf {
                key_digest: kd,
                value,
            } => {
                if kd == key_digest {
                    // found the leaf => remove it
                    Node::Empty
                } else {
                    // different leaf => keep
                    Node::Leaf {
                        key_digest: kd,
                        value,
                    }
                }
            }
            Node::Branch { left, right } => {
                let dir = Self::bit_at(&key_digest, depth);
                let (new_left, new_right) = match dir {
                    Direction::Left => {
                        let new_left =
                            Self::remove_node(*left, key_digest, depth + 1);
                        (new_left, *right)
                    }
                    Direction::Right => {
                        let new_right =
                            Self::remove_node(*right, key_digest, depth + 1);
                        (*left, new_right)
                    }
                };
                Self::try_compress_branch(Node::Branch {
                    left: Box::new(new_left),
                    right: Box::new(new_right),
                })
            }
        }
    }

    /// Try to compress a branch if both children are empty.
    /// This helps to reduce unnecessary zero-digests in the tree.
    fn try_compress_branch(node: Node) -> Node {
        match node {
            Node::Branch { left, right } => match (&*left, &*right) {
                // both empty => entire branch is empty
                (Node::Empty, Node::Empty) => Node::Empty,

                _ => Node::Branch { left, right },
            },
            _ => node, // If it's already a Leaf or Empty, just return it
        }
    }

    /// Helper function (recursive) that returns
    /// - the value associated with a key (if any)
    /// - the lookup proof (path and siblings)
    fn get_proof_node(
        node: &Node,
        key_digest: &Digest,
        depth: usize,
        path: &mut Vec<Direction>,
        siblings: &mut Vec<Digest>,
    ) -> Option<String> {
        match node {
            Node::Empty => {
                // Non-existence, but there's no deeper structure here
                None
            }
            Node::Leaf {
                key_digest: kd,
                value,
            } => {
                if kd == key_digest {
                    // Existence proof for this leaf => just return Some(value)
                    Some(value.clone())
                } else {
                    // NOTE: Different leaf => non-existence from the perspective of `key_digest`
                    None
                }
            }
            Node::Branch { left, right } => {
                // Normal branching: pick the side determined by the bit at `depth`.
                let dir = SparseMerkleTree::bit_at(key_digest, depth);
                path.push(dir.clone());
                match dir {
                    Direction::Left => {
                        // If going left, sibling is `right.digest()`
                        siblings.push(right.digest());
                        SparseMerkleTree::get_proof_node(
                            left,
                            key_digest,
                            depth + 1,
                            path,
                            siblings,
                        )
                    }
                    Direction::Right => {
                        // If going right, sibling is `left.digest()`
                        siblings.push(left.digest());
                        SparseMerkleTree::get_proof_node(
                            right,
                            key_digest,
                            depth + 1,
                            path,
                            siblings,
                        )
                    }
                }
            }
        }
    }

    /// Create a new empty tree
    pub fn new() -> Self {
        SparseMerkleTree { root: Node::Empty }
    }

    /// Returns the *root digest* of the tree (recursive).
    pub fn commit(&self) -> Digest {
        self.root.digest()
    }

    /// Verify a proof for (key, value) or (key, None if missing) against the root.
    /// 1. Compute key_digest = hash_one_thing("key", key).
    /// 2. Start from the leaf-hash (leaf if present, or zero_digest if absent).
    /// 3. For each step in `proof.path` (direction), combine with the proof.siblings.
    /// 4. Check if final result == `comm`.
    /// Returns Some(()) if valid, None if invalid.
    pub fn check_proof(
        key: String,
        res: Option<String>,
        pf: &SparseMerkleTreeProof,
        comm: &Digest,
    ) -> Option<()> {
        let key_digest = hash_one_thing("key", &key);

        // If the claimed value is Some, we build a leaf hash:
        let mut current = if let Some(val) = res {
            hash_two_things("leaf_key", "leaf_val", key_digest, val)
        } else {
            zero_digest() // non-existent => zero
        };

        // We must iterate siblings **in reverse**, because the proof collects them top-down,
        // but reconstruction is bottom-up.
        if pf.path.len() != pf.siblings.len() {
            println!(
                "Malformed proof: path length {} != siblings length {}",
                pf.path.len(),
                pf.siblings.len()
            );
            return None;
        }

        // Reverse loop from the last sibling/path down to the first.
        for i in (0..pf.path.len()).rev() {
            let dir = &pf.path[i];
            let sibling = pf.siblings[i];
            match dir {
                Direction::Right => {
                    // If we were the "right child", the sibling is the "left child"
                    current = hash_two_things(
                        "branch_left",
                        "branch_right",
                        sibling,
                        current,
                    );
                }
                Direction::Left => {
                    // If we were the "left child", the sibling is the "right child"
                    current = hash_two_things(
                        "branch_left",
                        "branch_right",
                        current,
                        sibling,
                    );
                }
            }
        }

        if current == *comm {
            Some(())
        } else {
            println!("Proof verification failed");
            None
        }
    }

    /// Return the value (if any) for `key` and the proof that authenticates it.
    pub fn get(&self, key: String) -> (Option<String>, SparseMerkleTreeProof) {
        let key_digest = SparseMerkleTree::key_to_digest(&key);
        let mut path = Vec::new();
        let mut siblings = Vec::new();
        let value = SparseMerkleTree::get_proof_node(
            &self.root,
            &key_digest,
            0,
            &mut path,
            &mut siblings,
        );

        let proof = SparseMerkleTreeProof { path, siblings };
        (value, proof)
    }

    /// Insert or update the given (key, value), returning the updated tree.
    pub fn insert(mut self, key: String, value: String) -> Self {
        let key_digest = SparseMerkleTree::key_to_digest(&key);
        self.root =
            SparseMerkleTree::insert_node(self.root, key_digest, value, 0);
        self
    }

    /// Remove the key, if it exists, returning the updated tree.
    pub fn remove(mut self, key: String) -> Self {
        let key_digest = SparseMerkleTree::key_to_digest(&key);
        self.root = SparseMerkleTree::remove_node(self.root, key_digest, 0);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_get() {
        let smt = SparseMerkleTree::new()
            .insert("k1".to_string(), "v1".to_string())
            .insert("k2".to_string(), "v2".to_string());
        let root_before = smt.commit();

        // Verify get() and proof
        let (val_k1, proof_k1) = smt.get("k1".to_string());
        let (val_k2, proof_k2) = smt.get("k2".to_string());
        assert_eq!(val_k1, Some("v1".to_string()));
        assert!(SparseMerkleTree::check_proof(
            "k1".to_string(),
            Some("v1".to_string()),
            &proof_k1,
            &root_before
        )
        .is_some());

        assert_eq!(val_k2, Some("v2".to_string()));
        assert!(SparseMerkleTree::check_proof(
            "k2".to_string(),
            Some("v2".to_string()),
            &proof_k2,
            &root_before
        )
        .is_some());
    }

    #[test]
    fn test_remove() {
        let smt = SparseMerkleTree::new()
            .insert("k1".to_string(), "v1".to_string())
            .insert("k2".to_string(), "v2".to_string());
        let root_before = smt.commit();
        smt.debug_print();

        // Confirm k1 is present
        let (val_k1, proof_k1) = smt.get("k1".to_string());
        assert_eq!(val_k1, Some("v1".to_string()));
        assert!(SparseMerkleTree::check_proof(
            "k1".to_string(),
            Some("v1".to_string()),
            &proof_k1,
            &root_before
        )
        .is_some());

        // Remove k1
        let smt2 = smt.remove("k1".to_string());
        smt2.debug_print();
        let root_after = smt2.commit();
        assert_ne!(root_after, root_before);

        let (val_k1_rem, proof_k1_rem) = smt2.get("k1".to_string());
        assert_eq!(val_k1_rem, None);
        // Now proof should verify None for k1
        assert!(SparseMerkleTree::check_proof(
            "k1".to_string(),
            None,
            &proof_k1_rem,
            &root_after
        )
        .is_some());

        // k2 is still present
        let (val_k2, proof_k2) = smt2.get("k2".to_string());
        assert_eq!(val_k2, Some("v2".to_string()));
        assert!(SparseMerkleTree::check_proof(
            "k2".to_string(),
            Some("v2".to_string()),
            &proof_k2,
            &root_after
        )
        .is_some());

        // Remove k2
        let smt3 = smt2.remove("k2".to_string());
        smt3.debug_print();
        let root_after2 = smt3.commit();
        assert_ne!(root_after2, root_after);

        let (val_k2_rem, proof_k2_rem) = smt3.get("k2".to_string());
        assert_eq!(val_k2_rem, None);
        assert!(SparseMerkleTree::check_proof(
            "k2".to_string(),
            None,
            &proof_k2_rem,
            &root_after2
        )
        .is_some());
    }

    #[test]
    fn test_update_value() {
        let smt =
            SparseMerkleTree::new().insert("k1".to_string(), "v1".to_string());
        let root1 = smt.commit();

        // Update value of k1
        let smt2 = smt.insert("k1".to_string(), "v1_updated".to_string());
        let root2 = smt2.commit();

        assert_ne!(root1, root2); // different root

        let (val, proof) = smt2.get("k1".to_string());
        assert_eq!(val, Some("v1_updated".to_string()));
        assert!(SparseMerkleTree::check_proof(
            "k1".to_string(),
            Some("v1_updated".to_string()),
            &proof,
            &root2
        )
        .is_some());
    }

    #[test]
    fn test_remove_non_existent() {
        // Removing a key that doesn't exist should not affect the tree.
        let smt = SparseMerkleTree::new()
            .insert("k1".to_string(), "v1".to_string())
            .insert("k2".to_string(), "v2".to_string());
        let root_before = smt.commit();

        // Attempt to remove a non-existent key
        let smt2 = smt.remove("k3".to_string());
        let root_after = smt2.commit();
        assert_eq!(root_before, root_after);

        // Verify k1 and k2 are still there
        let (val_k1, _) = smt2.get("k1".to_string());
        let (val_k2, _) = smt2.get("k2".to_string());
        assert_eq!(val_k1, Some("v1".to_string()));
        assert_eq!(val_k2, Some("v2".to_string()));
    }

    #[test]
    fn test_insert_duplicate_keys() {
        // Inserting the same key multiple times should update the value each time
        let smt = SparseMerkleTree::new()
            .insert("k1".to_string(), "v1".to_string())
            .insert("k1".to_string(), "v2".to_string())
            .insert("k1".to_string(), "v3".to_string());
        let (val, proof) = smt.get("k1".to_string());
        assert_eq!(val, Some("v3".to_string()));

        // Check proof
        let root = smt.commit();
        assert!(SparseMerkleTree::check_proof(
            "k1".to_string(),
            Some("v3".to_string()),
            &proof,
            &root
        )
        .is_some());
    }

    #[test]
    fn test_empty_tree_proof() {
        let smt = SparseMerkleTree::new();
        let (val, proof) = smt.get("no_key".to_string());

        // Should be None
        assert_eq!(val, None);

        // Proof should verify that "no_key" is not in the tree
        let root = smt.commit();
        assert!(SparseMerkleTree::check_proof(
            "no_key".to_string(),
            None,
            &proof,
            &root
        )
        .is_some());
    }

    /// Bulk insertion + verification:
    /// - Insert many (k, v) pairs
    /// - Then retrieve each one and verify the proof
    /// This tests that all inserted keys are present, and each proof is consistent.
    #[test]
    fn test_bulk_insertion() {
        let mut smt = SparseMerkleTree::new();

        // Insert a bunch of pairs
        let num_pairs = 100;
        for i in 0..num_pairs {
            let key = format!("key_{}", i);
            let val = format!("val_{}", i);
            smt = smt.insert(key.clone(), val.clone());
        }

        smt.debug_print();
        let root = smt.commit();

        // Now check each one
        for i in 0..num_pairs {
            let key = format!("key_{}", i);
            let val = format!("val_{}", i);

            let (got_val, proof) = smt.get(key.clone());
            assert_eq!(got_val, Some(val.clone()));

            // Proof must verify
            let check =
                SparseMerkleTree::check_proof(key, got_val, &proof, &root);
            assert!(check.is_some(), "Bulk insertion: proof must be valid");
        }
    }

    #[test]
    fn test_proof_for_completely_missing_key() {
        let smt = SparseMerkleTree::new()
            .insert("k1".to_string(), "v1".to_string())
            .insert("k2".to_string(), "v2".to_string())
            .insert("k3".to_string(), "v3".to_string());

        let root = smt.commit();

        // A key that was never inserted
        let missing_key = "random";

        // Get the proof for the missing key
        let (val, proof) = smt.get(missing_key.to_string());
        smt.debug_print();

        println!("proof: {:?}", proof);
        assert_eq!(val, None);

        // The proof should verify as "None"
        assert!(
            SparseMerkleTree::check_proof(
                missing_key.to_string(),
                val,
                &proof,
                &root
            )
            .is_some(),
            "Non-existence proof for an random key should be valid"
        );
    }
}
