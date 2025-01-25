# Sparse Merkle Tree Implementation in Rust

This is a Rust implementation of a Sparse Merkle Tree (SMT), a cryptographic data structure that efficiently stores key-value pairs while maintaining cryptographic proofs of inclusion and exclusion.

## Features

-   **Key-Value Storage**: Store and retrieve string key-value pairs
-   **Cryptographic Proofs**: Generate and verify inclusion/exclusion proofs
-   **Memory Efficient**: Sparse implementation that only stores non-empty nodes
-   **Immutable Updates**: All operations return new tree instances, preserving immutability
-   **Branch Compression**: Automatically compresses empty branches to reduce memory usage

## Usage

```rust
use sparse_merkle_tree::SparseMerkleTree;

// Create a new empty tree
let smt = SparseMerkleTree::new();

// Insert key-value pairs
let smt = smt
    .insert("key1".to_string(), "value1".to_string())
    .insert("key2".to_string(), "value2".to_string());

// Get a value and its proof
let (value, proof) = smt.get("key1".to_string());

// Get the root commitment
let root = smt.commit();

// Verify a proof
let is_valid = SparseMerkleTree::check_proof(
    "key1".to_string(),
    Some("value1".to_string()),
    &proof,
    &root
).is_some();

// Remove a key
let smt = smt.remove("key1".to_string());
```

## Implementation Details

The tree is implemented with three types of nodes:

-   **Empty**: Represents an empty subtree with zero digest
-   **Leaf**: Stores a key digest and value
-   **Branch**: Contains left and right child nodes

Key features of the implementation:

1. **Path Selection**: Uses bit-by-bit key digest traversal for deterministic paths
2. **Proof Structure**: Proofs contain:
    - Path directions (left/right) from root to target
    - Sibling digests for verification
3. **Branch Compression**: Empty branches are automatically compressed to save space
4. **Immutable Operations**: All modifications return new tree instances

## Testing

The implementation includes comprehensive tests covering:

-   Basic insertion and retrieval
-   Proof generation and verification
-   Key removal and updates
-   Edge cases (empty trees, missing keys)
-   Bulk operations
-   Branch compression

Run tests with:

```bash
cargo test
```

## Performance Considerations

-   Tree depth is fixed at 256 bits (based on hash digest size)
-   Operations are O(log n) where n is the number of stored items
-   Memory usage is proportional to the number of non-empty nodes
-   Branch compression helps reduce memory footprint for sparse trees
