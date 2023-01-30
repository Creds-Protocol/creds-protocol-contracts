//SPDX-License-Identifier: MIT
pragma solidity 0.8.4;

/// @title Credential interface.
/// @dev Interface of a Credential contract.
interface ICredential {
    error Credential__CallerIsNotTheCredAdmin();
    error Credential__MerkleTreeDepthIsNotSupported();
    error Credential__MerkleTreeRootIsExpired();
    error Credential__MerkleTreeRootIsNotPartOfTheCred();
    error Credential__YouAreUsingTheSameNillifierTwice();

    struct Verifier {
        address contractAddress;
        uint256 merkleTreeDepth;
    }

    /// It defines all the cred parameters, in addition to those in the Merkle tree.
    struct Cred {
        address admin;
        string credURI;
        uint256 merkleRootDuration;
        mapping(uint256 => uint256) merkleRootCreationDates;
        mapping(uint256 => bool) nullifierHashes;
    }

    /// @dev Emitted when an admin is assigned to a cred.
    /// @param credId: Id of the cred.
    /// @param oldAdmin: Old admin of the cred.
    /// @param newAdmin: New admin of the cred.
    event credAdminUpdated(uint256 indexed credId, address indexed oldAdmin, address indexed newAdmin);

    /// @dev Emitted when a Credential proof is verified.
    /// @param credId: Id of the cred.
    /// @param merkleTreeRoot: Root of the Merkle tree.
    /// @param externalNullifier: External nullifier.
    /// @param nullifierHash: Nullifier hash.
    /// @param signal: Credential signal.
    event ProofVerified(
        uint256 indexed credId,
        uint256 merkleTreeRoot,
        uint256 externalNullifier,
        uint256 nullifierHash,
        bytes32 signal
    );
    
}