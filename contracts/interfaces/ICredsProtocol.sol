//SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @title CredsProtocol interface.
/// @dev Interface of a CredsProtocol contract.
interface ICredsProtocol {
    
    struct Verifier {
        address contractAddress;
        uint8 merkleTreeDepth;
    }
    
    /// @dev Saves the nullifier hash to avoid double signaling and emits an event
    /// if the zero-knowledge proof is valid.
    /// @param credId: Id of the cred.
    /// @param signal: CredsProtocol signal.
    /// @param nullifierHash: Nullifier hash.
    /// @param externalNullifier: External nullifier.
    /// @param proof: Zero-knowledge proof.
    function verifyProof(
        uint256 credId,
        bytes32 signal,
        uint256 nullifierHash,
        uint256 externalNullifier,
        uint256[8] calldata proof
    ) external;
    
}
