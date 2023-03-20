// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./interfaces/ICredsProtocol.sol";
import "./interfaces/IVerifier.sol";
import "./base/CredsProtocolCore.sol";
import "./base/CredsProtocolCreds.sol";

/// @title CredsProtocol
contract CredsProtocol is
    ICredsProtocol,
    CredsProtocolCore,
    CredsProtocolCreds
{
    uint8 public treeDepth;
    IVerifier public verifier;

    /// @dev Initializes the CredsProtocol with issuer and verifier used to verify the user's ZK proofs.
    /// @param _verifier: CredsProtocol verifier address.
    /// @param _treeDepth: CredsProtocol verifier Merkle tree depth).
    constructor(uint8 _treeDepth, IVerifier _verifier) {
        treeDepth = _treeDepth;
        verifier = _verifier;
    }

    /// @dev Creates a new cred by initializing the associated tree.
    /// @param credId: Id of the cred.
    /// @param depth: Depth of the tree.
    /// @param zeroValue: Zero value of the tree.
    /// @param credsIssuer: address of credsIssuer
    function createCred(
        uint256 credId,
        uint8 depth,
        uint256 zeroValue,
        address credsIssuer
    ) internal {
        _createCred(credId, depth, zeroValue, credsIssuer);
    }

    /// @dev Adds an identity commitment to an existing cred.
    /// @param credId: Id of the cred.
    /// @param identityCommitment: New identity commitment.
    function addIdentity(uint256 credId, uint256 identityCommitment) internal {
        _addIdentity(credId, identityCommitment);
    }

    /// @dev Adds an identity commitment to an existing cred.
    /// @param credId: Id of the cred.
    /// @param identityCommitments: Array of identity commitments.
    function addIdentities(uint256 credId, uint256[] memory identityCommitments)
        internal
    {
        for (uint256 i = 0; i < identityCommitments.length; ) {
            _addIdentity(credId, identityCommitments[i]);

            unchecked {
                ++i;
            }
        }
    }

    /// @dev Removes an identity commitment from an existing cred. A proof of membership is
    /// needed to check if the node to be deleted is part of the tree.
    /// @param credId: Id of the cred.
    /// @param identityCommitment: Existing identity commitment to be deleted.
    /// @param proofSiblings: Array of the sibling nodes of the proof of membership.
    /// @param proofPathIndices: Path of the proof of membership.
    function removeIdentity(
        uint256 credId,
        uint256 identityCommitment,
        uint256[] calldata proofSiblings,
        uint8[] calldata proofPathIndices
    ) internal {
        _removeIdentity(
            credId,
            identityCommitment,
            proofSiblings,
            proofPathIndices
        );
    }

    /// @dev See {ICredsProtocol-verifyProof}.
    function verifyProof(
        uint256 credId,
        bytes32 signal,
        uint256 nullifierHash,
        uint256 externalNullifier,
        uint256[8] calldata proof
    ) public view override {
        uint256 root = getRoot(credId);
        uint8 depth = getDepth(credId);

        require(depth != 0, "CredsProtocol: cred does not exist");

        _verifyProof(
            signal,
            root,
            nullifierHash,
            externalNullifier,
            proof,
            verifier
        );
    }
}
