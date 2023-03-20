//SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {SNARK_SCALAR_FIELD} from "./CredsProtocolConstants.sol";
import "../interfaces/ICredsProtocolCreds.sol";
import "../zk-kit/incremental-merkle-tree.sol/contracts/IncrementalBinaryTree.sol";
import "../openzeppelin/contracts/utils/Context.sol";

/// @title CredsProtocol creds contract.
/// @dev The following code allows you to create creds, add and remove identities.
/// You can use getters to obtain informations about creds (root, depth, number of leaves).
abstract contract CredsProtocolCreds is Context, ICredsProtocolCreds {
    using IncrementalBinaryTree for IncrementalTreeData;

    /// @dev Gets a cred id and returns the cred/tree data.
    mapping(uint256 => IncrementalTreeData) internal creds;

    /// @dev Creates a new cred by initializing the associated tree.
    /// @param credId: Id of the cred.
    /// @param depth: Depth of the tree.
    /// @param zeroValue: Zero value of the tree.
    function _createCred(
        uint256 credId,
        uint8 depth,
        uint256 zeroValue,
        address issuer
    ) internal virtual {
        require(credId < SNARK_SCALAR_FIELD, "CredsProtocolCreds: cred id must be < SNARK_SCALAR_FIELD");
        require(getDepth(credId) == 0, "CredsProtocolCreds: cred already exists");

        creds[credId].init(depth, zeroValue);

        emit CredCreated(credId, issuer, depth, zeroValue);
    }

    /// @dev Adds an identity commitment to an existing cred.
    /// @param credId: Id of the cred.
    /// @param identityCommitment: New identity commitment.
    function _addIdentity(uint256 credId, uint256 identityCommitment) internal virtual {
        require(getDepth(credId) != 0, "CredsProtocolCreds: cred does not exist");

        creds[credId].insert(identityCommitment);

        uint256 root = getRoot(credId);

        emit IdentityAdded(credId, identityCommitment, root);
    }

    /// @dev Removes an identity commitment from an existing cred. A proof of membership is
    /// needed to check if the node to be deleted is part of the tree.
    /// @param credId: Id of the cred.
    /// @param identityCommitment: Existing identity commitment to be deleted.
    /// @param proofSiblings: Array of the sibling nodes of the proof of membership.
    /// @param proofPathIndices: Path of the proof of membership.
    function _removeIdentity(
        uint256 credId,
        uint256 identityCommitment,
        uint256[] calldata proofSiblings,
        uint8[] calldata proofPathIndices
    ) internal virtual {
        require(getDepth(credId) != 0, "CredsProtocolCreds: cred does not exist");

        creds[credId].remove(identityCommitment, proofSiblings, proofPathIndices);

        uint256 root = getRoot(credId);

        emit IdentityRemoved(credId, identityCommitment, root);
    }

    /// @dev See {CredsProtocolCreds-getRoot}.
    function getRoot(uint256 credId) public view virtual override returns (uint256) {
        return creds[credId].root;
    }

    /// @dev See {CredsProtocolCreds-getDepth}.
    function getDepth(uint256 credId) public view virtual override returns (uint8) {
        return creds[credId].depth;
    }

    /// @dev See {CredsProtocolCreds-getNumberOfLeaves}.
    function getNumberOfLeaves(uint256 credId) public view virtual override returns (uint256) {
        return creds[credId].numberOfLeaves;
    }
}
