//SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @title CredsProtocolCreds interface.
/// @dev Interface of a CredsProtocolCreds contract.
interface ICredsProtocolCreds {
    /// @dev Emitted when a new cred is created.
    /// @param credId: Id of the cred.
    /// @param depth: Depth of the tree.
    /// @param zeroValue: Zero value of the tree.
    event CredCreated(uint256 indexed credId, address indexed issuer, uint8 depth, uint256 zeroValue);

    /// @dev Emitted when a new identity commitment is added.
    /// @param credId: cred id of the cred.
    /// @param identityCommitment: New identity commitment.
    /// @param root: New root hash of the tree.
    event IdentityAdded(uint256 indexed credId, uint256 identityCommitment, uint256 root);

    /// @dev Emitted when a new identity commitment is removed.
    /// @param credId: cred id of the cred.
    /// @param identityCommitment: New identity commitment.
    /// @param root: New root hash of the tree.
    event IdentityRemoved(uint256 indexed credId, uint256 identityCommitment, uint256 root);

    /// @dev Returns the last root hash of a cred.
    /// @param credId: Id of the cred.
    /// @return Root hash of the cred.
    function getRoot(uint256 credId) external view returns (uint256);

    /// @dev Returns the depth of the tree of a cred.
    /// @param credId: Id of the cred.
    /// @return Depth of the cred tree.
    function getDepth(uint256 credId) external view returns (uint8);

    /// @dev Returns the number of tree leaves of a cred.
    /// @param credId: Id of the cred.
    /// @return Number of tree leaves.
    function getNumberOfLeaves(uint256 credId) external view returns (uint256);
}
