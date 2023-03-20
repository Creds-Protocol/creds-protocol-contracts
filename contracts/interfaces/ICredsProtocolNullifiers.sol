//SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @title CredsProtocolNullifiers interface.
/// @dev Interface of CredsProtocolNullifiers contract.
interface ICredsProtocolNullifiers {
    /// @dev Emitted when a external nullifier is added.
    /// @param externalNullifier: External CredsProtocol nullifier.
    event ExternalNullifierAdded(uint256 externalNullifier);

    /// @dev Emitted when a external nullifier is removed.
    /// @param externalNullifier: External CredsProtocol nullifier.
    event ExternalNullifierRemoved(uint256 externalNullifier);
}
