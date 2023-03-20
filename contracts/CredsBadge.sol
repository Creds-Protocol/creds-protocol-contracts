//SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./interfaces/IVerifier.sol";
import "./CredsProtocol.sol";
import "./openzeppelin/contracts/token/ERC1155/ERC1155.sol";

/// @title CredsBadge
contract CredsBadge is CredsProtocol, ERC1155 {
    address public issuer;
    uint256 private immutable badgeId;

    /// @dev Initializes the CredsProtocol with issuer and verifier used to verify the user's ZK proofs.
    /// @param _verifier: CredsProtocol verifier address.
    /// @param _treeDepth: CredsProtocol verifier Merkle tree depth).
    /// @param _badgeURI: URI of CredsBadge
    /// @param _badgeName: Name of CredsBadge
    /// @param _issuer: Issuer Address of CredsBadge
    constructor(
        uint8 _treeDepth,
        IVerifier _verifier,
        string memory _badgeURI,
        string memory _badgeName,
        address _issuer
    ) CredsProtocol(_treeDepth, _verifier) ERC1155(_badgeURI) {
        issuer = _issuer;
        uint256 credsBadgeID = getBadgeId(_badgeName);
        badgeId = credsBadgeID;
        createCred(credsBadgeID, treeDepth, 0, _issuer);
    }

    /// @dev Adds identity commitments to an existing cred.
    /// @param identityCommitments: List of identity commitments
    function awardCredsBadge(uint256[] memory identityCommitments) internal {
        addIdentities(badgeId, identityCommitments);
    }

    /// @dev Verifies the claimAddress is eligible for the credsBadge or not and mints a ERC1155 Badge NFT
    /// @param claimAddress: address of user who gonna claim the creds badge
    /// @param signal: signal.
    /// @param nullifierHash: Nullifier hash.
    /// @param proof: Zero-knowledge proof.
    function claimCredsBadge(
        address claimAddress,
        bytes32 signal,
        uint256 nullifierHash,
        uint256[8] calldata proof
    ) internal {
        verifyProof(badgeId, signal, nullifierHash, badgeId, proof);
        _mint(claimAddress, badgeId, 1, "");
    }

    /// @dev Verifies the ownership of CredsBadge
    /// @param signal: signal.
    /// @param nullifierHash: Nullifier hash.
    /// @param proof: Zero-knowledge proof.
    function verifyCredsBadgeOwnership(
        bytes32 signal,
        uint256 nullifierHash,
        uint256[8] calldata proof
    ) public view {
        verifyProof(badgeId, signal, nullifierHash, badgeId, proof);
    }

    /// @dev Computes Badge ID based on given badgeName
    /// @param badgeName : Name of the CredsBadge
    function getBadgeId(
        string memory badgeName
    ) private pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(badgeName))) >> 8;
    }

    /// @dev Getter of the value of a URI of the CredsBadge
    function getBadgeURI() public view returns (string memory) {
        return uri(badgeId);
    }

    /// @dev Reverts, this is a non transferable ERC115 contract
    function _beforeTokenTransfer(
        address,
        address from,
        address to,
        uint256[] memory,
        uint256[] memory,
        bytes memory
    ) internal virtual override {
        require(
            from == address(0) || to == address(0),
            "This a Soulbound token. It cannot be transferred. It can only be burned by the token owner."
        );
    }
}
