// SPDX-License-Identifier: MIT
pragma solidity 0.8.4;

import "./interfaces/ICredential.sol";
import "./interfaces/IVerifier.sol";
import "./base/CredentialCore.sol";
import "./base/CredentialCreds.sol";

/// @title Credential
contract Credential is ICredential, CredentialCore, CredentialCreds {
    
    /// @dev Gets a tree depth and returns its verifier address.
    mapping(uint256 => IVerifier) public verifiers;

    /// @dev Gets a cred id and returns the cred parameters.
    mapping(uint256 => Cred) public creds;

    /// @dev Checks if the cred admin is the transaction sender.
    /// @param credId: Id of the cred.
    modifier onlyCredAdmin(uint256 credId) {
        if (creds[credId].admin != _msgSender()) {
            revert Credential__CallerIsNotTheCredAdmin();
        }
        _;
    }

    /// @dev Checks if there is a verifier for the given tree depth.
    /// @param merkleTreeDepth: Depth of the tree.
    modifier onlySupportedMerkleTreeDepth(uint256 merkleTreeDepth) {
        if (address(verifiers[merkleTreeDepth]) == address(0)) {
            revert Credential__MerkleTreeDepthIsNotSupported();
        }
        _;
    }

    /// @dev Initializes the Credential verifiers used to verify the user's ZK proofs.
    /// @param _verifiers: List of Credential verifiers (address and related Merkle tree depth).
    constructor(Verifier[] memory _verifiers) {
        for (uint8 i = 0; i < _verifiers.length; ) {
            verifiers[_verifiers[i].merkleTreeDepth] = IVerifier(_verifiers[i].contractAddress);

            unchecked {
                ++i;
            }
        }
    }

    /// @dev See {ICredential-createCred}.
    function createCred(
        uint256 credId,
        uint256 merkleTreeDepth,
        uint256 zeroValue,
        address admin,
        string memory credURI
    ) internal onlySupportedMerkleTreeDepth(merkleTreeDepth) {
        _createCred(credId, merkleTreeDepth, zeroValue);

        creds[credId].admin = admin;
        creds[credId].credURI = credURI;
        creds[credId].merkleRootDuration = 1 hours;

        emit credAdminUpdated(credId, address(0), admin);
    }

    /// @dev See {ICredential-createCred}.
    function createCred(
        uint256 credId,
        uint256 merkleTreeDepth,
        uint256 zeroValue,
        address admin,
        uint256 merkleTreeRootDuration,
        string memory credURI
    ) internal onlySupportedMerkleTreeDepth(merkleTreeDepth) {
        _createCred(credId, merkleTreeDepth, zeroValue);

        creds[credId].admin = admin;
        creds[credId].credURI = credURI;
        creds[credId].merkleRootDuration = merkleTreeRootDuration;

        emit credAdminUpdated(credId, address(0), admin);
    }

    /// @dev See {ICredential-updateCredAdmin}.
    function updateCredAdmin(uint256 credId, address newAdmin) internal onlyCredAdmin(credId) {
        creds[credId].admin = newAdmin;

        emit credAdminUpdated(credId, _msgSender(), newAdmin);
    }

    /// @dev See {ICredential-addIdentity}.
    function addIdentity(uint256 credId, uint256 identityCommitment) internal virtual onlyCredAdmin(credId) {
        _addIdentity(credId, identityCommitment);

        uint256 merkleTreeRoot = getMerkleTreeRoot(credId);

        creds[credId].merkleRootCreationDates[merkleTreeRoot] = block.timestamp;
    }

    /// @dev See {ICredential-addIdentities}.
    function addIdentities(uint256 credId, uint256[] calldata identityCommitments)
        internal
        onlyCredAdmin(credId)
    {
        for (uint8 i = 0; i < identityCommitments.length; ) {
            _addIdentity(credId, identityCommitments[i]);

            unchecked {
                ++i;
            }
        }

        uint256 merkleTreeRoot = getMerkleTreeRoot(credId);

        creds[credId].merkleRootCreationDates[merkleTreeRoot] = block.timestamp;
    }

    /// @dev See {ICredential-updateIdentity}.
    function updateIdentity(
        uint256 credId,
        uint256 identityCommitment,
        uint256 newIdentityCommitment,
        uint256[] calldata proofSiblings,
        uint8[] calldata proofPathIndices
    ) internal onlyCredAdmin(credId) {
        _updateIdentity(credId, identityCommitment, newIdentityCommitment, proofSiblings, proofPathIndices);
    }

    /// @dev See {ICredential-removeIdentity}.
    function removeIdentity(
        uint256 credId,
        uint256 identityCommitment,
        uint256[] calldata proofSiblings,
        uint8[] calldata proofPathIndices
    ) internal onlyCredAdmin(credId) {
        _removeIdentity(credId, identityCommitment, proofSiblings, proofPathIndices);
    }

    /// @dev See {ICredential-verifyProof}.
    function verifyProof(
        uint256 credId,
        uint256 merkleTreeRoot,
        bytes32 signal,
        uint256 nullifierHash,
        uint256 externalNullifier,
        uint256[8] calldata proof
    ) internal {
        uint256 currentMerkleTreeRoot = getMerkleTreeRoot(credId);

        if (currentMerkleTreeRoot == 0) {
            revert Credential__CredDoesNotExist();
        }

        if (merkleTreeRoot != currentMerkleTreeRoot) {
            uint256 merkleRootCreationDate = creds[credId].merkleRootCreationDates[merkleTreeRoot];
            uint256 merkleRootDuration = creds[credId].merkleRootDuration;

            if (merkleRootCreationDate == 0) {
                revert Credential__MerkleTreeRootIsNotPartOfTheCred();
            }

            if (block.timestamp > merkleRootCreationDate + merkleRootDuration) {
                revert Credential__MerkleTreeRootIsExpired();
            }
        }

        if (creds[credId].nullifierHashes[nullifierHash]) {
            revert Credential__YouAreUsingTheSameNillifierTwice();
        }

        uint256 merkleTreeDepth = getMerkleTreeDepth(credId);

        IVerifier verifier = verifiers[merkleTreeDepth];

        _verifyProof(signal, merkleTreeRoot, nullifierHash, externalNullifier, proof, verifier);

        creds[credId].nullifierHashes[nullifierHash] = true;

        emit ProofVerified(credId, merkleTreeRoot, nullifierHash, externalNullifier, signal);
    }
}
