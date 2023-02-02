// SPDX-License-Identifier: MIT

pragma solidity 0.8.4;

contract CredsProtocol {

    mapping(address => address) public issuer;
    mapping(address => bool) public isRegisteredIssuer;
    
    function registerIssuer(address _issuerAddress, address _issuerContractAddress) public {
        require(!isRegisteredIssuer[_issuerAddress], "Already Registered as Issuer");
        issuer[_issuerAddress] = _issuerContractAddress;
        isRegisteredIssuer[_issuerAddress] = true;
    }

}


