// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC721Metadata} from "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";

import {IGasKillerSDK} from "../../src/interface/IGasKillerSDK.sol";
import {ISchnorrGasKillerSDK} from "../../src/schnorr/interface/ISchnorrGasKillerSDK.sol";
import {ISchnorrGasKillerSDKBatch} from "../../src/schnorr/interface/ISchnorrGasKillerSDKBatch.sol";
import {DualSchemeGasKillerSDK} from "../../src/migration/DualSchemeGasKillerSDK.sol";

/// The migration counterpart of `test/ERC165Composition.t.sol`, kept here so the whole
/// migration can be removed as one directory.
contract DualSchemeSdkFirstNft is DualSchemeGasKillerSDK, ERC721 {
    constructor() ERC721("DualSchemeSdkFirst", "DSF") {}

    function supportsInterface(bytes4 interfaceId) public view override(DualSchemeGasKillerSDK, ERC721) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}

contract DualSchemeERC165CompositionTest is Test {
    /// The dual-scheme base reports both scheme IDs, so a target composing it with another
    /// ERC-165 module must report the union of all three sets. Otherwise composing it costs
    /// the target its routability under one of the two fleets.
    function test_dualSchemeSdkFirst_reportsUnionOfInterfaceIds() public {
        DualSchemeSdkFirstNft target = new DualSchemeSdkFirstNft();

        assertTrue(target.supportsInterface(type(IGasKillerSDK).interfaceId), "gas killer id");
        assertTrue(target.supportsInterface(type(ISchnorrGasKillerSDK).interfaceId), "schnorr gas killer id");
        assertTrue(target.supportsInterface(type(ISchnorrGasKillerSDKBatch).interfaceId), "schnorr batch id");
        assertTrue(target.supportsInterface(type(IERC721).interfaceId), "erc721 id");
        assertTrue(target.supportsInterface(type(IERC721Metadata).interfaceId), "erc721 metadata id");
        assertTrue(target.supportsInterface(type(IERC165).interfaceId), "erc165 id");
        assertFalse(target.supportsInterface(0xffffffff), "invalid id");
    }
}
