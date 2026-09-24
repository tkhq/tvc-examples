// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { SignedEthUsdOracle } from "../src/SignedEthUsdOracle.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function expectRevert(bytes calldata revertData) external;
    function prank(address sender) external;
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 newTimestamp) external;
}
contract SignedEthUsdOracleTest {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address private constant UPDATER = address(0xBEEF);
    address private constant OTHER = address(0xCAFE);
    address private constant COINGECKO_AIRNODE = 0x9dB03a07bE313B3C08261B1d1606D511f3560D9e;
    bytes32 private constant ETH_USD_TEMPLATE_ID =
        0xdeda2f7938bf877d2f011aa550852d3459794e16944ea0b7513465479752ba93;

    // Captured directly from CoinGecko's public Signed API on 2026-09-02.
    uint256 private constant FIXTURE_TIMESTAMP = 1_788_381_825;
    uint256 private constant FIXTURE_PRICE_USD_E18 = 2_391_230_000_000_000_000_000;
    bytes private constant FIXTURE_ENCODED_VALUE =
        hex"000000000000000000000000000000000000000000000081a0fb87b871530000";
    bytes private constant FIXTURE_SIGNATURE =
        hex"6a157125cc065e38c66d6b978f8897d7693282462f041fb68bbdd49cbc5b8322143c59e8ac68aacdb2533a5247e0fb50601a0bbd7f8c1e4a7e5627d685dbb3361c";

    SignedEthUsdOracle private oracle;

    function setUp() public {
        oracle = new SignedEthUsdOracle(
            address(this), UPDATER, COINGECKO_AIRNODE, ETH_USD_TEMPLATE_ID
        );
        VM.warp(FIXTURE_TIMESTAMP + 60);
    }

    function testAcceptsRealCoinGeckoSignature() public {
        _publishFixture();

        _assertEq(oracle.latestPriceUsdE18(), FIXTURE_PRICE_USD_E18);
        _assertEq(oracle.sourceTimestamp(), FIXTURE_TIMESTAMP);
        _assertEq(oracle.recordedAt(), FIXTURE_TIMESTAMP + 60);
        _assertEq(
            oracle.latestBeaconId(),
            keccak256(abi.encodePacked(COINGECKO_AIRNODE, ETH_USD_TEMPLATE_ID))
        );
        _assertEq(
            oracle.latestPayloadHash(),
            keccak256(
                abi.encodePacked(ETH_USD_TEMPLATE_ID, FIXTURE_TIMESTAMP, FIXTURE_ENCODED_VALUE)
            )
        );
        _assertEq(oracle.latestSignatureHash(), keccak256(FIXTURE_SIGNATURE));
    }

    function testRejectsUnauthorizedUpdater() public {
        VM.expectRevert(
            abi.encodeWithSelector(SignedEthUsdOracle.UnauthorizedUpdater.selector, address(this))
        );
        oracle.updatePrice(
            ETH_USD_TEMPLATE_ID, FIXTURE_TIMESTAMP, FIXTURE_ENCODED_VALUE, FIXTURE_SIGNATURE
        );
    }

    function testRejectsReplay() public {
        _publishFixture();

        VM.expectRevert(
            abi.encodeWithSelector(
                SignedEthUsdOracle.SourceTimestampNotNewer.selector,
                FIXTURE_TIMESTAMP,
                FIXTURE_TIMESTAMP
            )
        );
        VM.prank(UPDATER);
        oracle.updatePrice(
            ETH_USD_TEMPLATE_ID, FIXTURE_TIMESTAMP, FIXTURE_ENCODED_VALUE, FIXTURE_SIGNATURE
        );
    }

    function testRejectsUnexpectedTemplate() public {
        bytes32 wrongTemplate = keccak256("BTC/USD");
        VM.expectRevert(
            abi.encodeWithSelector(
                SignedEthUsdOracle.UnexpectedTemplateId.selector, wrongTemplate, ETH_USD_TEMPLATE_ID
            )
        );
        VM.prank(UPDATER);
        oracle.updatePrice(
            wrongTemplate, FIXTURE_TIMESTAMP, FIXTURE_ENCODED_VALUE, FIXTURE_SIGNATURE
        );
    }

    function testRejectsStaleObservation() public {
        VM.warp(FIXTURE_TIMESTAMP + oracle.MAX_SOURCE_AGE() + 1);
        VM.expectRevert(
            abi.encodeWithSelector(
                SignedEthUsdOracle.SourceTimestampTooOld.selector,
                FIXTURE_TIMESTAMP,
                FIXTURE_TIMESTAMP + 1
            )
        );
        VM.prank(UPDATER);
        oracle.updatePrice(
            ETH_USD_TEMPLATE_ID, FIXTURE_TIMESTAMP, FIXTURE_ENCODED_VALUE, FIXTURE_SIGNATURE
        );
    }

    function testRejectsObservationTooFarInFuture() public {
        VM.warp(FIXTURE_TIMESTAMP - oracle.MAX_FUTURE_DRIFT() - 1);
        VM.expectRevert(
            abi.encodeWithSelector(
                SignedEthUsdOracle.SourceTimestampTooFarInFuture.selector,
                FIXTURE_TIMESTAMP,
                FIXTURE_TIMESTAMP - 1
            )
        );
        VM.prank(UPDATER);
        oracle.updatePrice(
            ETH_USD_TEMPLATE_ID, FIXTURE_TIMESTAMP, FIXTURE_ENCODED_VALUE, FIXTURE_SIGNATURE
        );
    }

    function testRejectsWrongCertifiedSigner() public {
        oracle.setSourceAirnode(OTHER);
        VM.expectRevert(
            abi.encodeWithSelector(
                SignedEthUsdOracle.InvalidSourceSigner.selector, COINGECKO_AIRNODE, OTHER
            )
        );
        VM.prank(UPDATER);
        oracle.updatePrice(
            ETH_USD_TEMPLATE_ID, FIXTURE_TIMESTAMP, FIXTURE_ENCODED_VALUE, FIXTURE_SIGNATURE
        );
    }

    function testRejectsNonPositivePrice() public {
        uint256 sourcePrivateKey = 0xA11CE;
        address sourceSigner = VM.addr(sourcePrivateKey);
        SignedEthUsdOracle localOracle =
            new SignedEthUsdOracle(address(this), UPDATER, sourceSigner, ETH_USD_TEMPLATE_ID);
        bytes memory encodedZero = abi.encode(int256(0));
        bytes memory zeroSignature =
            _signObservation(sourcePrivateKey, FIXTURE_TIMESTAMP, encodedZero);

        VM.expectRevert(abi.encodeWithSelector(SignedEthUsdOracle.InvalidPrice.selector, int256(0)));
        VM.prank(UPDATER);
        localOracle.updatePrice(ETH_USD_TEMPLATE_ID, FIXTURE_TIMESTAMP, encodedZero, zeroSignature);
    }

    function testSeparatesAdministrationFromRoutineUpdates() public {
        oracle.setUpdater(OTHER);
        oracle.setSourceAirnode(OTHER);

        _assertEq(oracle.updater(), OTHER);
        _assertEq(oracle.sourceAirnode(), OTHER);

        VM.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("OwnableUnauthorizedAccount(address)")), UPDATER
            )
        );
        VM.prank(UPDATER);
        oracle.setSourceAirnode(COINGECKO_AIRNODE);
    }

    function _publishFixture() private {
        VM.prank(UPDATER);
        oracle.updatePrice(
            ETH_USD_TEMPLATE_ID, FIXTURE_TIMESTAMP, FIXTURE_ENCODED_VALUE, FIXTURE_SIGNATURE
        );
    }

    function _signObservation(uint256 privateKey, uint256 timestamp, bytes memory encodedValue)
        private
        returns (bytes memory)
    {
        bytes32 payloadHash =
            keccak256(abi.encodePacked(ETH_USD_TEMPLATE_ID, timestamp, encodedValue));
        bytes32 digest =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash));
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _assertEq(uint256 actual, uint256 expected) private pure {
        require(actual == expected, "uint256 values differ");
    }

    function _assertEq(address actual, address expected) private pure {
        require(actual == expected, "address values differ");
    }

    function _assertEq(bytes32 actual, bytes32 expected) private pure {
        require(actual == expected, "bytes32 values differ");
    }
}
