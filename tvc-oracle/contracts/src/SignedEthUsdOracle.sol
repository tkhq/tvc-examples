// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title Single-source ETH/USD oracle backed by CoinGecko-signed observations
/// @notice This demonstration contract independently verifies the API3-compatible signature
///         carried by each CoinGecko observation. A signature proves publisher provenance and
///         payload integrity; it does not prove that the reported market price is economically true.
contract SignedEthUsdOracle is Ownable2Step {
    using MessageHashUtils for bytes32;

    uint256 public constant MAX_SOURCE_AGE = 1 hours;
    uint256 public constant MAX_FUTURE_DRIFT = 5 minutes;

    bytes32 public immutable templateId;

    address public updater;
    address public sourceAirnode;

    uint256 public latestPriceUsdE18;
    uint256 public sourceTimestamp;
    uint256 public recordedAt;
    bytes32 public latestBeaconId;
    bytes32 public latestPayloadHash;
    bytes32 public latestSignatureHash;

    error UnauthorizedUpdater(address caller);
    error ZeroAddress();
    error EmptyTemplateId();
    error UnexpectedTemplateId(bytes32 received, bytes32 expected);
    error InvalidEncodedValueLength(uint256 received);
    error InvalidPrice(int256 received);
    error InvalidSourceSigner(address recovered, address expected);
    error SourceTimestampNotNewer(uint256 received, uint256 current);
    error SourceTimestampTooOld(uint256 received, uint256 oldestAllowed);
    error SourceTimestampTooFarInFuture(uint256 received, uint256 newestAllowed);

    event PriceUpdated(
        uint256 priceUsdE18,
        uint256 sourceTimestamp,
        uint256 recordedAt,
        address indexed sourceAirnode,
        bytes32 indexed templateId,
        bytes32 indexed beaconId,
        bytes32 payloadHash,
        bytes32 signatureHash
    );
    event UpdaterChanged(address indexed previousUpdater, address indexed newUpdater);
    event SourceAirnodeChanged(address indexed previousAirnode, address indexed newAirnode);

    constructor(
        address administrator,
        address initialUpdater,
        address initialSourceAirnode,
        bytes32 ethUsdTemplateId
    ) Ownable(administrator) {
        if (administrator == address(0) || initialUpdater == address(0)) revert ZeroAddress();
        if (initialSourceAirnode == address(0)) revert ZeroAddress();
        if (ethUsdTemplateId == bytes32(0)) revert EmptyTemplateId();

        updater = initialUpdater;
        sourceAirnode = initialSourceAirnode;
        templateId = ethUsdTemplateId;
    }

    /// @notice Publishes a new CoinGecko-signed ETH/USD observation.
    /// @dev The signature format intentionally matches API3's
    ///      BeaconUpdatesWithSignedData.updateBeaconWithSignedData().
    function updatePrice(
        bytes32 observationTemplateId,
        uint256 observationTimestamp,
        bytes calldata encodedValue,
        bytes calldata signature
    ) external {
        if (msg.sender != updater) revert UnauthorizedUpdater(msg.sender);
        if (observationTemplateId != templateId) {
            revert UnexpectedTemplateId(observationTemplateId, templateId);
        }
        if (encodedValue.length != 32) revert InvalidEncodedValueLength(encodedValue.length);
        if (observationTimestamp <= sourceTimestamp) {
            revert SourceTimestampNotNewer(observationTimestamp, sourceTimestamp);
        }

        _validateTimestamp(observationTimestamp);

        bytes32 payloadHash = keccak256(
            abi.encodePacked(observationTemplateId, observationTimestamp, encodedValue)
        );
        _validateSignature(payloadHash, signature);

        int256 signedPrice = abi.decode(encodedValue, (int256));
        if (signedPrice <= 0) revert InvalidPrice(signedPrice);

        latestPriceUsdE18 = uint256(signedPrice);
        sourceTimestamp = observationTimestamp;
        recordedAt = block.timestamp;
        latestBeaconId = keccak256(abi.encodePacked(sourceAirnode, observationTemplateId));
        latestPayloadHash = payloadHash;
        latestSignatureHash = keccak256(signature);

        emit PriceUpdated(
            latestPriceUsdE18,
            observationTimestamp,
            block.timestamp,
            sourceAirnode,
            observationTemplateId,
            latestBeaconId,
            payloadHash,
            latestSignatureHash
        );
    }

    /// @notice Changes the address permitted to publish valid signed observations.
    function setUpdater(address newUpdater) external onlyOwner {
        if (newUpdater == address(0)) revert ZeroAddress();
        address previousUpdater = updater;
        updater = newUpdater;
        emit UpdaterChanged(previousUpdater, newUpdater);
    }

    /// @notice Rotates the CoinGecko signing address after off-chain certification is checked.
    function setSourceAirnode(address newSourceAirnode) external onlyOwner {
        if (newSourceAirnode == address(0)) revert ZeroAddress();
        address previousAirnode = sourceAirnode;
        sourceAirnode = newSourceAirnode;
        emit SourceAirnodeChanged(previousAirnode, newSourceAirnode);
    }

    function _validateTimestamp(uint256 observationTimestamp) private view {
        uint256 newestAllowed = block.timestamp + MAX_FUTURE_DRIFT;
        if (observationTimestamp > newestAllowed) {
            revert SourceTimestampTooFarInFuture(observationTimestamp, newestAllowed);
        }
        uint256 oldestAllowed =
            block.timestamp > MAX_SOURCE_AGE ? block.timestamp - MAX_SOURCE_AGE : 0;
        if (observationTimestamp < oldestAllowed) {
            revert SourceTimestampTooOld(observationTimestamp, oldestAllowed);
        }
    }

    function _validateSignature(bytes32 payloadHash, bytes calldata signature) private view {
        address recoveredSigner = ECDSA.recover(payloadHash.toEthSignedMessageHash(), signature);
        if (recoveredSigner != sourceAirnode) {
            revert InvalidSourceSigner(recoveredSigner, sourceAirnode);
        }
    }
}
