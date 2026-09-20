// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice The reading side of a trust oracle, as the existing TrustGateHook
///         defines it. Kept byte-compatible on purpose: a deployment that
///         already points at an oracle can point at this hook instead without
///         changing what it talks to.
interface ITrustOracle {
    function getScore(uint256 agentId, uint256 chainId, string calldata namespace)
        external
        view
        returns (uint256 score, uint256 grade, uint256 confidence, uint256 updatedAt);

    function meetsThreshold(uint256 agentId, uint256 chainId, string calldata namespace, uint256 threshold)
        external
        view
        returns (bool);
}

/**
 * @title MerkleTrustGateHook
 * @notice Gates a job on a trust score the caller proves, instead of one the
 *         chain is asked for.
 *
 * @dev Why this exists.
 *
 * The oracle-reading gate has a liveness problem that is not hypothetical: the
 * reference trust oracle on Base was last written on 2026-04-24 and its own
 * documentation claims a nightly sync. A gate that reads it today is enforcing
 * five-month-old scores while reporting them as current, and nothing on chain
 * says so.
 *
 * This hook inverts the direction. The issuer publishes one Merkle root per
 * batch of scores, with the time it was computed. The caller supplies the leaf
 * and the path, and the contract checks the arithmetic. Three things follow:
 *
 *  - Staleness becomes visible. A root carries `computedAt`, and the hook
 *    refuses a root older than `maxAgeSeconds`. The oracle version cannot do
 *    this, because a score with no timestamp of its own looks the same on day
 *    one and day one hundred and fifty.
 *  - The gate costs one hash chain instead of one external call. No reentrancy
 *    surface, no oracle that can revert the job, no dependency on another
 *    contract being alive at settle time.
 *  - The issuer cannot change an individual score after the fact without
 *    moving the root, and moving the root is a visible transaction.
 *
 * What it does not do: it does not make the issuer honest. A published root is
 * exactly as trustworthy as whoever signed the transaction that published it.
 * It makes the issuer's claims fixed, timestamped and checkable, which is a
 * different and smaller promise than the oracle version implies.
 *
 * Not upgradeable, no proxy, no delegatecall — per the hook-contracts rules.
 */
contract MerkleTrustGateHook {
    // -------------------------------------------------------------- errors --

    error NotOwner();
    error ZeroAddress();
    error ZeroRoot();
    error RootNotSet();
    error RootTooOld(uint256 computedAt, uint256 maxAgeSeconds);
    error ProofInvalid();
    error BelowThreshold(uint256 score, uint256 threshold);
    error ThresholdTooHigh(uint256 threshold);
    error MaxAgeTooShort(uint256 maxAgeSeconds);

    // -------------------------------------------------------------- events --

    event RootPublished(bytes32 indexed root, uint256 computedAt, uint256 leafCount);
    event ThresholdSet(uint256 threshold);
    event MaxAgeSet(uint256 maxAgeSeconds);
    event OwnerTransferred(address indexed from, address indexed to);
    event GatePassed(address indexed subject, uint256 score, bytes32 indexed root);

    // ------------------------------------------------------------- storage --

    /// @notice Scores are percentages. A threshold above this can never be met,
    ///         which would brick the gate silently rather than loudly.
    uint256 public constant MAX_SCORE = 100;

    /// @notice A window shorter than this cannot be satisfied by any real
    ///         publishing cadence and is refused at the setter.
    uint256 public constant MIN_MAX_AGE = 1 hours;

    address public owner;

    bytes32 public root;
    uint256 public rootComputedAt;
    uint256 public rootLeafCount;

    uint256 public threshold;
    uint256 public maxAgeSeconds;

    // ------------------------------------------------------------ modifiers --

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // ---------------------------------------------------------- constructor --

    constructor(address initialOwner, uint256 initialThreshold, uint256 initialMaxAgeSeconds) {
        if (initialOwner == address(0)) revert ZeroAddress();
        if (initialThreshold > MAX_SCORE) revert ThresholdTooHigh(initialThreshold);
        if (initialMaxAgeSeconds < MIN_MAX_AGE) revert MaxAgeTooShort(initialMaxAgeSeconds);

        owner = initialOwner;
        threshold = initialThreshold;
        maxAgeSeconds = initialMaxAgeSeconds;

        emit OwnerTransferred(address(0), initialOwner);
        emit ThresholdSet(initialThreshold);
        emit MaxAgeSet(initialMaxAgeSeconds);
    }

    // --------------------------------------------------------------- admin --

    /**
     * @notice Publish the root of a scored batch.
     * @param newRoot      Merkle root over the batch's leaves.
     * @param computedAt   When the scores were computed, not when they were
     *                     published. The two differ and only the first is a
     *                     statement about the data.
     * @param leafCount    How many agents the batch covers. Recorded so a root
     *                     over one agent is distinguishable from a root over
     *                     ten thousand; a single-leaf root is a valid Merkle
     *                     root and a meaningless attestation.
     */
    function publishRoot(bytes32 newRoot, uint256 computedAt, uint256 leafCount) external onlyOwner {
        if (newRoot == bytes32(0)) revert ZeroRoot();
        // A root claiming to be from the future is a clock error at best, and
        // it would survive every staleness check forever.
        if (computedAt > block.timestamp) revert RootTooOld(computedAt, maxAgeSeconds);

        root = newRoot;
        rootComputedAt = computedAt;
        rootLeafCount = leafCount;
        emit RootPublished(newRoot, computedAt, leafCount);
    }

    function setThreshold(uint256 newThreshold) external onlyOwner {
        if (newThreshold > MAX_SCORE) revert ThresholdTooHigh(newThreshold);
        threshold = newThreshold;
        emit ThresholdSet(newThreshold);
    }

    function setMaxAge(uint256 newMaxAgeSeconds) external onlyOwner {
        if (newMaxAgeSeconds < MIN_MAX_AGE) revert MaxAgeTooShort(newMaxAgeSeconds);
        maxAgeSeconds = newMaxAgeSeconds;
        emit MaxAgeSet(newMaxAgeSeconds);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnerTransferred(owner, newOwner);
        owner = newOwner;
    }

    // ---------------------------------------------------------- the leaf ----

    /**
     * @notice The leaf a subject and score hash to.
     * @dev Double-hashed, and the inner hash uses abi.encode rather than
     *      encodePacked. Both matter:
     *
     *      encodePacked over (address, uint256) is fixed-width here and so not
     *      itself ambiguous, but the moment a string or bytes field is added it
     *      becomes so, and the collision is silent. encode is unambiguous by
     *      construction.
     *
     *      The outer hash keeps a leaf from being reinterpreted as an internal
     *      node. Without it, a caller who can choose a "score" can present a
     *      precomputed internal node as a leaf and prove membership of a pair
     *      that was never in the tree — the second-preimage attack every
     *      Merkle implementation has to answer.
     */
    function leafOf(address subject, uint256 score) public pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(subject, score))));
    }

    /**
     * @notice Is this subject attested at this score?
     * @dev Takes the subject and score, never a raw leaf.
     *
     *      An earlier draft exposed `verify(proof, leaf)` and a test caught
     *      what that allows: hand it an internal node instead of a leaf and it
     *      walks to the root perfectly, proving membership of a pair that was
     *      never a leaf. The leaf domain separation is real — leaves hash 32
     *      bytes, internal nodes hash 64 — but it only protects a caller who
     *      cannot choose the starting value. Taking (subject, score) means
     *      nobody can.
     */
    function verifyMembership(address subject, uint256 score, bytes32[] calldata proof) public view returns (bool) {
        if (root == bytes32(0)) return false;
        return _walk(leafOf(subject, score), proof) == root;
    }

    /// @dev Sorted pairs, so a proof carries no direction bits.
    function _walk(bytes32 leaf, bytes32[] calldata proof) private pure returns (bytes32) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 sibling = proof[i];
            computed = computed <= sibling
                ? keccak256(abi.encode(computed, sibling))
                : keccak256(abi.encode(sibling, computed));
        }
        return computed;
    }

    // ----------------------------------------------------------- the gate ---

    /**
     * @notice Everything the gate checks, in one view call.
     * @dev Exposed so a caller can find out why it would be rejected without
     *      spending a transaction to be told.
     */
    function check(address subject, uint256 score, bytes32[] calldata proof)
        public
        view
        returns (bool ok, string memory reason)
    {
        if (root == bytes32(0)) return (false, "no root published");
        if (block.timestamp - rootComputedAt > maxAgeSeconds) return (false, "root is stale");
        if (score < threshold) return (false, "score below threshold");
        if (!verifyMembership(subject, score, proof)) return (false, "proof does not reach the root");
        return (true, "");
    }

    /**
     * @notice Gate one party. Reverts with the specific reason.
     * @dev The named errors are the point. A single `require(ok)` tells a
     *      caller that something failed, which is the least useful thing a gate
     *      can say to someone trying to integrate against it.
     */
    function gate(address subject, uint256 score, bytes32[] calldata proof) public {
        if (root == bytes32(0)) revert RootNotSet();
        if (block.timestamp - rootComputedAt > maxAgeSeconds) {
            revert RootTooOld(rootComputedAt, maxAgeSeconds);
        }
        if (score < threshold) revert BelowThreshold(score, threshold);
        if (!verifyMembership(subject, score, proof)) revert ProofInvalid();
        emit GatePassed(subject, score, root);
    }

    /**
     * @notice ERC-8183 hook entry points.
     * @dev Decoded from `optParams`, which the core contract forwards untouched.
     *      A job whose params do not decode is rejected rather than waved
     *      through: a gate that passes when it cannot read its input is not a
     *      gate.
     */
    function preFund(address client, bytes calldata optParams) external {
        (uint256 score, bytes32[] memory proof) = abi.decode(optParams, (uint256, bytes32[]));
        _gateMemory(client, score, proof);
    }

    function preSubmit(address provider, bytes calldata optParams) external {
        (uint256 score, bytes32[] memory proof) = abi.decode(optParams, (uint256, bytes32[]));
        _gateMemory(provider, score, proof);
    }

    function _gateMemory(address subject, uint256 score, bytes32[] memory proof) internal {
        if (root == bytes32(0)) revert RootNotSet();
        if (block.timestamp - rootComputedAt > maxAgeSeconds) {
            revert RootTooOld(rootComputedAt, maxAgeSeconds);
        }
        if (score < threshold) revert BelowThreshold(score, threshold);

        bytes32 computed = leafOf(subject, score);
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 sibling = proof[i];
            computed = computed <= sibling
                ? keccak256(abi.encode(computed, sibling))
                : keccak256(abi.encode(sibling, computed));
        }
        if (computed != root) revert ProofInvalid();
        emit GatePassed(subject, score, root);
    }

    // ------------------------------------------------------- introspection --

    /// @notice How old the current root is, in seconds. Reverts nothing; a
    ///         caller deciding whether to trust this gate should be able to ask.
    function rootAgeSeconds() external view returns (uint256) {
        if (rootComputedAt == 0) return type(uint256).max;
        return block.timestamp - rootComputedAt;
    }
}
