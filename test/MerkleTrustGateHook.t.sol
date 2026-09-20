// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MerkleTrustGateHook} from "../src/MerkleTrustGateHook.sol";

contract MerkleTrustGateHookTest is Test {
    MerkleTrustGateHook internal hook;

    address internal owner = address(0xA11CE);
    address internal alice = address(0xA1);
    address internal bob = address(0xB0B);
    address internal carol = address(0xCA401);

    uint256 internal constant THRESHOLD = 40;
    uint256 internal constant MAX_AGE = 7 days;

    // A four-leaf tree, built the way the contract hashes: double-hashed
    // leaves, sorted pairs, abi.encode at every level.
    bytes32[4] internal leaves;
    bytes32 internal treeRoot;

    function setUp() public {
        vm.warp(1_700_000_000);
        hook = new MerkleTrustGateHook(owner, THRESHOLD, MAX_AGE);

        leaves[0] = _leaf(alice, 85);
        leaves[1] = _leaf(bob, 75);
        leaves[2] = _leaf(carol, 30);
        leaves[3] = _leaf(address(0xD), 50);

        bytes32 n01 = _hashPair(leaves[0], leaves[1]);
        bytes32 n23 = _hashPair(leaves[2], leaves[3]);
        treeRoot = _hashPair(n01, n23);

        vm.prank(owner);
        hook.publishRoot(treeRoot, block.timestamp, 4);
    }

    function _leaf(address subject, uint256 score) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(subject, score))));
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a <= b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }

    /// Proof for leaf 0: its sibling, then the other branch.
    function _proofForAlice() internal view returns (bytes32[] memory p) {
        p = new bytes32[](2);
        p[0] = leaves[1];
        p[1] = _hashPair(leaves[2], leaves[3]);
    }

    function _proofForCarol() internal view returns (bytes32[] memory p) {
        p = new bytes32[](2);
        p[0] = leaves[3];
        p[1] = _hashPair(leaves[0], leaves[1]);
    }

    // ---------------------------------------------------------------- 1 ----

    function test_a_member_above_threshold_passes() public {
        hook.gate(alice, 85, _proofForAlice());
        (bool ok, string memory reason) = hook.check(alice, 85, _proofForAlice());
        assertTrue(ok);
        assertEq(bytes(reason).length, 0);
    }

    // ---------------------------------------------------------------- 2 ----

    function test_a_member_below_threshold_is_refused_with_its_score() public {
        // Carol is genuinely in the tree. The proof is valid and she still
        // fails, which is the case a proof-only check would wave through.
        vm.expectRevert(abi.encodeWithSelector(MerkleTrustGateHook.BelowThreshold.selector, 30, THRESHOLD));
        hook.gate(carol, 30, _proofForCarol());
    }

    // ---------------------------------------------------------------- 3 ----

    function test_a_score_the_caller_raised_breaks_the_proof() public {
        // The obvious attack: keep the proof, claim a better number. The score
        // is inside the leaf, so the path stops reaching the root.
        vm.expectRevert(MerkleTrustGateHook.ProofInvalid.selector);
        hook.gate(carol, 95, _proofForCarol());
    }

    // ---------------------------------------------------------------- 4 ----

    function test_someone_elses_proof_does_not_work_for_you() public {
        vm.expectRevert(MerkleTrustGateHook.ProofInvalid.selector);
        hook.gate(bob, 85, _proofForAlice());
    }

    // ---------------------------------------------------------------- 5 ----

    function test_a_stale_root_is_refused_even_with_a_perfect_proof() public {
        // The whole reason this hook exists. The reference oracle on Base went
        // five months without a write while claiming a nightly sync; a gate
        // reading it enforced April data and said nothing.
        vm.warp(block.timestamp + MAX_AGE + 1);
        vm.expectRevert(abi.encodeWithSelector(MerkleTrustGateHook.RootTooOld.selector, hook.rootComputedAt(), MAX_AGE));
        hook.gate(alice, 85, _proofForAlice());
    }

    function test_a_root_at_exactly_the_age_limit_still_passes() public {
        // The boundary belongs on the permitted side, or every root is stale
        // one second early and the limit means something other than it says.
        vm.warp(block.timestamp + MAX_AGE);
        hook.gate(alice, 85, _proofForAlice());
    }

    // ---------------------------------------------------------------- 6 ----

    function test_no_root_means_refusal_not_an_open_gate() public {
        MerkleTrustGateHook fresh = new MerkleTrustGateHook(owner, THRESHOLD, MAX_AGE);
        vm.expectRevert(MerkleTrustGateHook.RootNotSet.selector);
        fresh.gate(alice, 85, _proofForAlice());

        (bool ok, string memory reason) = fresh.check(alice, 85, _proofForAlice());
        assertFalse(ok);
        assertEq(reason, "no root published");
    }

    // ---------------------------------------------------------------- 7 ----

    function test_an_internal_node_cannot_be_passed_off_as_a_leaf() public view {
        // Second preimage, and the first draft of this contract was open to it:
        // `verify(proof, leaf)` took a raw bytes32, so handing it the internal
        // node n01 with a one-element proof walked to the root and proved
        // membership of a pair that was never a leaf. The API takes
        // (subject, score) now, so there is no way to name a starting value —
        // the closest a caller can come is an address and a number, and those
        // always go through leafOf.
        //
        // What is asserted here is that the two domains cannot collide: a leaf
        // hashes 32 bytes, an internal node hashes 64.
        bytes32 n01 = _hashPair(leaves[0], leaves[1]);
        assertTrue(n01 != hook.leafOf(alice, 85));
        assertTrue(n01 != hook.leafOf(address(uint160(uint256(n01))), 0));
    }

    // ---------------------------------------------------------------- 8 ----

    function test_only_the_owner_moves_the_root_or_the_dials() public {
        vm.expectRevert(MerkleTrustGateHook.NotOwner.selector);
        hook.publishRoot(bytes32(uint256(1)), block.timestamp, 1);

        vm.expectRevert(MerkleTrustGateHook.NotOwner.selector);
        hook.setThreshold(0);

        vm.expectRevert(MerkleTrustGateHook.NotOwner.selector);
        hook.setMaxAge(365 days);

        vm.expectRevert(MerkleTrustGateHook.NotOwner.selector);
        hook.transferOwnership(alice);
    }

    // ---------------------------------------------------------------- 9 ----

    function test_the_dials_refuse_values_that_would_brick_the_gate() public {
        vm.startPrank(owner);

        // A threshold above the maximum score can never be met.
        vm.expectRevert(abi.encodeWithSelector(MerkleTrustGateHook.ThresholdTooHigh.selector, 101));
        hook.setThreshold(101);

        // A window no publishing cadence can satisfy closes the gate for good.
        vm.expectRevert(abi.encodeWithSelector(MerkleTrustGateHook.MaxAgeTooShort.selector, 60));
        hook.setMaxAge(60);

        // And a root with no content.
        vm.expectRevert(MerkleTrustGateHook.ZeroRoot.selector);
        hook.publishRoot(bytes32(0), block.timestamp, 1);

        vm.stopPrank();
    }

    function test_a_root_from_the_future_is_refused() public {
        // It would outlive every staleness check forever.
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(MerkleTrustGateHook.RootTooOld.selector, block.timestamp + 1, MAX_AGE));
        hook.publishRoot(bytes32(uint256(2)), block.timestamp + 1, 1);
    }

    // --------------------------------------------------------------- 10 ----

    function test_the_hook_entry_points_gate_the_same_way() public {
        bytes memory params = abi.encode(uint256(85), _proofForAlice());
        hook.preFund(alice, params);
        hook.preSubmit(alice, params);

        bytes memory bad = abi.encode(uint256(95), _proofForAlice());
        vm.expectRevert(MerkleTrustGateHook.ProofInvalid.selector);
        hook.preFund(alice, bad);
    }

    function test_params_that_do_not_decode_are_rejected_not_waved_through() public {
        // A gate that passes when it cannot read its input is not a gate.
        vm.expectRevert();
        hook.preFund(alice, hex"deadbeef");
    }

    // --------------------------------------------------------------- 11 ----

    function test_check_explains_itself_without_costing_a_transaction() public {
        bool ok;
        string memory reason;

        (ok, reason) = hook.check(carol, 30, _proofForCarol());
        assertFalse(ok);
        assertEq(reason, "score below threshold");

        (ok, reason) = hook.check(bob, 85, _proofForAlice());
        assertFalse(ok);
        assertEq(reason, "proof does not reach the root");

        vm.warp(block.timestamp + MAX_AGE + 1);
        (ok, reason) = hook.check(alice, 85, _proofForAlice());
        assertFalse(ok);
        assertEq(reason, "root is stale");
    }

    function test_root_age_is_readable_before_any_root_exists() public {
        MerkleTrustGateHook fresh = new MerkleTrustGateHook(owner, THRESHOLD, MAX_AGE);
        assertEq(fresh.rootAgeSeconds(), type(uint256).max);
        assertEq(hook.rootAgeSeconds(), 0);
    }

    // ------------------------------------------------------------ fuzzing --

    function testFuzz_a_score_that_is_not_the_attested_one_never_verifies(uint256 claimed) public view {
        vm.assume(claimed != 85);
        assertFalse(hook.verifyMembership(alice, claimed, _proofForAlice()));
    }

    function testFuzz_an_address_that_is_not_in_the_tree_never_verifies(address who) public view {
        vm.assume(who != alice);
        assertFalse(hook.verifyMembership(who, 85, _proofForAlice()));
    }
}
