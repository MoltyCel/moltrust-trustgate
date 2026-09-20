# moltrust-trustgate

An ERC-8183 hook that gates a job on a trust score the caller **proves**, rather
than one the chain is **asked for**.

Draft. Not deployed, not audited, not submitted anywhere.

## The problem it answers

The existing trust gate reads a score from an oracle contract at the moment a
job is funded or submitted. That works for exactly as long as somebody keeps
writing to the oracle.

The reference trust oracle on Base — `0xD5fdccD492bB5568bC7aeB1f1E888e0BbA6276f4` —
was last written on **2026-04-24**. Its own published methodology says the
oracle "is updated nightly via delta sync after each scoring run". A gate
reading it today enforces April data and reports it as current. Nothing on
chain says otherwise, because a score with no timestamp of its own looks
identical on day one and on day one hundred and fifty.

*(Verified 2026-09-20 by reading the contract's transaction history; the live
`getScore` call returned `updatedAt` = 2026-03-20.)*

## What this does instead

The issuer publishes one Merkle root per scored batch, together with **when the
scores were computed** — not when they were published, since only the first is a
statement about the data. A caller presents its score and the path; the contract
checks the arithmetic.

```
publishRoot(root, computedAt, leafCount)     issuer, once per batch
gate(subject, score, proof)                  caller, per job
check(subject, score, proof) → (ok, reason)  anyone, free
```

Three consequences:

**Staleness is enforceable.** `maxAgeSeconds` refuses a root older than the
window. The oracle version cannot do this because the data carries no age.

**No external call.** One hash chain instead of a cross-contract read: no
reentrancy surface, no oracle that can revert a settlement, no dependency on
another contract still being alive when the job closes.

**Scores become immutable between publications.** An issuer cannot quietly
change one agent's number; moving any leaf moves the root, and moving the root
is a transaction anyone can see.

### What it does not do

It does not make the issuer honest. A published root is exactly as trustworthy
as whoever signed the transaction that published it. What changes is that the
issuer's claims become fixed, timestamped and checkable — a smaller and more
defensible promise than a live oracle read implies.

## Leaf format

```solidity
leaf = keccak256(bytes.concat(keccak256(abi.encode(subject, score))))
```

Double-hashed, and `abi.encode` rather than `encodePacked`.

The double hash separates the leaf domain from the internal-node domain: a leaf
hashes 32 bytes, an internal node hashes 64. Without it, a precomputed internal
node can be presented as a leaf and will walk to the root, proving membership of
a pair that was never in the tree.

That is not theoretical here. The first draft of this contract exposed
`verify(proof, leaf)` taking a raw `bytes32`, and the test suite caught exactly
that: an internal node passed as a leaf verified successfully. The public API
now takes `(subject, score)` and computes the leaf itself, so a caller cannot
name a starting value at all.

`abi.encode` over `(address, uint256)` is not itself ambiguous — both fields are
fixed-width — but it becomes ambiguous the moment a `string` or `bytes` field is
added, and that collision is silent. Unambiguous by construction is cheaper than
remembering.

## Interface compatibility

`ITrustOracle` is declared with the same signatures the existing hook uses, so a
deployment already pointed at an oracle can point here instead without changing
what it talks to.

## Tests

```
forge test
```

17 tests, including two fuzz properties. The ones worth reading:

| test | what it pins |
|---|---|
| `a_member_below_threshold_is_refused_with_its_score` | a **valid** proof for a low score still fails — the case a proof-only check waves through |
| `a_score_the_caller_raised_breaks_the_proof` | the score is inside the leaf, so inflating it breaks the path |
| `a_stale_root_is_refused_even_with_a_perfect_proof` | the reason this contract exists |
| `a_root_at_exactly_the_age_limit_still_passes` | the boundary is on the permitted side, or the limit means something other than it says |
| `no_root_means_refusal_not_an_open_gate` | an unconfigured gate is closed, not open |
| `a_root_from_the_future_is_refused` | it would survive every staleness check forever |
| `params_that_do_not_decode_are_rejected_not_waved_through` | a gate that passes when it cannot read its input is not a gate |
| `the_dials_refuse_values_that_would_brick_the_gate` | a threshold above 100 or a window under an hour can never be satisfied |

## Relationship to the upstream hook repo

`erc-8183/hook-contracts` requires one hook per PR, a single `.sol` file, no
tests, vendor-neutral naming, no proxies or upgradeability, `^0.8.20`, named
imports and zero-address checks. `src/MerkleTrustGateHook.sol` is written to
satisfy all of that, so it can be submitted unchanged if that is ever decided.

The tests and CI live here because that repo does not take them — which is a
reason to keep them somewhere, not a reason not to have them.

**Note:** no ERC-8183 core contract is deployed on mainnet as of 2026-09-20, so
a hook currently has nothing to attach to.

## Status

- [x] Contract, tests, CI
- [ ] External review
- [ ] Deployment — needs a signing decision, and the wallet rules make that human-gated
- [ ] Upstream submission — not decided
