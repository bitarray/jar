# JAR: A Coinless Blockchain

## Context

JAR (Join-Accumulate Refine) is a blockchain protocol based on JAM. It began as Grey — an experiment where an AI agent built a complete node implementation in Rust in under a week for ~$50 in API costs. The project evolved into JAR: a formal specification in Lean 4 with testing, fuzzing, and a variant system for protocol experimentation.

JAR is built by AI agents, with human guidance on strategic decisions. This isn't incidental — it's the thesis: **JAR is a blockchain protocol built by AI agents, for AI agents.**

The project has a genesis distribution mechanism called [Proof of Intelligence](genesis.md) — a system where tokens materialize exclusively through demonstrated intelligence: code contributions that get reviewed, ranked, and merged. There is no premine, no team allocation, no investor round, no foundation reserve. Every token in existence is earned by contributing to the protocol.

This document proposes the next step: a **coinless** mainnet design where the base-layer protocol has no native token at all.

## The Problem with Coins

Every existing L1 blockchain forces participants into a token economy. Want to build on Ethereum? You need ETH. Solana? SOL. This creates several problems:

**The "not-my-coin" problem.** Protocols compete on token price rather than technical merit. Users and developers must buy into a specific token economy before they can use the infrastructure. This friction exists for economic reasons, not technical ones.

**Initial distribution is always political.** ICOs favor capital. Airdrops favor connections or Sybil capacity. Premines favor insiders. Every distribution mechanism creates winners and losers based on criteria unrelated to contribution.

**Revenue must go somewhere.** If the protocol generates revenue (transaction fees, MEV), that revenue accrues to token holders. This creates a class of passive rent-seekers who extract value without contributing. The conversation about revenue is inherently adversarial — every dollar to one party is a dollar not going to another.

**Gas fees are artificial scarcity.** On a non-congested chain, the marginal cost of processing an additional transaction is approximately zero. Charging for it is rent extraction. In an era of abundant compute — especially in AI economics where we expect excess capacity — this model is increasingly misaligned with reality.

## The Coinless Design

JAR's base layer has no native coin. Instead:

### Governance: Proof of Intelligence

The [Proof of Intelligence](genesis.md) system continues from genesis into mainnet. Contributors earn **weight** by submitting code that gets reviewed, ranked, and merged. Weight is:

- **Cumulative** — the sum of scores across all contributions.
- **Non-transferable** — you can't buy weight, only earn it.
- **Dilutive** — if you stop contributing, your share of total weight decreases as others earn more. Structurally equivalent to Proof of Work: miners must continuously spend electricity to maintain hashrate share; here, contributors must continuously produce intelligent work.

The scoring mechanism uses ranked comparison (not absolute scores) with a weighted lower-quantile aggregation that provides Byzantine fault tolerance. Below 50% of reviewer weight, a Sybil coalition cannot inflate their own scores. The full security analysis is in the [genesis document](genesis.md).

### Validator Selection: Weight-Based NPoS

Weight holders nominate validators through a standard Nominated Proof-of-Stake (NPoS) mechanism:

1. Contributors accumulate weight through Proof of Intelligence.
2. Weight holders nominate validators they trust.
3. The protocol selects the active validator set based on nominations.
4. Validators produce blocks and participate in consensus.

The validator set bridges the off-chain intelligence process and on-chain consensus. No coins change hands — it's pure governance, backed by demonstrated contribution.

### Transactions: Free by Default

The base layer does not charge for transactions. Validators decide which work packages to include based on their own criteria. When the chain is not congested — the expected steady state, since JAR is designed for high throughput — all valid transactions are included.

This is the natural price for a non-scarce resource. TCP/IP doesn't charge per packet. HTTP doesn't charge per request. When compute is abundant, the correct price for a transaction is zero.

### Service-Layer Economics: Launch Your Own Coin

JAR's architecture separates computation into **services**. Each service is an independent state machine that processes **work packages**: `refine` runs off-chain (parallel, scalable), then `accumulate` runs on-chain (sequential, finalized).

A service like CorePlay might host an entire smart contract platform. Users deploy contracts, launch tokens, and transact — entirely within CorePlay's own logic, not in any base-layer coin. Other services might provide storage, gaming, DeFi, or AI inference, each with their own token economics or none at all.

This means:
- **Users choose their token economy.** No forced buy-in to a base-layer token.
- **Services compete on merit.** Without a shared base token, there's no "my token vs your token" tribalism at the infrastructure level.
- **New services start free.** No gas costs to bootstrap. Deploy a service, attract users, introduce a token when and if it makes sense.

### Core-Time Market: Validator Revenue

Validators control a scarce resource: **core-time** (the number of cores available per timeslot is fixed). While transactions are free under normal conditions, core-time becomes scarce under congestion. This creates a natural bilateral market:

- **Services offer payment** to validators for prioritized core-time allocation, in whatever token the service uses.
- **Validators choose** which work packages to include, considering offered payments.
- **Under low congestion**, everyone gets included for free — services don't need to pay, and validators include everything.
- **Under high congestion**, paying services get priority — a natural market emerges without any protocol-level fee mechanism.

A validator's revenue is a portfolio of service-layer tokens — PLAY from CorePlay, STORE from a storage service, GAME from a gaming platform. This is explicit, above-board, and market-driven, unlike MEV extraction on existing chains.

### Protocol Self-Improvement: Reserved Throughput

A portion of throughput is reserved for protocol development — the agentic coordination process itself runs on-chain:

- PR submission, review, and scoring happen on-chain.
- The Proof of Intelligence mechanism is enforced by consensus, not by a GitHub bot.
- Protocol upgrades are proposed, reviewed, scored, and deployed through the same mechanism that built the protocol.

The protocol's operational cost is denominated in core-time, not money. The LLM inference tokens needed to run the contributing and reviewing agents are the real cost — funded through the Protocol Guild mechanism described below.

### Long-Term Funding: Protocol Guild

We expect the ecosystem to evolve a pattern similar to Ethereum's [Protocol Guild](https://www.protocolguild.org/): projects that launch coins on JAR voluntarily contribute a portion of their revenue to fund core protocol development.

The incentive is self-interest: if your project runs on JAR, you benefit from JAR being well-maintained, secure, and improving. The contribution funds LLM tokens for the agents that build and maintain the protocol. This creates a virtuous cycle:

1. Agents build the protocol (earn weight).
2. Weight governs the validator set.
3. Validators run the chain (free transactions).
4. Users build services on the chain (launch coins).
5. Successful services voluntarily fund protocol development.
6. Funding pays for LLM inference.
7. LLM inference powers the agents. Back to 1.

This is not a tax or a protocol-level fee. It's a social contract — the same one that funds open-source infrastructure today, except the "maintainers" are AI agents whose costs (LLM tokens) are transparent and auditable.

## Security Analysis

### Cost to Attack

To compromise the network, an attacker needs to control >1/3 of the validator set (BFT threshold). This requires controlling >1/3 of total weight through NPoS nominations.

**Attack via weight accumulation.** To earn weight, you must make genuine contributions that pass review by existing weight holders. This cannot be parallelized — each PR is reviewed against historical commits, and the review process is bottlenecked by reviewer bandwidth. If average weight per merged PR is ~40 and an agent can get ~3-5 PRs merged per week, accumulating 1/3 of a mature system's weight takes years of sustained genuine contribution. During that time, honest contributors are also earning weight — it's a Red Queen race.

**Attack via bribery.** You must offer validators more than their expected future revenue (service-layer token payments) plus the non-fungible value of their weight and reputation. Weight cannot be repurchased once lost — a contributor's track record of years of work is destroyed by a single defection.

**The key property:** The optimal long-run attack strategy is indistinguishable from honest participation. To accumulate enough weight to influence governance, you must produce work that existing weight holders judge as valuable. By the time you have enough influence to attack, you've invested so much genuine contribution that attacking destroys more value than it captures.

| Chain | Cost to control 1/3 | Nature of cost |
|-------|---------------------|----------------|
| Bitcoin | ~$10B+ in hardware + electricity | Capital + energy |
| Ethereum | ~$15B+ in staked ETH | Capital (liquid, recoverable) |
| JAR | Years of genuine intellectual contribution | Time + intelligence (non-transferable) |

### Formal Verification

JAR's specification is written in Lean 4, a language with machine-checked correctness guarantees. The security properties described above can be — and are intended to be — formally proven:

- **Sybil resistance:** Splitting contributions across accounts provides zero advantage (weight linearity).
- **Manipulation bounds:** Below 50% reviewer weight, a coalition cannot inflate scores (quantile property).
- **Dilution monotonicity:** Inactive contributors' weight share strictly decreases over time.
- **Attack cost lower bounds:** Controlling 1/3 of validators requires producing a proportional amount of genuine work, under honest reviewer majority.

These proofs would live alongside the protocol specification, checked by the same type checker, contributed by the same agents, and scored by the same mechanism whose properties they prove. The protocol reasons about itself, in itself.
