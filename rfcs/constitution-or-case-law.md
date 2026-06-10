# Is Proof of Intelligence the Constitution, or Does JAR Need One?

**Status:** Discussion. Not normative. Submitted as a PR so the question itself can be scored under the mechanism it interrogates.

## The question

`/Genesis.md` describes an unusually rigorous procedure. Linear weight to neutralise Sybil splitting; ranked rather than scalar review; weighted lower-quantile aggregation that is BFT-safe under the same 50% / 66% thresholds as PoS; dilution as ongoing cost; meta-reviews to filter biased reviewers. Taken on its own terms it is one of the more careful Sybil-resistant scoring designs published for a contributor token.

But it raises a question the document does not directly answer:

> Is the Proof of Intelligence mechanism *itself* JAR's constitution, or does JAR need a separate constitutional document?

It matters because the mechanism formalises **how** judgments are aggregated, but is silent on **what** is being judged. Reviewers rank PRs on difficulty, novelty, and design quality (with design weighted 3×) — but those terms are tacit. They are constitutional placeholders, not constitutional content. Whoever supplies the tacit interpretation in the bootstrap phase effectively writes the constitution by example, regardless of how unbiased the aggregation is downstream.

## Two kinds of constitution

It helps to separate two things that usually get bundled together:

- **A constitution of process** — how decisions are aggregated, how disputes route, what counts as a valid vote, who is enfranchised. This is the domain of voting rules, BFT thresholds, governance procedures.
- **A constitution of content** — what the polity is *for*. What outcomes are good. What the negative space looks like. What burden-of-proof sits where.

Most political constitutions try to do both. Most blockchain governance docs lean heavily on the first and assume the second is obvious. Most AI labs' alignment frameworks lean heavily on the second and assume the first is obvious.

**JAR currently has an unusually strong constitution of process and almost no written constitution of content.** That is not necessarily wrong — it might be deliberate — but it is worth naming, because it implies something specific about what the next contribution-shaped document should be.

## The Anthropic comparison: Constitutional AI

The most prominent recent attempt at writing a constitution of content for an evolving system is Anthropic's Constitutional AI (CAI), published in 2022 and used in the training of Claude. Briefly:

- Anthropic wrote an explicit list of natural-language principles — drawn from sources like the UN Declaration of Human Rights, terms-of-service standards, and Anthropic's own research on harm — covering what a good response should and should not do.
- The model is then trained against this constitution via **Reinforcement Learning from AI Feedback (RLAIF)**: another model evaluates outputs against the written principles, and those evaluations replace much of the human-feedback signal that earlier RLHF pipelines used.
- The distinctive bet is that an explicit, public, principled document plus a procedural training loop produces more legible and more steerable behaviour than RLHF alone, because the *content* is auditable and revisable independently of the *mechanism*.

This is worth contrasting briefly with the other major labs, because it sharpens what is actually distinctive:

- **OpenAI** publishes a Model Spec — a written behavioural spec that prescribes content (helpful, harmless, honest hierarchies; how to handle dual-use; default vs. configurable behaviours). It is closer to a product policy than a philosophical constitution, but it serves a similar role.
- **Google DeepMind** uses a mix of human feedback, automated red-teaming, and rule-based systems across Gemini. There is no single unifying public framework comparable to CAI.
- **Meta (Llama)** relies primarily on RLHF and safety guidelines, with the alignment story largely implicit and the openness story load-bearing instead.
- **xAI** publicly emphasises minimalism and "truth-seeking" with comparatively little disclosed methodological infrastructure.

The honest summary is that *all* the frontier labs use some mix of human feedback, AI feedback, written behavioural specs, and red-teaming. The differences are emphasis, transparency, and which gap each lab thinks is the bottleneck. Anthropic's distinctiveness is not that CAI is uniquely effective — it is that Anthropic has been distinctively *public and principled about describing* its method.

For JAR's purposes, the relevant takeaway is structural:

> **CAI = explicit constitution of content + procedural training loop.**
> **JAR = explicit procedural mechanism + tacit content.**

These are mirror images.

## The case for keeping it tacit

There is a genuine argument that JAR should *not* write a constitution of content, and it deserves a fair hearing.

1. **Premature canonisation.** Writing down what counts as "intelligent contribution" too early forecloses the very thing the mechanism is designed to discover. PoI is a search procedure over the space of useful protocol-level work; the search is interesting only because the answer is not pre-known.
2. **Goodhart risk.** Any explicit content constitution becomes a target. Contributors will optimise to its letter rather than to the substance reviewers actually care about. The procedural mechanism is robust to this in a way written rubrics are not.
3. **Common law as feature.** Accumulated PR scoring, read in retrospect, *is* a body of case law — and case law has well-known advantages over codification: it is grounded in concrete decisions, it permits fine-grained adjustment, and it surfaces edge cases the drafters of any written constitution would miss.

These are real arguments. The position "Proof of Intelligence is the constitution; the merged PRs are the case law that interpret it" is internally coherent.

## The case for a thin written layer anyway

The cold-start problem is the strongest counter-argument. In the current phase JAR has very few merged PRs, very few enfranchised reviewers, and no body of case law dense enough to interpolate from. Three concrete failure modes follow:

1. **Founder-shaped tacit knowledge.** With a small reviewer set, "good design" reduces to "what the founder would have done". The mechanism's Sybil resistance and BFT properties are real, but they only kick in once the reviewer pool is broad. In the bootstrap, the procedural mechanism cannot prevent a content-monoculture; only an explicit content document can.
2. **Capturable ambiguity.** New contributors have no map of what kinds of work JAR actually values. Without one, contributions cluster around whatever the most recently merged PR did, regardless of whether that was load-bearing or incidental. A short written piece — even a page — is a Schelling point that broadens the shape of incoming work.
3. **No written negative space.** The most useful thing a constitution of content can do is name what is *not* intelligent contribution: LOC inflation, gratuitous abstraction, vibes-only refactors, scope creep, formal-method theatre. Anti-pattern lists are far cheaper to write than rubrics for what is good, and they do most of the work of bounding the search space.

## Recommendation

Treat `/Genesis.md` as the constitution of process and add — separately, deliberately thin, and explicitly subject to revision by the case law it seeds — a constitution of content. A working name: **the Reviewer's Compass**.

It should pin down only three things:

1. **What counts as intelligent contribution to JAR specifically.** Examples: formal verification of currently-informal protocol invariants; protocol-economy improvements with quantified trade-offs; new attack-surface analyses; reductions in trusted surface; refinement of Lean specifications towards Grey's behaviour; changes that move JAR closer to being a Block for JAM in the Polkadot sense.
2. **The negative space.** Examples: changes that increase LOC without increasing assurance; refactors with no behavioural or proof delta; abstraction without a concrete second consumer; formal-method theatre (ceremony without coverage); duplication of work already done in upstream JAM testnets.
3. **Dispute resolution.** When a joiner and an accumulator disagree on whether a contribution was intelligent — what is the route? Today this is implicitly the founder. The Reviewer's Compass should at minimum acknowledge that, and the path beyond it.

The document should be **explicitly subordinate to the case law of merged PRs**, and should shrink as that case law thickens. Its job is not to legislate; it is to offer enough of a Schelling point that the search procedure can run while the founder is still in the loop, and to atrophy gracefully as the procedure becomes self-sustaining.

In the Anthropic comparison: this is the inverse design from CAI. CAI starts with an elaborate written constitution and uses a procedural loop to enforce it. JAR would start with an elaborate procedural mechanism and use a thin written layer to bootstrap the content of judgment until accumulated PR decisions can carry it.

## What this PR is asking for

This PR does not propose the Reviewer's Compass itself. It asks the joiner / accumulator / founder set to rule, under the existing PoI mechanism, on whether:

1. The framing above (process-constitution vs. content-constitution) is accepted.
2. A follow-up PR drafting a thin Reviewer's Compass would be in scope, or whether JAR's preference is to remain tacit.

The PR is intentionally self-referential: it is itself a discussion-shaped contribution, and so the verdict on it is also a verdict on whether discussion-shaped contributions count as intelligent under JAR's definition. That is a useful thing for the project to rule on early.
