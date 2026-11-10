# curve-archaeology

A multi-phase research plan to explain the origin of unexplained "random-looking" constants in deployed
cryptographic standards, by recognizing the output of a period pseudo-random number generator, recovering
its state, and reading back the seed.

The work extends the method behind Anthropic's 2026 result that the NIST ECDSA curve seeds are
`drand48`/`lrand48` output seeded with 1997–98 Unix timestamps
([post](https://www.anthropic.com/research/ecdsa-curve-origins),
[Valsorda](https://words.filippo.io/seeds-solved/)).

- **[PROPOSAL.md](PROPOSAL.md)** — the plan: objective and scope, a tiered evidence standard, operating
  rules, shared infrastructure (`gens/`, `solvers/`), eight phases (0–7), sequencing and budget, and four
  appendices (a sandbox pilot that independently reproduced the published results and the full candidate
  census; the verified X9.62/FIPS 186 generation procedure; the changelog; and a catalogue of public work
  as of 2026-11-10).
- **[CLAUDE.md](CLAUDE.md)** — the binding operating rules for any agent working in this repository.

Targets, in priority order: the NIST/X9.62 skipped-candidate filter; the B-163 seed and the unexplained
NIST base points; the SECG/secp256k1 base points; the Dual_EC_DRBG point Q; the FRP256v1, SM2 and GOST
curves; and same-era "nothing-up-my-sleeve" constants including the Kuznyechik/Streebog S-box residue.

A documented, quantified negative result is an acceptable outcome for every target. Nothing is published or
disclosed without user sign-off; see the disclosure rules in PROPOSAL.md §3 and Phase 7.
