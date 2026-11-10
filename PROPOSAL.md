# Curve Archaeology: Multi-Phase Agent Proposal

Rev. 2 — 2026-11-10 · @Vaishnav

> Rev. 2 incorporates a source-verified review of the state of the art as of 2026-11-10 (the Anthropic post and Valsorda's bounty-claimed write-up of 2026-10-16, the public follow-up work, and the primary standards documents), plus a sandbox pilot that re-derived the published results and the full candidate census independently. Changes from Rev. 1 are summarized in Appendix C.

## 1. Objective and scope

Explain the origin of unexplained "random-looking" constants in deployed cryptographic standards. The work starts from the infrastructure Anthropic published for the NIST seeds ([post](https://www.anthropic.com/research/ecdsa-curve-origins), [Valsorda](https://words.filippo.io/seeds-solved/)) and extends its method — recognize the output of a period PRNG, recover its state, read back the seed — to the constants that remain unexplained.

**What is already settled** (reproduced in the pilot, Appendix A): the ten NIST/X9.62 prime-curve seeds are consecutive 20-byte blocks of `(int)(drand48()*256)` after `srand48(t)` for ten Unix timestamps between 1997-05-15 and 1998-04-03; the four published binary seeds B-233/283/409/571 are five 31-bit `lrand48()` words each, after `srand48(t/2)`; the base points of P-192 and the five X9.62 example prime curves come from the FreeLIP `zrandom` generator seeded with small integers. These are not targets. They are the regression tests of Phase 0 and the training data for everything after.

**Targets**, in priority order (expected value = security relevance × tractability × how little is already known):

| # | Target | What counts as success | Security relevance | Prior art status |
| --- | --- | --- | --- | --- |
| 1 | The NIST/X9.62 skipped-candidate filter: why ~half of acceptable candidates were passed over | A mechanism that reproduces the 10-of-21 published/skipped split and is corroborated beyond the 18.4-bit label set | High: the last open backdoor-adjacent question on the P-curves | Open. Many deterministic features excluded by Anthropic, Valsorda, and a large public agent study (Appendix D). No mechanism |
| 2 | B-163 seed; base points of P-224/256/384/521 and of the NIST binary curves; the halved binary clock | A hypothesis regenerating the target bits at the evidence bar, or an enumerated negative space | None for base points; low for B-163 | Open. B-163 is a genuine seed (its seed→b verifies); not five `lrand48` words. Four later base points: public negatives exist |
| 3 | SECG / secp256k1 base points | A generation procedure for the structured value behind each family | None; very high visibility | Largely scooped: a public write-up (Oct 2026) found the shared "stored value" structure across 25 SECG/X9.62 curves. The residue (the stored strings, the last-digit rule) is open |
| 4 | Dual_EC_DRBG point Q (P-256/384/521) | (a) a verifiable random-*point* derivation of Qx; (b) a scalar recoverable from a weak/seedable PRNG; or (c) an enumerated negative space | Highest of any remaining target: outcome (b) is a live key-recovery | Open. Primary sources establish Q = d·P for a secret d; its provenance has never been investigated by PRNG archaeology |
| 5 | FRP256v1 (ANSSI), SM2 (OSCCA), GOST R 34.10 curves | Any reproducible derivation of b or G, or a documented negative space | Medium | Open; wide hypothesis space, highest false-positive risk |
| 6 | Same-era "nothing-up-my-sleeve" companions: FIPS 186 DSA example seeds, Kuznyechik/Streebog S-box residue, selected S-boxes | Explanation of a residual arbitrary choice, or a quantified residue | Low–medium | Mixed; several are low-capacity targets |

A clean negative result with a documented, quantified hypothesis space is an acceptable outcome for every target. For target 4 a negative result is the *expected* outcome and is still valuable; a positive result there is handled under a strict disclosure gate (§Phase 4-DualEC, rule 13).

**Non-goals.** No attack, no weakness search, no attempt to recover any secret that is still protective. Target 4 is pursued only to the point where provenance is decided; the moment a result would recover a usable trapdoor scalar, the rule-13 gate stops autonomous work. Explicitly out of scope: SHA-1 preimage search on unstructured seeds; the Solinas "humorous phrase" (a cracking problem, already shown wrong); CMEA, COMP128, DSAA, DES S-boxes, WTLS curves, Oakley groups, and other documented or hand-crafted tables.

---

## 2. Evidence standard

Every claim of the form "procedure H produced target T" is scored the same way.

- `match_bits`: bits of T that H reproduces exactly, at positions fixed before the comparison.
- `search_bits`: log2 of the number of distinct hypotheses whose match would have been reported for T or for any sibling target scanned by the same pipeline. Count every (generator, slicing, transform, seed or state, offset) combination, across all phases, pilots included. A lattice or algebraic solver that covers a whole state space counts the whole state space (lrand48: 48 bits per slicing). Scanning M targets with one pipeline adds log2 M.
- `margin = match_bits − search_bits`. The chance of a false positive is about 2^−margin, provided the registry is complete.

| Tier | Requirement | How it may be reported |
| --- | --- | --- |
| A, explained | margin ≥ 64 | As an explanation |
| B, probable | 32 ≤ margin < 64 **and** one independent corroboration: the same procedure, with no new free parameters, explains a sibling target at margin ≥ 16, or a prediction written to the registry before checking comes true | As probable, with the margin |
| C, lead | 16 ≤ margin < 32 | As a lead with a named confirmation test. Never as an explanation |
| noise | margin < 16 | Logged only |

Rules that follow from this:

1. **Capacity first.** Before any search on a target, write its capacity (entropy in bits) and the best reachable tier into the registry. A target with fewer than 80 bits cannot reach Tier A; say so up front. Known low-capacity targets: the Phase 1 labels (18.4 bits), the Kuznyechik permutation `s` (40.25 bits), single 4-bit S-boxes (44.25 bits).
2. **Margins add across siblings** only when the procedure and all its parameters are shared or derived by a stated rule. Per-target free parameters are paid for per target.
3. **Negative results need controls** (operating rule 8). A negative without a passing planted-target control is reported as "not tested".
4. **Partial matches** are scored by their own `match_bits` (contiguous, pre-declared positions). "Some bits, some curves" below Tier C is noise.
5. **Post-hoc hypotheses** (formed after looking at the target or at labels) are tagged `exploratory`, still counted in `search_bits`, and capped at Tier C until a confirmation test fixed in advance passes.

Worked example (the published result): one NIST prime seed, 160 bits; hypotheses = 34 generator/slice pairs × 2^48 states × windows ≈ 2^58; margin ≈ 100 per seed; ten seeds share the procedure. Tier A many times over. The rewind to an `srand48` state is free of new parameters; its evidence is that all ten decoded arguments fall inside one 11-month window out of 136 years (about 7 bits each).

---

## 3. Agent operating rules

These apply to every phase. `CLAUDE.md` in the repo root carries the same text.

1. **No constants from memory.** Every curve parameter, seed, S-box and test vector is fetched from a primary source and stored in `data/params/*.json` with source URL, document section, SHA-256 of the fetched file and fetch date. Cross-check each value against a second independent source (OpenSSL explicit parameters, the std-curves database, PARI, a library test vector). A value that fails the cross-check blocks the phase.
2. **Hypothesis registry.** Every hypothesis is a row in `registry/hypotheses.yaml` before it is run: target, generator, slicing, transforms, parameter ranges, `search_bits`, capacity, controls. After the run: `match_bits`, `margin`, tier, commit hash, wall time. Rows are never deleted. Nothing is tested off the books, including quick checks in a notebook.
3. **Evidence standard.** Section 2. Report the margin and tier with every claim.
4. **Generators are bit-exact.** Each generator in `gens/` ships with test vectors produced by the original source or a reference C build. An unverified generator invalidates every negative result it touched.
5. **Cross-target consistency.** A procedure claimed for one target is run on every sibling target from the same standard and era. A one-target explanation is flagged weak and cannot exceed Tier B.
6. **Gates.** At each gate write `reports/phaseN.md` and stop. Do not start the next phase in the chain without user sign-off.
7. **No public disclosure.** Nothing is posted, emailed, or pushed to a public remote. Findings, registry rows with positive margins and gate reports go only to a private remote. The agent contacts no third party; the user does.
8. **Controls for every negative.** A negative result is valid only if (a) planted targets, generated by the same generator and slicing with random seeds, are recovered by the same pipeline at ≥ 99% over at least 100 trials, and (b) the pipeline run on at least 1000 random targets of the same length returns no hit at the reporting threshold. Record both in the registry row.
9. **Era plausibility.** Each hypothesis names the software, platform and date that would have produced it. Implausible-but-cheap tests are allowed, are tagged `implausible`, and still count in `search_bits`.
10. **Pre-registration where labels exist.** For Phase 1 and any other labelled comparison, the feature list and rule families are committed before the labels are joined to the features. Later ideas are `exploratory`.
11. **Reproducibility.** Every reported number is regenerated by one documented command inside the pinned container. Jobs are deterministic, checkpointed and resumable. Hot loops are compiled code with a Python reference implementation that agrees on test vectors.
12. **Prior-art sweep.** At the start of each phase and before each gate report, search for new public results on that phase's targets and record what was found. Other groups are working on the same questions.
13. **Weakness or trapdoor: stop.** Any result suggesting an exploitable weakness, a recoverable secret, or deliberate manipulation is out of scope for autonomous follow-up. Stop, write a private note to the user, wait.
14. **Time boxes.** Each phase has a budget in section 6. At 100% of budget, write the gate report with what exists.

---

## 4. Repo layout and shared infrastructure

One repo, shared generator and solver libraries, one directory per phase.

```
curve-archaeology/
  CLAUDE.md                # operating rules (§3)
  data/params/             # primary-source constants + provenance (URL, sha256, section, date)
  data/candidates/         # frozen Phase 1 census (hashed)
  gens/                    # bit-exact PRNGs, each with test vectors (see below)
  solvers/                 # lattice, seed-sweep, default-stream, fingerprint, rewind
  x962/                    # X9.62 / FIPS 186 verifiable generation, prime + binary
  curves/                  # point counting, feature extraction (PARI via cypari)
  registry/hypotheses.yaml # every hypothesis, before and after running (§3 rule 2)
  reports/                 # one gate report per phase
  phases/p0 .. p7/
```

**Stack:** Python 3.12; `cypari` (PARI 2.15.4 with the `seadata` package — both verified in the pilot; SEA full counts cost ≈ 0.6/1.7/13.5/59 s at 192/256/384/521 bits); `fpylll` (verified working — it recovered all ten prime-seed states in the pilot); `gmpy2`; `numpy`; `pyyaml`; OpenJDK and `gmpy2`/GMP for cross-language reference vectors; a reference C toolchain for FreeLIP/LIP, early NTL, and period point-counting code. SageMath optional. A Docker image pins every version, including the `seadata` tables.

### gens/ — the generator library

The Rev. 1 list was too small and its adapter too weak. Replace it with a three-layer library (`gens/core/` state update, `gens/seeding/` seed→state, `gens/consumers/` big-integer assembly), because Java, CPython and GMP build a big integer from the *same* word stream in different byte/word orders, and the `(shift, width, words)` adapter cannot express that. The catalogue is 55 entries (pilot: 40 bit-exact ports pass against fetched vectors); the minimum set:

- **C library:** full `rand48` family (`lrand48`, `mrand48`, `nrand48`, `jrand48`, `erand48`, `drand48`, plus `seed48`/`lcong48`); `rand` as an explicit `(a, c, m, output)` table (ANSI/V7/SysV 15-bit; 4.3BSD 31-bit; MSVC; Borland; Watcom; FreeBSD/Apple 16807; glibc `rand_r`); `random()` in **three** distinct `srandom` initializations (4.3BSD/SunOS `1103515245`; libc5 `1103515145`; glibc 2 `16807 mod 2³¹−1`) × four table sizes — the single "glibc TYPE_3" of Rev. 1 was wrong for a 1997 NSA Unix box, which had the BSD form; Park–Miller minstd variants; RANDU; VAX MTH$RANDOM.
- **Bignum / CAS (era-critical):** FreeLIP/LIP `zrandom`/`zrandomb` (107-bit state; re-implemented from C) and early NTL; **PARI LCG** (`1000276549·x+12347 mod 2³¹`, default seed 1, stable through 2.3.x until 2011) and PARI xorgens (2.5.0+, 2011); **Maple ≤ 9.5 LCG** (`427419669081·s mod 999999999989`, default seed 1 — the top Certicom/Waterloo hypothesis); GMP in three eras (libc glue; 64-bit default LC; MT19937 with GMP seeding); MIRACL; LiDIA; Crypto++ `LC_RNG`; **GOST R 34.10-94 LCGs** (`19381 mod 2¹⁶`, `97781173 mod 2³²`).
- **Runtimes:** `java.util.Random` + `BigInteger(numBits, rnd)` + `nextBytes` + `SHA1PRNG`; CPython Wichmann–Hill and MT seeding + `getrandbits`; Delphi/Turbo Pascal; VB `Rnd`; MATLAB v4 and v5.
- **Classic / structured:** MT19937 in its 1998 `sgenrand` and 2002 `init_genrand`/`init_by_array` seedings; Marsaglia KISS/SWB/MWC; R250; TT800; ISAAC; and, as a "structured seeds only" registry class, FIPS 186 Appendix 3 (SHA-1 and DES `G`), ANSI X9.17/X9.31, RSAREF, BSAFE, SSLeay `md_rand`.
- **Default-unseeded-stream class:** the fixed stream a program gets when the author forgets to seed (SysV `drand48` `0x1234ABCD330E`, `rand`/`random`/PARI/Maple/GMP-LC seed 1, the GMP-MT 5489 table, MIRACL defaults, VB `0x50000`, Delphi 0, the MT reference 4357/5489). A cheap, separate scan.

Each entry: exact recurrence and constants, state size, output function, seeding idioms, era/issuer plausibility, and a reference from which bit-exact vectors are produced. Operating rule 4: two independent vectors per generator before use.

### solvers/ — expanded

- `fingerprint.py`: the sliding scan generalized — per target, slide bit offsets and test every (generator, slicing, consumer) triple for consecutive-output consistency and fixed-bit signatures (e.g. all-zero top bits).
- `lcg_lattice.py`: truncated-LCG state recovery `(a, c, m, shift, width)` from `k` consecutive outputs, with an unknown-window sweep, the trivial hidden-bit enumeration path, composite generators (Wichmann–Hill, MWC), Maple's base-10¹² chain, and a two-word test for an unknown increment.
- `seed_sweep.py` **(new, required):** for large-state generators that no lattice can touch (`random()` TYPE_1–4, R250, TT800, MT19937, Knuth, MIRACL, xorgens, MATLAB 5), enumerate seeding-form states × stream positions against a hash table of target windows built for all layouts. Without this, Rev. 1 silently could not see any of these generators.
- `default_stream.py` **(new):** position scan of every documented unseeded stream.
- `rewind.py`: step an LCG back to seeding-form states (e.g. low 16 bits `0x330E` for `srand48`) and decode as timestamps under transforms (identity, ÷2, ÷k, ± timezone, Java scramble + ms, 1/256-s clocks, `seed48` literals, distance from the default state).
- `bm_profile.py` **(new):** Berlekamp–Massey linear-complexity profile and a mod-2³² additive-lag test, for LFSR/GFSR-type generators and concatenated sibling targets.
- `zr_state.py` **(new, from the pilot):** FreeLIP `zrandom` state-complete recovery by CVP (Babai on an LLL-reduced basis) when middle limbs of `x = x_raw mod p` are known up to a borrow bit — the method behind the Phase 2 base-point negatives.

---

## 5. The phases

Phase 0 is mandatory and blocks everything. Phases 1, 2, 5 and 6 then run in parallel; Phase 3 and Phase 4-DualEC reuse Phase 2/3 tooling; Phase 7 prepares the write-up once any gate passes. Each phase ends at a gate requiring user sign-off.

## Phase 0: environment and ground truth

Nothing downstream is trusted until the published results reproduce bit-exactly from independently written code, and until every period generator reproduces its original test vectors.

**Reproduce the published result**
- [ ] Build the pinned container; confirm `cypari`/PARI with `seadata`, `fpylll`, and SEA work at 521 bits. (Pilot: `cypari` 2.5.7 bundling PARI 2.15.4, with the `seadata` package, reproduces all orders; `ellsea` full counts cost ≈ 0.6/1.7/13.5/59 s at 192/256/384/521 bits on 4 cores. See Appendix A for the install.)
- [ ] Re-derive all ten prime seeds and four binary seeds from `srand48`+`drand48`/`lrand48` with independently written code (done in the pilot; keep as a regression test). Regenerate the six FreeLIP base points from `zrandom` (done).
- [ ] Re-derive one prime seed's `srand48` state from its 20 bytes alone, with a truncated-LCG lattice solver, without using the timestamp (pilot: `fpylll` status and the P-256 recovery are in Appendix A). This validates `solvers/lcg_lattice.py`.

**Fetch and pin every primary source** (`data/params/`, with URL, SHA-256, section, date; cross-checked against a second source). The review already fetched and hashed the core set — reuse these hashes as the pinned manifest:

| Document | SHA-256 (first 16) | Note |
| --- | --- | --- |
| FIPS 186-2 | `7384ae9ddbf8e36e` | Appendix 6: all 100 curve values |
| ANSI X9.62 draft 1998-09-20 | `6cb44495bf816008` | the only non-paywalled X9.62; procedure text in Appendix B |
| FIPS 186 (1994) / 186-1 | `1ee5bf0d397dbd51` / `b2701fb61cb7fd3e` | DSA example seeds |
| SP 800-186 | `53c7cf3340528aaa` | current, names Gaussian normal basis |
| SEC 2 v1.0 / v2.0 | `d1b16728ad83888f` / `87b8f3703364ed5b` | SECG seeds, MinghuaQu markers |
| NIST "Recommended Elliptic Curves" (1999-07) | `5920a161d9706d39` | standalone; PDF metadata (DVILASER/PS, Distiller 3.01) is itself a provenance datum |
| SP 800-90A (2012) | (fetch) | Dual_EC P, Q — pin before Phase 4-DualEC |
| J08nY/std-curves | git HEAD pinned | machine-readable second source for nist/x962/secg/brainpool/anssi/gost/oscca |

- [ ] Add the 1997-11-17 and (if recoverable) earlier X9.62 working drafts; their example-curve lists are the archive track's primary evidence (Phase 1 Step 6).

**Implement and test the two generation procedures**
- [ ] Prime: `seed → c → b` with `a = −3`, `b² ≡ −27/c`, root = `(−27/c)^((p+1)/4)` for `p ≡ 3 mod 4`. Test against all ten published `(seed, b)`; pilot: all ten match. Record which root each curve published (Appendix A: P-224 is the only `p ≡ 1 mod 4` curve; its `b` is the negative of the Tonelli–Shanks root with non-residue 11).
- [ ] Binary: `seed → b` via SHA-1, read as a **Gaussian normal-basis** coefficient vector, then convert to polynomial basis with the field polynomial. Test against all five B-curves. **Pilot/review result: B-163's seed regenerates its published normal-basis `b` bit-for-bit (`6 645f3cac…d9fb`) and the matrix conversion gives the published polynomial `b`. The B-163 seed is therefore a genuine seed for its curve; an erratum is excluded.** This narrows Phase 2's B-163 task to the seed's own origin.
- [ ] Settle the hash-length formula: `s = ⌊(l−1)/160⌋`, `w` = the `(l−160s)` rightmost bits of `H` with the top bit cleared (X9.62 A.3.3.2 / FIPS 186-2 App 6.4). A competing public claim holds the 1997 and 1998 drafts differ (one reproduces all 21 `b`, the other only some); test both variants and record which the published curves use.

**Build and verify the generator library** (`gens/`; see §4 for the catalogue)
- [ ] Each generator ships with test vectors from its original source or a reference C build; an unverified generator invalidates every negative it touches (operating rule 4). Re-implement `lrand48` and FreeLIP `zrandom` from their C sources, not from the published Python, and check against compiled C output.

**Benchmark** (fixes the Phase 1 budget)
- [ ] `ellsea` early-abort and full-count timing at 192–521 bits (pilot numbers in Appendix A). The full six-run census (≈21,750 candidates) cost about 1.5 CPU-hours on 4 cores — two orders of magnitude below Rev. 1's "1 CPU-day on 32 cores". The real cost is engineering (period-software builds), not CPU.

**Gate 0:** every regression test passes; the generator library reproduces its vectors; `reports/phase0.md` holds the benchmark table and the pinned-source manifest.

---

## Phase 1: the unexplained candidate filter

**Question.** After the known criteria (prime order, MOV condition, `bitlen(n) ≤ bitlen(p)`), 21 candidates in the four multi-candidate prime runs were acceptable. The generator kept 10 and passed over 11. What decided?

**What the data already says** (verified in the pilot, Appendix A):

| Run | Acceptable candidates in stream order (published in bold) |
| --- | --- |
| prime239, 1997-05-15 | 36, 1562, **2185** (v1), **2320** (v2), 2491, 2682, 2863, **3048** (v3) |
| prime192, 1997-05-18 | **139** (P-192), 2198, **5228** (v3), 5405, **6013** (v2) |
| P-521, 1997-08-08 | **1136** |
| P-256, 1997-08-16 | 876, **1842** |
| P-384, 1997-08-30 | **2688** |
| P-224, 1998-04-03 | 777, 1485, 5736, **7026** |

- Every run ends at its last published candidate: one-curve runs stop at the first kept candidate, three-curve runs at the third.
- The counts fit a sequential scan in which each acceptable candidate is kept with probability about 1/2, independently (10 of 21; skips before the quota are 1, 3, 0, 0 for the one-curve runs and 5, 2 for the three-curve runs, against expectations of 1 and 3).
- prime192v2 and v3 are numbered against stream order (v3 = 5228, v2 = 6013).
- Already excluded by others: rho, transfer, anomalous, CM discriminant size and twist security (Anthropic's table); regular RNG-consumption gaps (Valsorda). Excluded in the pilot: see Appendix A.

**Capacity.** The labels carry log2 C(21,10) = 18.4 bits. A rule from a family of N candidates that reproduces all 21 labels has margin 18.4 − log2 N. Consequences:

- Phase 1 cannot reach Tier A or B from the labels alone. A separating rule is a Tier C lead unless a mechanism supplies further bits (step 5) or new labels confirm it (step 2).
- The confirmatory budget is N ≤ 256 global rules (margin ≥ 10.4 bits). The pilot has already spent about 64. Rules with per-run parameters are inadmissible: per-run capacity is 5.8 + 3.3 + 1 + 2 = 12.1 bits before paying for the parameters.
- A continuous feature counts as 2 rules (only the split at the 10/11 boundary can match, in either direction); a k-class feature counts as 2^(k−1) − 1; a two-feature Boolean search over F features counts as 10·F(F−1)/2, so it is only admissible for F ≤ 7.

### Step 1: freeze the dataset
- [ ] Enumerate all six prime runs to max(8000, 1.2 × last published index). Store every candidate with: seed, c, whether b exists, both roots, early-abort outcome, and for full counts n, t, primality, bit lengths, MOV degree to 1023, the twist order.
- [ ] Confirm the 21 acceptable candidates and the list of prime-order candidates rejected only by the bit-length rule. Any disagreement with Valsorda's list is a finding.
- [ ] Decide the exact form of the length rule. `bitlen(n) ≤ bitlen(p)` and "n fits in the octets of p" differ only for P-521, where a 522-bit n still fits in 66 octets: check every prime-order P-521 candidate before 1136.
- [ ] Freeze as `data/candidates/*.json`, hash it, record the hash in the registry. No Phase 1 hypothesis is evaluated before the freeze.

### Step 2: get more labels
The four binary runs (B-233 candidate 155, B-283 32, B-409 60, B-571 73) used the same seed generator eleven days after the P-224 run.
- [ ] Enumerate each binary run to 1.2 × its published index; count points; mark candidates whose order is 2 × prime and that pass the binary analogues of the known criteria.
- [ ] Record acceptable-but-skipped binary candidates. They are new labels for any rule expressible on binary curves, and their absence is evidence too: if all four published binary candidates are the first acceptable ones, a 1/2 filter is disfavoured there at 2^−4.

### Step 3: pre-registered families, in priority order
Write each family to `registry/phase1_families.yaml` with its rule count before running it. Stop when the budget is spent.

| # | Family | Rules | Status |
| --- | --- | --- | --- |
| F1 | Era-computable auxiliary factorizations: is n−1, n+1, the twist order or t²−4p fully factored by bounded effort (rho, small ECM) | 8 | Pilot: negative |
| F2 | Residues of n and t modulo 3, 4, 8 | 26 | Pilot: negative. Lead L1: all published have t mod 8 ∈ {5, 7}; 4 skipped also do |
| F3 | Quadratic characters of x³−3x+b at x = ±1, ±2, ±3; root conventions of b | 9 | Pilot: negative |
| F4 | Elkies/Atkin type of ℓ ≤ 23 for the curve | 8 | Pilot: negative. Lead L2: ℓ = 11 |
| F5 | RNG-consumption walks: after event E the program swallows m more 20-byte blocks, E ∈ {b exists, b missing}, m ≤ 3 | 6 | Pilot: negative |
| F6 | SEA cost proxies: least L with ∏ Elkies ℓ ≤ L exceeding 4√p; number of Atkin primes below it; size of the match-and-sort set | 6 | Open |
| F7 | 2-power and 3-power torsion structure used by 1990s SEA code: t mod 16, t mod 9, splitting type of the 4- and 8-division polynomials, isogeny-volcano depth at 2 and 3 | 16 | Open |
| F8 | Chunked parallel search: W workers on blocks of L candidates, L ∈ {500, 1000, 2000, 2500, 3000, 5000}, W ∈ {2, 3, 4, 8, 16}, either "each worker stops at its first hit" or "first k hits by offset"; one (L, rule) for all runs | 60 | Open. Needs the candidates beyond the last published index |
| F9 | Properties of the seed or of SHA-1 output rather than of the curve: byte and sign patterns of the seed, top and bottom bits of c | 16 | Open |
| F10 | Second-pass checks an X9.62-era validator would run on the finished parameters: base-point search succeeding within j tries for the FreeLIP recipe with seed 20000+, cofactor and order re-verification with a single random x | 12 | Open |

Reserve: 89 rules for hypotheses raised by the mechanism and archive tracks.

Adopt **DiSSECT's 22 traits** (Sedláček et al.) as the pre-computed baseline for F1–F4/F7 rather than re-deriving them, and its X9.62 simulation (5M seeds/size) as the null distribution; cite its published findings. Note that for the NIST filter the relevant features are of the *curve*, but one feature family generalizes to the national targets and is cheap here too: the **prime-structure group** — factor chains of `p−1` and `p+1` (recursive half-size factors, à la the GOST/Shawe-Taylor/Maurer generators), safe-prime test, residues mod 3/4/8/24, trailing-bit runs. For the NIST runs `p` is fixed per run so this is constant, but the group is carried into Phase 5 (it is how the pilot's CryptoPro-C result was found) and freezes here for uniformity.

### Step 4: statistical protocol
- [ ] Evaluate each family once, on the frozen data, with code committed before the run.
- [ ] Report for every rule the full contingency table, not only separators.
- [ ] A separator's reported margin is 18.4 − log2(rules evaluated so far, all families). Anything found outside a registered family is `exploratory`.
- [ ] Fit the baseline too: independent keep-probability q per acceptable candidate with quota stopping. Report the likelihood ratio of each deterministic rule against it. If nothing separates, the deliverable is the upper bound on what a deterministic rule of each family could be, and the statement that the data are consistent with q = 1/2.

### Step 5: mechanism track (where extra bits can come from)
A mechanism earns evidence beyond the labels only if it reproduces something else bit-exactly. Pilot caution: the leading benign mechanism — the X9.62 A.3.1 random-point check failing on a separate RNG (`G = h·R`; `nG ≠ O` ⇒ "wrong order") — was tested across 2,952 parameterizations (generator, slicing, verify-model) and **none separates the 21 labels** (best 19/21). So even the natural mechanism does not trivially explain the filter; the bar is a bit-exact second artefact, not a plausible story.
- [ ] Rebuild period point-counting code on FreeLIP (the base points prove FreeLIP was in the toolchain) and run it on all 21 candidates. Sources and candidate programs: Appendix B. Record every candidate on which period code fails, aborts or returns a wrong order.
- [ ] Model the natural 50% failure modes and test each for a deterministic signature: trace sign fixed by a single random point without a twist branch; order verification with one random x that may lie on the twist; eigenvalue sign errors for a class of Elkies primes; Atkin-only curves abandoned.
- [ ] If a mechanism consumes FreeLIP `zrandom` output, try to tie it to the six known base-point seeds (20000, 20420, 20507, 20509, 20512, 20517): the same stream that passes or fails a candidate would then also have to produce the published base point. That link is worth up to 192 bits per curve and is the only route to Tier A in this phase.
- [ ] Explain the length rule with the same mechanism if possible. Two unexplained behaviours with one cause is the target.

### Step 6: archive track (may answer the question outright)
- [ ] Collect every draft of ANSI X9.62 and IEEE P1363 from 1997 to 1999 and every X9F1 or P1363 mailing-list message that lists example curves. A draft that lists more curves from the same streams turns "skipped by the program" into "dropped by an editor".
- [ ] Collect NIST and NSA statements on selection criteria, including the July 1999 curve recommendation and FOIA releases.
- [ ] List people to ask. The user makes all contact.

**Benign hypotheses to rule in or out explicitly:** (1) a probabilistic step that fails half the time; (2) point-counting failure or timeout in period code; (3) parallel workers on blocks of the candidate list; (4) an editor choosing from a longer list; (5) a requirement nobody has stated.

**Gate 1.** `reports/phase1.md`: the frozen dataset and its hash; each family with rule count and outcome; the best rule with its margin and tier; binary-run labels; mechanism and archive findings; the total rule count spent.

---

## Phase 2: B-163, the unexplained NIST base points, and the halved clock

Reuses all Phase 0 infrastructure. The base points carry no security relevance (every generator of a prime-order group is equivalent for ECDLP); they are pursued for completeness and because each is a fresh, labelled test of the generator library.

### 2a. B-163 seed
The seed is `85E25BFE 5C86226C DB12016F 7553F9D0 E693A268`.
- [ ] Settled in Phase 0: the seed regenerates the published `b` (normal basis, then converted), so it is a genuine seed and the task is its own origin, not an erratum.
- [ ] Record the known negatives before searching (operating rule 2, prior-art import): it is **not** five 31-bit `lrand48` words — the top bits of its five 32-bit words are `1,0,1,0,1`, where the four published binary seeds are all `0`; public work reports the `drand48` family (all shifts/windows), FreeLIP limbs, and the glibc/BSD/SysV/MSVC `rand`/`random` generators seeded with the 1997–98 timestamps and their halves all negative.
- [ ] New ground to cover: the full generator library (§4) under the seed-sweep solver, including the large-state generators the old scanner could not see; the "default unseeded stream" class; two-source mixes; `jrand48`/`nrand48` with an explicit `Xsubi`; and byte/word assembly orders that the Java/CPython/GMP consumers impose. Budget and report the total `search_bits`.
- [ ] Decode any recovered `srand48`-form state under the clock transforms (identity, ÷2, ÷k, timezone offsets, the 1997–98 window).
- [ ] Test whether B-163 belongs to the same stream as B-233…B-571, at an index before 155 or after 73 in any of their runs (cheap; a few hundred draws).

### 2b. Base points of P-224, P-256, P-384, P-521 and the NIST binary curves
The generation path is fixed by X9.62 A.3.1 + D.3.1 (verified text, Appendix B): a random `x` is drawn, `α = x³+ax+b` is formed, a square root is attempted, and on failure another `x` is drawn; then `G = h·R`. Consequences the search must respect:
- Only `x` is random; `y` is whatever the root algorithm returns. For `p ≡ 1 mod 4` (P-224) the draft's root algorithm is itself **randomized** (Lucas sequences with a random seed), so P-224 consumes a variable, data-dependent number of random draws — a materially harder target.
- For cofactor `h > 1` (all binary curves) the published `G = h·R`, so the raw random value is `x(R)` for one of the `h` division points of `G`, **not** `x(G)`. The search must test every preimage of `G` under multiplication by `h`, including points outside the prime-order subgroup, in both the polynomial and the normal/Gaussian basis.

Pilot result (lead, computed): under the state-complete FreeLIP test — 26-bit limbs, `x = (limbs) mod p`, `L ∈ {⌈bits/26⌉, ⌈bits/26⌉+1}`, both limb orders, with planted-target controls recovering 60/60 and 0 false positives in 1000+ null trials — **no `zrandom` state reproduces `x(G)` for P-224, P-256, P-384 or P-521.** This rules out the exact May-1997 FreeLIP recipe for the four later points (it does not cover other radices, the `y`-draw, `G = k·R`, or truncation instead of reduction).

- [ ] Extend the search: FreeLIP at other build radices (30-, 62-bit limbs), the `h·R` preimage structure, and the exact X9.62 draw order (how many `zrandom` calls a `D.3.1` attempt consumes, including the `a`-is-arbitrary and MR-primality draws). A public lead holds that FreeLIP `zprobprime`/`zprime` on `p` or `n` consumes exactly the seven discarded single-limb draws seen on the May-1997 curves; test that call-level model and whether it also predicts the four later points.
- [ ] Record the `y`-sign evidence (lead, computed): for the six May-1997 FreeLIP points the published `y` is the canonical root `α^((p+1)/4)` **iff the FreeLIP seed is even** (6/6; chance 1/32); for P-256/P-384/P-521 the published `y` is the canonical root (3/3). A model that explains the sign is worth bits.
- [ ] Try the untested period libraries named by the archive track (LiDIA, Magma, SIMATH, KANT, ZEN/BigNum) and the seed-as-counter/PID reading of the FreeLIP seeds (20000, 20420, 20507, 20509, 20512, 20517 — ordered by curve *name*, not by stream block, so generated in a later pass, one invocation per curve).
- [ ] Binary base points: note the public observation that the K-163 half-point (`2R = G`) has `x(R) = 23E21D60 19E1211F 6BD47EC1 80256E97`, only 126 of 163 bits (≈37 leading zero bits, chance ≈ 2⁻³⁶) — the binary analogue of the secp256k1 structure, and evidence that the K-curve points came through Certicom, not NSA. Fold into Phase 3.

### 2c. The halved binary clock
The four binary `srand48` arguments (446413329, 446413432, 446413509, 446413564) read directly as 1984-02-23; doubled they are 1998-04-17 15:24–15:32 UTC (Friday, 11:24–11:32 US Eastern), exactly 14 days after the P-224 run, with inter-run gaps of 206/154/110 s.
- [ ] Nobody has tested the alternatives. Test `srand48(time)` with `time` read under a halved clock vs `srand48(time>>1)` vs `seed48`/`lcong48` packings vs a mis-set 1984 workstation clock. The acceptance test is a second independent artefact from the same session (a binary base point, or B-163) decoding consistently.

**Gate 2:** for each target, an explanation clearing the bar or an enumerated negative space with its `search_bits`.

---

## Phase 3: SECG / secp256k1 base points

secp256k1 is rigid apart from `G`. The widely circulated observation is that `G/2` has an `x`-coordinate with many leading zero bytes, suggesting `G` was produced by doubling (or cofactor-multiplying) a structured point. **This phase is largely scooped** and should be scoped accordingly:

- A public write-up (October 2026) reports that 25 of 69 standard SECG/X9.62 curves have a "hidden" structured point `R` with `h·R = G` (or `2R = G`), 18 of them newly observed; the shared structure is a "stored value" (a short number or a reused string, sometimes the base point of an *earlier* curve) with the last hex digit bumped until valid, then multiplied by the cofactor even where `h = 1`. The pilot reproduced the core independently: the `k1` family shares the 38-hex-digit half-point core `…3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6_` across secp160k1/192k1/224k1/256k1 (`x(G/2)` of secp256k1 = `3b78ce563f89a0ed…9c63`, 166 bits), with "gap to previous valid `x`" 1/5/1/2 — the last-digit-bump signature. Brainpool and SM2 `G/2` show no such structure (pilot survey).
- What is **not** explained, and is the actual target: the stored strings themselves (the shared 38-hex-digit core across the k1 family; the `…cabe…` strings; the 32-digit values) and the last-digit rule.

- [ ] Reproduce the public census with independent code: for every SEC 2 curve (k1 and r1, 112–521 bits, prime and binary) compute every preimage of `G` under `[h]` and under `[k]` for small `k`, including torsion translates (the naive `x(k⁻¹G mod n)` misses these). Score by leading zeros, Hamming weight, ASCII decodability, and match against digits of π, e, √2. Output a ranked table. Confirm or refute each published claim and report the exact bit length of each structured coordinate.
- [ ] Attack the residue: fingerprint each stored string with the full generator library plus SHA-1/SHA-256 of counters, short strings, and small integers; account for bit length (a value that is not 160 or 256 bits wide rules out raw hash output and points to truncation or reduction). Test the "smallest valid `x ≥ structured_start`" hypothesis under a defined `y`-sign rule.
- [ ] Decode the SEC 2 seed ASCII (the published seeds embed `MinghuaQu`; tabulate the residual non-ASCII bytes of each seed as fingerprint targets), and note the `MinghuaQu` marker shared with the X9.62 binary example seeds and the Certicom ECC-challenge seeds — cross-target evidence for a single Certicom tool.
- [ ] Era-appropriate tooling (SEC 2 v1.0 is 2000-09-20): Certicom/Waterloo software — **Maple ≤ 9.5 is a 40-bit LCG with default seed 1** (lead's gens catalogue), the top hypothesis; also MIRACL, Crypto++, Security Builder.

**Gate 3:** an explanation of the stored strings clearing the bar, or the ranked structure table plus an enumerated negative space. The `G/2` observation itself is already confirmed — do not relitigate it.

---

## Phase 4-DualEC: the Dual_EC_DRBG point Q

The one remaining target with real security stakes. The algorithm is withdrawn (SP 800-90A Rev. 1, 2015) but persists in legacy and embedded products. `P` is the P-256/384/521 generator `G`; only `Q` is unexplained. Primary sources (the 2004 Johnson→Kelsey email released in 2014; Shumow–Ferguson 2007; Bernstein–Lange–Niederhagen) establish that `Q` is the public key `d·P` for a secret scalar `d`, and that the verifiable "canonical-`G`" construction was rejected in standardization. No one has investigated `Q`'s provenance by PRNG archaeology.

**Three distinguishable outcomes:**
1. **Exoneration** — `x(Q)` is reproduced by a verifiable nothing-up-my-sleeve *random-point* derivation (random `x`, solve for `y`, as in the FreeLIP recipe). By ECDLP hardness this precludes a known `d`.
2. **Recoverable trapdoor** — `d` (or `e = d⁻¹`, with `P = e·Q`) is reproduced from a weak or seedable PRNG. This is a live key-recovery.
3. **Inconclusive** — `d` came from a strong RNG; no enumeration can confirm or exclude it. This is the *expected* outcome.

**Critical asymmetry:** random-looking coordinates do **not** exonerate. `Q = d·P` for a random `d` is observationally identical to a random point. Only outcome 1 or 2 is informative; a negative is outcome 3.

**Cost:** one scalar multiplication per candidate `d` (microseconds), reusing the Phase 2/3 fingerprint tooling. Plausible weak-PRNG seed spaces (FreeLIP small integers ≈ 2²⁰, Unix-time windows ≈ 2²⁶, 32-bit counters 2³²) are all tractable in hours on one machine.

- [ ] Pin `P` and `Q` for P-256/384/521 from SP 800-90A Appendix A.1 into `data/params/` (the review captured the exact coordinates).
- [ ] Run the random-point fingerprint on `x(Q)` (outcome 1) and the scalar-recovery sweep for `d` and `e` against the generator library with era-appropriate seeds (outcome 2), 2002–2005 NSA/NIST tooling.
- [ ] Report the enumerated seed space as `search_bits` whatever the result.

**Disclosure gate (rule 13, strengthened for this phase):** a positive outcome-2 result is a usable trapdoor scalar. Do **not** commit `d`, `e`, or any seed to the repository; do **not** publish; stop autonomous work and write a private note to the user naming the recommended coordinated-disclosure contacts (the bounty organizer, a CERT, affected legacy vendors). An outcome-1 exoneration may be reported normally. This phase runs only to the point where provenance is decided.

**Gate 4-DualEC:** the three-outcome analysis with its seed-space sizes, `Q` pinned with source, and either an exoneration, a sealed private note (outcome 2), or a bounded negative space (outcome 3).

---

## Phase 5: FRP256v1, SM2, and the GOST curves

Wide hypothesis space, highest false-positive risk — the evidence standard (§2) and controls (rule 8) carry the weight here. The pilot already produced one genuine result on this family; it is both an encouragement and a warning (it needs independent reproduction before any claim). Time-box: 2 weeks.

**Pilot result to reproduce first (lead, computed; needs independent confirmation):** the random-looking 256-bit field prime of the GOST `CryptoPro-C` / XchB parameter set, `p = 9B9F605F…022D759B`, is the exact output of the **GOST R 34.10-94 Procedure A′ prime generator** (a 32-bit LCG, `x ← 97781173·x + c mod 2³²`) with `x0 = 3`, `c = 0x123`, recovered by factoring the `p−1 → 128 → 64 → 32`-bit prime chain and stepping the LCG backwards; the generator was validated bit-exactly on all eight GOST R 34.10-94 parameter sets in RFC 4357. This demonstrates the whole method on a national standard. (Caveat: `(x0, c) = (3, 0x123)` is itself not fully explained — `x0 = 2` already gives a `p ≡ 3 mod 4` prime — so this is a Tier-B/C result pending the choice's explanation.)

**FRP256v1 (ANSSI, 2011)**
- [ ] Pin from the Journal Officiel (JORF n°0241, 2011-10-16). The pilot reconstructed the notice's SHA-256/SHA-1 fingerprints from the 227-byte explicit-`ECParameters` DER, proving bit-level provenance and that **the distributed file carried no seed**.
- [ ] The notice documents no procedure (no *aléatoire/germe/graine/hachage*). Test the ANSSI/Flori-style `b = gⁿ` construction and structured-seed FIPS-style hashing; era tooling 2010–11 (PARI 2.3 LCG or 2.5 xorgens, Magma, Sage, OpenSSL safe-prime). Record pilot features: `(p−1)/2` is prime (safe prime), `p ≡ 3 mod 2¹⁰`, twist security 2⁷⁹ — all exploratory, post hoc.

**SM2 (OSCCA, 2010)**
- [ ] Pin the recommended curve and the GM/T 0003.5 example curves from the OSCCA PDFs (the review has them). GB/T 32918.1 Annex D **does** define verifiable random generation (`r = H256(SEED) mod p`, then `r·b² ≡ a³`; or `b = r` directly), but **no SEED is published** for the recommended curve.
- [ ] Test structured seeds only (ASCII tied to the issuing body and year, counters, constant digits) under SM3 and SHA-256; `r = a³/b² mod p = 7282C84D…D5BEE4D7`. Hash preimages of unstructured seeds are infeasible — do not attempt them.

**GOST R 34.10 (CryptoPro / TC26)**
- [ ] The TC26 twisted-Edwards curves' `seed → d` relation (`d = Streebog-512(seed) mod p`) is verified (pilot). The 96-byte seeds are themselves unexplained random strings, published years after the curves — the same structure as the NIST seed problem; fingerprint them.
- [ ] The CryptoPro Weierstrass sets resist a hash origin (`b = 166` for set A, `b = 32858` for set C are too small to be hash outputs); set A's `p = 2²⁵⁶ − 617` is the 5th prime below 2²⁵⁶ and `b = 166` is the smallest `b` giving prime order (DiSSECT). Treat these as structured-choice, not PRNG, targets. CryptoPro-B and the 2001 test curve are "smallest-`c`" CM constructions (`D = −619, −915`; pilot).
- [ ] Add the **selection sub-problems** as enumerable targets, the national analogue of Phase 1: why `x0 = 3` for the CryptoPro-C prime when `x0 = 2` also gives a `p ≡ 3 mod 4` prime; why `b = 32858` (the 80th admissible `b`); why `p = 2²⁵⁶ − 617` over `−189`/`−357`; why `x = 3` for the 512-paramSetA base point when `x = 1` is valid. Reuse the Phase 1 permutation-test machinery; DiSSECT already published a negative on the 45 skipped `b` values as a baseline.
- [ ] Chinese example-curve note: the SM2 Annex C `F_{2^257}` example *violates* Annex D's own rule (bit 256 of `b` is 0 where the rule forces 1), and `wapip192v1` (WAPI, public by 2006-01-18) equals the SM2 `Fp-192` example — so "Annex D was not used" is the null hypothesis for the Chinese curves, and the example curves are extra siblings.
- [ ] Add the RFC 4357 `(x0, c, d)` triples for every CryptoPro 34.10-94 set — fourteen unexplained 32-bit-aligned values from one vendor and era, cheap to sweep — as sibling targets.

**Shared tooling**
- [ ] Run the generator-library fingerprint and the lattice solver on `b` and on `G`'s coordinates in both endiannesses; run the `G·k⁻¹` structure survey (Phase 3); run the Phase 1 feature extraction (twist security, CM discriminant, embedding degree) on every curve.
- [ ] Reuse DiSSECT (Sedláček et al., AFRICACRYPT 2022) as a second parameter source (its curve DB = J08nY/std-curves) and as prior art: its "simulated vs standard" trait study already covers these families and reports no separating trait, but it does **not** cover PRNG/seed provenance or `p−1` internal structure — which is exactly where the pilot's GOST result came from.

**Gate 5:** per curve, a reproducible derivation clearing the bar (with controls) or a documented negative space. A negative here is the expected outcome.

---

## Phase 6: the Kuznyechik/Streebog S-box residue, and shuffle archaeology

Lowest-capacity target in the plan; kept because the method (fingerprint a permutation against a PRNG-driven shuffle) is distinct and reusable, and because some S-box *sets* are higher-capacity than the single Kuznyechik box. Biryukov–Perrin–Udovenko (2016) and Perrin (2019) already show the S-box π is a highly structured TKlog; this phase targets the arbitrary choices inside that decomposition, not a rediscovery. Time-box: 2 weeks.

**Capacity reality (pilot, computed):** π was reproduced bit-exactly from the published TKlog parameters. The residual free choice is about **58 bits before** the differential-uniformity/linearity filter and **≈50 bits after** — below the 64-bit margin. So **π can never reach Tier A under the standard evidence rule**; the honest deliverable for π is a quantified residue, not a discovery. (The pilot also confirmed π is not a shuffle output, and recorded exploratory new structure in the "arbitrary" components, e.g. `Im(Λ)` is the canonical coordinate complement of the subfield — register as exploratory.)

**6a — π accounting (2–3 days):**
- [ ] Reproduce the TKlog, TU and log decompositions; publish the entropy table per component (field choice, `κ`/`Λ`, the permutation `s`). Confirm π from RFC 7801 / RFC 6986.
- [ ] Run only cheap structured-enumeration tests and at most one joint-stream PRNG test. Gate text: "quantified residue of `X` bits"; no hit is possible under the 64-bit rule.

**6b — shuffle archaeology of S-box sets (higher capacity):** a Fisher–Yates shuffle driven by an LCG leaves a recoverable signature (the swap-index sequence is low-entropy per step). Targets in priority order, each with its own capacity and controls:
- [ ] GOST 28147-89 S-box sets where a PRNG origin is plausible: CryptoPro-A and the R 34.11-94 set (raw), the two Test sets (derangement filter), CryptoPro B/C/D and tc26 param-Z (optimality filter with candidate skipping). Use the generator library; detect shuffles by the swap-index low-bit signature.
- [ ] The original Whirlpool-0 / Anubis-0 / Khazad-0 boxes; Kalyna (only if generator code is obtained); Skipjack F-table (fingerprints only — classified origin, low hit probability, but a clean bounded negative).

**6c — TC26 siblings:** the Streebog MDS matrix (512 bits) and Kuznyechik LFSR coefficients; verify the designers' published recipe for the Streebog round constants `Cᵢ` as a regression test.

Out of scope (documented, hand-crafted, or infeasible): SM4 S-box internal structure, DES S-boxes, CMEA, COMP128, DSAA, and SHA-preimage search on unstructured seeds. SM4 `FK`/`CK` and SM3 `IV`/`T` move to Phase 5 as joint targets with SM2.

**Gate 6:** explained components, or a quantified residue of unexplained choice per component, in bits. Any claim of a *weakness* is out of scope — flag to the user and stop (rule 13).

---

## Phase 7: write-up and disclosure

The user decides what is published. The agent only prepares material and never contacts anyone.

- [ ] For each positive finding: a standalone reproduction script under 100 lines, printing every target value, in the style of the Anthropic post.
- [ ] For each negative finding: the hypothesis table and the total `search_bits` covered, with the controls that validate it (rule 8).
- [ ] **Novelty audit** before any claim of newness: re-run the prior-art sweep (rule 12) and diff against the public work catalogued in Appendix D. Much of Phases 2 and 3 is already partly public.
- [ ] If anything bears on curve or product security (above all a Phase 4-DualEC outcome-2 result), the disclosure gate (rule 13) applies: stop, private note to the user, named coordinated-disclosure contacts, independent reproduction before any publication. Suggested first contacts for the NIST questions: the bounty organizer and the Anthropic authors; the user makes all contact.
- [ ] Archive/FOIA track (preparation only; the user decides any outreach): the 1996–1998 X9.62 and IEEE P1363 drafts, the X9F1 and P1363 mailing-list archives, and FOIA requests to NIST/NSA. This track could answer Phase 1 outright (an editor's longer curve list would turn "skipped by the program" into "dropped by a human").

---

## 6. Sequencing, gates, compute budget

Phase 0 blocks everything. Phases 1, 2, 5 and 6 can then run in parallel; Phase 3 reuses the `G·k⁻¹` survey; Phase 4-DualEC reuses the Phase 2/3 scalar-mult and fingerprint tooling; Phase 5 reuses the Phase 1 feature extractor and the Phase 3 survey.

| Phase | Depends on | Dominant cost | Budget (revised from the pilot) |
| --- | --- | --- | --- |
| 0 | — | Building and verifying generators and period software | 3–5 days (engineering, not CPU) |
| 1 | 0 | Census (done), then the mechanism and archive tracks | Census ≈ 1.5 CPU-h on 4 cores (**measured**); the work is analysis + archive, not compute |
| 2 | 0 | Lattice/seed sweeps; FreeLIP sweeps | Hours to 1 CPU-day |
| 3 | 0, 2 (survey) | Scalar mults for small `k` across SEC 2 | Minutes; residue analysis dominates |
| 4-DualEC | 0, 2/3 (tooling) | Scalar mults over the seed space | Hours to ≈ 1 CPU-day; **strict disclosure gate** |
| 5 | 0, 1, 3 | Fingerprinting; feature extraction; `p−1` chains | Time-boxed to 2 weeks |
| 6 | 0 | Shuffle search over S-box sets | Time-boxed to 2 weeks |
| 7 (write-up) | any gate passed | Writing | — |

**Budget correction.** Rev. 1's "1 CPU-day on 32 cores" for Phase 1 overstated the cost by ~2 orders of magnitude: the full six-run census (≈21,750 candidates) was 1.5 CPU-hours on 4 cores (pilot, Appendix A). Early-abort SEA is sound here (0 false aborts on the validation sample, Appendix A). The real cost across the plan is engineering — building and bit-exactly validating the generator library and the period point-counting code — not CPU. Every job is embarrassingly parallel and checkpointable; GCP spot instances (`c3-highcpu`) are fine but modest. Each gate needs user sign-off before the next phase in its chain starts.

**Evidence-budget ledger.** `registry/budget.yaml` tracks cumulative `search_bits` per target, so margins stay honest as hypotheses accumulate. A full sweep of the generator catalogue against one 160-bit target is ≈ 2⁷⁶ ·⁶ hypotheses (margin 83) with 64-bit-state LCGs included, ≈ 2⁶¹ ·⁸ (margin 98) without — comfortably inside Tier A for a 160-bit target, but the Phase 1 labels (18.4 bits) and the S-box residues (≈50 bits) are not, and the plan says so up front.

## Appendix A — Pilot reproduction (sandbox, 2026-11-10)

Everything below was computed in the sandbox with independently written code; it is the evidence behind the budget and the Phase 1/2 claims. Environment: Python venv, `cypari` 2.5.7 (PARI 2.15.4) with the `seadata` package, `fpylll`.

- **Seeds and base points reproduced.** Independent implementations of the `srand48`/`drand48`/`lrand48` seed stream and the FreeLIP `zrandom` base-point recipe reproduce all ten prime seeds, four binary seeds, and six FreeLIP base points.
- **State recovery from the seed alone.** `fpylll` (lattice dim 20; minimal working dim 6–7) recovered the 48-bit `srand48` state of every one of the ten published prime seeds from its 20 bytes alone, stepped back to the `…330E` seeding form, and read off the Unix timestamp and block index — reproducing the discovery from scratch. The solver also surfaces alternate readings (e.g. P-384 as block 51840 of a 1995 timestamp, P-521 as block 17520 of a 1994 timestamp), illustrating the `2¹⁶`-step recurrence caveat: a seeding-form state is not evidence by itself.
- **Full candidate census** (independent of Valsorda; runs enumerated to index 8000 where feasible):

| run | viable (prime, `bitlen(n) ≤ bitlen(p)`) up to last published | agrees with Valsorda | prime-order excluded only by the length rule (indices) | viable *after* the last published index |
| --- | --- | --- | --- | --- |
| prime239 (863711343) | 36,1562,2185,2320,2491,2682,2863,3048 | yes | none | 3391, 5986, 6500, 7004 |
| prime192 (863966734) | 139,2198,5228,5405,6013 | yes | 1006,2678,2771,5242,5674,5701,5964 | none to 8000 |
| P-521 (871002724) | 1136 | yes | none | none to 1148 |
| P-256 (871696354) | 876,1842 | yes | none | 3807,4329,4568,5261,5284,5454,5546,5583,5959,6217,7051,7145 |
| P-384 (872952608) | 2688 | yes | 1497,1626 | none to 2688 |
| P-224 (891607927) | 777,1485,5736,7026 | yes | 77,2232,2328,2938,2954,3191,3199,5861 | none to 8000 |

  Three independent computations (lead, pilot, and the public census) agree on the 10-of-21 published/skipped split exactly. Two facts for Phase 1: every run stops at its last *published* index though good curves continue after it (P-256 has twelve more by 7145), so the stop is a quota, not exhaustion; and the length rule (itself undocumented, Appendix B) removes 17 prime-order candidates, unevenly (7 in the P-192 run, 8 in P-224, 0 in the 239/256/521 runs).
- **Early-abort SEA is sound** on the validation sample: of 240 curves counted both ways, every early abort corresponded to a genuine small factor; 0 prime-order curves were falsely aborted.
- **Base-point negatives (lead).** The FreeLIP state-complete test (26-bit limbs, `x = limbs mod p`, `L ∈ {⌈bits/26⌉, +1}`, both orders; planted controls 60/60, 0 null false positives over 1000+ trials) finds **no `zrandom` state** reproducing `x(G)` for P-224, P-256, P-384 or P-521.
- **Benchmarks** (CPU-s per SEA call, one core): early-abort avg 0.004/0.009/0.008/0.019/0.26/1.3 s and full-count avg 0.42/0.84/1.0/1.4/10/46 s at 192/224/239/256/384/521 bits. Enumerating 10,000 candidates with early abort: 0.04–3.7 CPU-h by size.

Pre-registered Phase 1 probes run in the pilot, all **negative** (recorded in `registry/` as spent budget, ≈ 64 rules): `n−1`/`n+1`/twist/discriminant bounded-factorization; `n` and `t` residues mod 3/4/8; quadratic characters of `x³−3x+b`; Kronecker symbols of the discriminant at ℓ ≤ 23; six RNG-consumption walk models; the FreeLIP state test on the later base points. Closest post-hoc partials (leads only, Tier C): `t mod 8 ∈ {5,7}` for 10/10 published and 4/11 skipped; `Kronecker(D/11) = −1` for 6/10 published vs 1/11 skipped.

## Appendix B — Verified generation procedure (ANSI X9.62 draft 1998-09-20; FIPS 186-2 App. 6)

Quoted from the fetched primary text (SHA-256 pinned in Phase 0). **Prime curves (A.3.3.2):** `s = ⌊(l−1)/160⌋`; `W₀` = the `(l−160s)` rightmost bits of `SHA-1(SEED)` with the top bit cleared; `Wᵢ = SHA-1((SEED+i) mod 2^g)`; `W = W₀‖…‖W_s`; `r = Σ wᵢ 2^{t−i}`; choose `a, b` with `r·b² ≡ a³`. With `a = −3`: `b² ≡ −27/r`, and the published root is `(−27/r)^((p+1)/4)` for `p ≡ 3 mod 4`. **Acceptance (A.3.2):** near-primality (cofactor `lmax`-smooth, `lmax` typ. 255; `n ≥ rmin > 2¹⁶⁰` and `> 4√q`), MOV condition `B ≥ 20`, anomalous condition, Miller–Rabin `T ≥ 50` with **random** bases. **Base point (A.3.1 + D.3.1):** draw random `x`, attempt a square root, retry on failure; `G = h·R`.

**Two criteria the published curves obey that the standard does not state** (this is the crux of Phase 1):
1. **Prime order (`h = 1`).** X9.62 only requires an `lmax`-smooth cofactor; every published curve has `h = 1`. An unwritten NSA choice.
2. **`bitlen(n) ≤ bitlen(p)`.** There is no upper bound on `n` anywhere in the draft — only lower bounds. Yet every prime-order candidate with a longer `n` before a published seed was rejected (verified: 17 across the runs). This is Valsorda's "undocumented criterion", confirmed here to be absent from the primary text.

The unexplained ~50% filter sits *on top of* these two, among the candidates that pass both.

**Binary curves (A.3.3.1 / FIPS 186-2 App. 6.6):** `b` is `SHA-1`-derived, read in the **Gaussian normal basis** in which the curve is specified, then converted to polynomial basis. Verified: all five B-curve seeds, **including B-163**, regenerate the published normal-basis `b` bit-for-bit — so B-163 is a genuine seed, not an erratum.

Same-era, same-agency fingerprint targets surfaced by the review (for the generator library to sweep): the X9.62 worked-example private keys `d` and per-message secrets `k`; the FIPS 186 DSA example `SEED`/`XKEY`/`KKEY` (the 1998 DSA seed is the 1994 seed `+ 0x16`, incremented until `q` worked).

## Appendix C — Changes from Rev. 1

1. **Target set and ordering** rebuilt around what is still open after 2026-10-16 and a public follow-up wave: the candidate filter (unchanged as #1), then B-163/base points/clock, then a re-scoped secp256k1 phase (largely scooped), a **new Dual_EC_DRBG Q phase** (highest security relevance), then the national curves, then the S-box residue.
2. **Evidence standard** rewritten: tiered margins with a capacity-first rule, because the flagship Phase 1 target carries only 18.4 bits of label information and can never meet a flat 64-bit bar. "Freedom in bits" (BADA55) and the S-box "anomaly" measure (Bonnetain–Perrin–Tian) are adopted as the units.
3. **Phase 1** redesigned from "freeze a feature list" to "freeze a *mechanism* list" (deterministic curve features are essentially exhausted — 150+ on public record), with pre-registered rule families, a binary-run held-out label set, the extended census, and explicit capacity accounting.
4. **Generator library and solvers** corrected and expanded (three-layer `gens/`, big-integer consumers, large-state `seed_sweep.py`, default-stream scan, FreeLIP CVP solver); the Rev. 1 "glibc TYPE_3" and the weak adapter were wrong.
5. **Compute budget** cut ~100× for Phase 1 (measured 1.5 CPU-h, not 1 CPU-day on 32 cores); the real cost is engineering.
6. **Controls and prior-art import** made mandatory (rules 8, 12); a large public negative-result corpus is folded in (Appendix D) with a re-verification sample.
7. **Disclosure** strengthened: a dedicated gate for the Dual_EC phase, and a novelty audit before any newness claim.

## Appendix D — Public work as of 2026-11-10 (import to the registry; verify before reuse)

- **Valsorda**, bounty claimed, write-up + Go reimplementation (`seeds.go`): the length rule; "roughly twice as many valid seeds as published"; the filter unexplained.
- **A large agent-driven study** (public repos, 2026-10-16→31): full census (21,753 blocks, 11,042 point-counted, 21 accepted), ~150 pre-registered features and several process models for the filter — all negative; period-software replays (FreeLIP 1.0, early NTL, ECPP, LiDIA); B-163 and base-point searches (T1–T14) negative; a recovered 1997-11-17 X9.62 draft containing P-256 with its final base point.
- **A SECG-generator write-up** (Oct 2026): 25 of 69 standard curves share a "stored value → bump last digit → ×cofactor" structure for their base points; the stored strings and the last-digit rule remain unexplained. Also: RC2 PITABLE solved (Fisher–Yates on digits of π).
- **An independent port** with a committed 11,042-line order cache (useful cross-check; compute orders independently anyway).
- **DiSSECT** (AFRICACRYPT 2022): standard-vs-simulated trait study across NIST/SECG/Brainpool/GOST/SM2/ANSSI; no separating trait; does **not** cover PRNG/seed provenance or `p−1` structure.
- **BADA55** (2015): none of the sub-512-bit Brainpool curves follow their own documented procedure; "freedom in bits" accounting. Use Brainpool as a Phase 0 regression target, not a discovery phase.

Blocked/not reached in the review (retry in Phase 0): eprint.iacr.org and iacr archive (Cloudflare), web.archive.org, Reddit/X/Mastodon full-text, the IETF mail archive, legifrance and tc26.ru via curl.
