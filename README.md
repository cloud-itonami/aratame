# aratame 改め — governed malware verdict plane

**改め (aratame) is the old word for an official examination — 関所改め, the
inspection at a checkpoint that decides what may pass.** The name does not say
what this does, so it says it here first, as this workspace requires of
metaphor-named repositories: **aratame turns evidence about a file into a
verdict, and governs what anyone is allowed to do about that verdict.** It is a
`cloud-itonami` actor; it lives at `orgs/cloud-itonami/aratame`.

(It was called `harai` 祓 for the first hour of its life, until the concept index
surfaced `cloud-itonami/app-harai` — 払い, payment and settlement clearing —
under the same reading in the same org. Two repositories a person cannot tell
apart when speaking are worse than one awkward name, and the index that found
the collision is the same one this repository added.)

It is not a scanner. It ships no detection engine, no signature database it
maintains, and no real-time hook. On a Mac, XProtect is the antivirus — `aratame
doctor` reports XProtect's version rather than competing with it.

What it owns is the part nothing in this workspace owned: **the decision, and the
gate in front of the decision.**

## The one thing this exists to prevent

> A scan that could not run must never return the value a clean scan returns.

Every antivirus product ever shipped collapses those two into one green shield.
A skipped file, a denied directory, a signature database nobody updated, a probe
that failed — all of them present as *no threats found*. That collapse is not a
bug in any one product; it is the shape of the interface.

So here it is not representable:

| | |
|---|---|
| `aratame.taxonomy/verdicts` | contains **`:unmeasured`**, ranked *above* `:clean`. Not knowing is a louder state than knowing there is nothing, because it is the one that needs a person. |
| `aratame.taxonomy/actions` | contains `:report`, `:quarantine`, `:block` and **no `:delete`**. Destroying bytes is not in the codomain, so no policy and no future caller can request it. Reversal is [`kotoba-lang/quarantine`](https://github.com/kotoba-lang/quarantine)'s job and stays there. |
| `aratame.coverage/summarize` | over an empty verdict list returns **`:refused`**, not clean. A sweep that examined nothing may not say it found nothing. |
| exit codes | `0` nothing found · `1` something found · **`2` could not answer**. `2` is neither of the other two, so a caller that checks `if exit == 0` cannot read an unanswered sweep as success. |

Out of the box, with no feed configured, aratame answers `:unmeasured` for every
file and exits `2`. That is the correct first answer, and it is the behaviour a
scanner cannot produce.

## The three rules in the decision core

`aratame.verdict/judge` is pure — facts in, verdict out, the clock passed as an
argument.

1. **A required probe that did not answer ends the computation.** Not a
   downgrade, not a warning: `:unmeasured`, naming each probe. A probe missing
   from the map counts as unanswered, because omission is how probes usually
   fail.
2. **One accuser cannot convict.** `:malicious` requires corroboration from
   signals that differ in **source *and* kind**. Two feeds republishing one
   vendor's hash list share a kind, so they count once — which is what they are.
3. **A stale indicator set cannot produce `:clean`.** It can still produce
   `:malicious` from evidence that does not depend on it — a revoked certificate
   is measured today whatever the feed's age — but the *absence* of a hit in a
   stale set is not the absence of a threat. A set that cannot say when it was
   collected is stale, not fresh.

## The gate does not trust what it gates

`aratame.governor/admit` recounts corroboration from `:verdict/signals` instead of
reading `:verdict/value`. A containment structure whose gate believes the thing
it contains is decoration. It refuses by default, and every reason it can give
is a literal in the closed sets `aratame.taxonomy/refusals` and `escalations`:

```
:refuse/action-not-admitted  :refuse/verdict-unmeasured  :refuse/no-corroboration
:refuse/indicators-stale     :refuse/protected-path      :refuse/platform-signed
:refuse/tlp-disclosure       :refuse/no-subject
:escalate/uncorroborated     :escalate/suspicious
```

Refusals are printed, never filtered. A gate whose refusals leave no trace is
indistinguishable from a gate that permitted everything.

## Where it sits

aratame invents no vocabulary. Each producer that already exists here has exactly
one translation into it, in `aratame.adapters`:

| producer | what it gives aratame |
|---|---|
| [`cloud-itonami/threat-intelligence`](https://github.com/cloud-itonami/threat-intelligence) | `IndicatorRecord` — hashes, domains, addresses, with its own 0–1000 permille confidence and TLP class, carried through unrescaled |
| [`cloud-itonami/yabai`](https://github.com/cloud-itonami/yabai) | `MalwareSample` — sample hashes, C2 domains and addresses, `vt_detection_rate` as a reputation input |
| [`kotoba-lang/macos-inventory`](https://github.com/kotoba-lang/macos-inventory) | the codesign/spctl verdict, quarantine provenance, XProtect version, Gatekeeper state — **required, not copied**, so a change upstream breaks the binding instead of drifting past it |
| [`gftdcojp/misogi`](https://github.com/gftdcojp/misogi) | its fact map, so a local hygiene finding can be judged here |
| [`kotoba-lang/quarantine`](https://github.com/kotoba-lang/quarantine) | the enforcement that `:quarantine` names — reversible by construction |

## Use

```sh
npm test                                    # 31 tests, 103 assertions, nbb
npm run aratame -- doctor                     # XProtect version, Gatekeeper, feed freshness
npm run aratame -- scan ~/Downloads
npm run aratame -- scan ~/Downloads --indicators ti-export.edn --ledger run.edn
```

`docs/operator-quickstart.md` has each of those with the output actually
observed, including the two cases that matter: a missing feed, and an empty
directory.

## What this does not do yet

Stated plainly, because a security tool's gaps are the part worth reading:

- **No real-time protection.** There is no EndpointSecurity client and no
  on-access hook. aratame judges what it is pointed at, when it is pointed at it.
- **No content inspection.** Verdicts come from identifiers, signing state,
  provenance and structural facts. There is no unpacking, no emulation, no YARA
  evaluation — `yabai`'s `MalwareSample.yara_rules` is carried as evidence, not
  evaluated.
- **The bundled seed expires by design.** `resources/aratame/indicators.seed.edn`
  dates itself and the default floor is 7 days, so a week after it was written
  every verdict computed against it alone becomes `:unmeasured`. A bundled list
  with no expiry is precisely how a product ends up asserting "clean" from a
  list nobody has updated.
- **Not wired to a live feed.** The `threat-intelligence` adapter is tested
  against that repository's record shape, not against its running PDS.
- **Not deployed.** No worker, no scheduled sweep, no fleet integration.

## Runtime

nbb, and only nbb. There is no `deps.edn` and no JVM surface: the workspace
runtime order is kotoba wasm > clojurewasm > ClojureScript > nbb, with the JVM
last, and nothing here needs one. The whole decision core is portable `.cljc`
with no host calls in it, so it is ready to move further up that order — what
holds it at `.cljc` is the host layer, which needs filesystem and process
capabilities that `.kotoba` does not have yet.

The one cross-repo dependency is `kotoba-lang/macos-inventory`, required for the
code-signing vocabulary rather than copied. That is also why there is no
fleet-ci gate registered yet: `:nbb-test` ships a single repo's tree, so a
sibling `:local/root` is not on the node's classpath. Registering it needs the
dependency expressed as a git dep with `:ship-git-deps true`, measured green on
a node first — a gate that has never been green is as uninformative as one that
never goes red.
