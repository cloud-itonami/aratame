# harai 祓 — governed malware verdict plane

**祓 (harai) is the rite of removing what has been judged impure.** The name does
not say what this does, so it says it here first, as this workspace requires of
metaphor-named repositories: **harai turns evidence about a file into a verdict,
and governs what anyone is allowed to do about that verdict.** It is a
`cloud-itonami` actor; it lives at `orgs/cloud-itonami/harai`.

It is not a scanner. It ships no detection engine, no signature database it
maintains, and no real-time hook. On a Mac, XProtect is the antivirus — `harai
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
| `harai.taxonomy/verdicts` | contains **`:unmeasured`**, ranked *above* `:clean`. Not knowing is a louder state than knowing there is nothing, because it is the one that needs a person. |
| `harai.taxonomy/actions` | contains `:report`, `:quarantine`, `:block` and **no `:delete`**. Destroying bytes is not in the codomain, so no policy and no future caller can request it. Reversal is [`kotoba-lang/quarantine`](https://github.com/kotoba-lang/quarantine)'s job and stays there. |
| `harai.coverage/summarize` | over an empty verdict list returns **`:refused`**, not clean. A sweep that examined nothing may not say it found nothing. |
| exit codes | `0` nothing found · `1` something found · **`2` could not answer**. `2` is neither of the other two, so a caller that checks `if exit == 0` cannot read an unanswered sweep as success. |

Out of the box, with no feed configured, harai answers `:unmeasured` for every
file and exits `2`. That is the correct first answer, and it is the behaviour a
scanner cannot produce.

## The three rules in the decision core

`harai.verdict/judge` is pure — facts in, verdict out, the clock passed as an
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

`harai.governor/admit` recounts corroboration from `:verdict/signals` instead of
reading `:verdict/value`. A containment structure whose gate believes the thing
it contains is decoration. It refuses by default, and every reason it can give
is a literal in the closed sets `harai.taxonomy/refusals` and `escalations`:

```
:refuse/action-not-admitted  :refuse/verdict-unmeasured  :refuse/no-corroboration
:refuse/indicators-stale     :refuse/protected-path      :refuse/platform-signed
:refuse/tlp-disclosure       :refuse/no-subject
:escalate/uncorroborated     :escalate/suspicious
```

Refusals are printed, never filtered. A gate whose refusals leave no trace is
indistinguishable from a gate that permitted everything.

## Where it sits

harai invents no vocabulary. Each producer that already exists here has exactly
one translation into it, in `harai.adapters`:

| producer | what it gives harai |
|---|---|
| [`cloud-itonami/threat-intelligence`](https://github.com/cloud-itonami/threat-intelligence) | `IndicatorRecord` — hashes, domains, addresses, with its own 0–1000 permille confidence and TLP class, carried through unrescaled |
| [`cloud-itonami/yabai`](https://github.com/cloud-itonami/yabai) | `MalwareSample` — sample hashes, C2 domains and addresses, `vt_detection_rate` as a reputation input |
| [`kotoba-lang/macos-inventory`](https://github.com/kotoba-lang/macos-inventory) | the codesign/spctl verdict, quarantine provenance, XProtect version, Gatekeeper state — **required, not copied**, so a change upstream breaks the binding instead of drifting past it |
| [`gftdcojp/misogi`](https://github.com/gftdcojp/misogi) | its fact map, so a local hygiene finding can be judged here |
| [`kotoba-lang/quarantine`](https://github.com/kotoba-lang/quarantine) | the enforcement that `:quarantine` names — reversible by construction |

## Use

```sh
npm test                                    # 31 tests, 103 assertions, nbb
npm run harai -- doctor                     # XProtect version, Gatekeeper, feed freshness
npm run harai -- scan ~/Downloads
npm run harai -- scan ~/Downloads --indicators ti-export.edn --ledger run.edn
```

`docs/operator-quickstart.md` has each of those with the output actually
observed, including the two cases that matter: a missing feed, and an empty
directory.

## What this does not do yet

Stated plainly, because a security tool's gaps are the part worth reading:

- **No real-time protection.** There is no EndpointSecurity client and no
  on-access hook. harai judges what it is pointed at, when it is pointed at it.
- **No content inspection.** Verdicts come from identifiers, signing state,
  provenance and structural facts. There is no unpacking, no emulation, no YARA
  evaluation — `yabai`'s `MalwareSample.yara_rules` is carried as evidence, not
  evaluated.
- **The bundled seed expires by design.** `resources/harai/indicators.seed.edn`
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
