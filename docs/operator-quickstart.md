# harai — operator quickstart

Every command below was run on 2026-08-26 on macOS 26 (arm64, nbb 1.4.x) and the
output is what came back, unedited. Where a run exits non-zero, that is the
intended result and the reason is given.

## Install and test

```sh
cd orgs/cloud-itonami/harai
npm install          # nbb only
npm test
```

```
Ran 31 tests containing 103 assertions.
0 failures, 0 errors.
```

The suite discriminates: each of the five load-bearing invariants was broken
once, in place, and only its own test failed —

| mutation | test that failed |
|---|---|
| a missing probe counts as answered | `a-probe-that-did-not-run-is-not-a-clean-result` |
| independence keyed on source only | `two-feeds-carrying-one-observation-are-still-one-accuser` |
| the governor trusts `:verdict/value` | `a-forged-verdict-does-not-convince-the-gate` |
| an empty sweep reports `:complete` | `an-empty-sweep-is-refused-not-clean` |
| an undated indicator set reads as fresh | `a-stale-set-cannot-say-clean` |

## 1. What is this machine's actual antivirus

```sh
bin/harai doctor
```

```
PLATFORM	answered	xprotect=5356	gatekeeper=enabled
INDICATORS	…/resources/harai/indicators.seed.edn	count=2	stale=false
NOTE	On a Mac, XProtect is the antivirus. harai judges what it is given and governs what may be done about it; it does not replace that.
```

`xprotect=5356` is Apple's blocklist version on this machine. That number is
more consequential than anything harai ships, which is why it is the first line
of output.

## 2. A scan that finds something

```sh
mkdir -p /tmp/harai-demo
printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/harai-demo/sample.txt
printf 'ordinary text\n' > /tmp/harai-demo/notes.txt
bin/harai scan /tmp/harai-demo; echo "exit=$?"
```

```
INDICATORS	…/indicators.seed.edn	count=2	rejected=0	stale=false
SUSPICIOUS	[:uncorroborated 1]	permit		/tmp/harai-demo/sample.txt
CLEAN	[:no-signal]	permit		/tmp/harai-demo/notes.txt
SCANNED	2
ANSWER	complete	malicious=0 suspicious=1 unmeasured=0 clean=1
exit=1
```

`sample.txt` is the EICAR standard test file — 68 published, harmless bytes that
exist so a detection path can be exercised without handling a real sample. Note
what it is **not**: `:malicious`. One indicator source is one accuser, and
`[:uncorroborated 1]` says exactly that. A product that convicted here would
convict on a single feed's say-so.

The `permit` in the third column is the governor permitting the *proposed
action*, which for a non-malicious verdict is `:report` — reporting touches
nothing. It is not a permission to act on the file.

## 3. A scan that cannot answer — the case that matters

```sh
bin/harai scan /tmp/harai-demo --indicators /tmp/nope.edn; echo "exit=$?"
```

```
INDICATORS	unreadable	/tmp/nope.edn	ENOENT: no such file or directory, open '/tmp/nope.edn'
INDICATORS	/tmp/nope.edn	count=0	rejected=0	stale=true	reason=:indicators/no-collection-time
UNMEASURED	[:indicators/stale :indicators/no-collection-time]	permit		/tmp/harai-demo/notes.txt
UNMEASURED	[:indicators/stale :indicators/no-collection-time]	permit		/tmp/harai-demo/sample.txt
SCANNED	2
ANSWER	partial	malicious=0 suspicious=0 unmeasured=2 clean=0
exit=2
```

The feed did not load. Both files were hashed successfully and neither matched
anything — and the answer is still `:unmeasured`, because nothing was matched
*against*. Every scanner in the world prints "no threats found" here.

## 4. A sweep with nothing in it

```sh
mkdir -p /tmp/harai-empty
bin/harai scan /tmp/harai-empty; echo "exit=$?"
```

```
INDICATORS	…/indicators.seed.edn	count=2	rejected=0	stale=false
SCANNED	0
ANSWER	refused	malicious=0 suspicious=0 unmeasured=0 clean=0
exit=2
```

`SCANNED	0` and `refused`. A sweep that examined nothing is not allowed to
report that it found nothing.

## 5. The ledger

```sh
bin/harai scan /tmp/harai-demo --ledger /tmp/harai-run.edn | tail -1
head -1 /tmp/harai-run.edn
```

```
LEDGER	/tmp/harai-run.edn	entries=4
#:ledger{:seq 0, :prev nil, :kind :verdict, :at-ms 1787727791493, :actor "harai", :payload #:verdict{…
```

Four entries for two files: one verdict and one governor decision each.
Refusals are recorded with the same weight as permissions. `harai.ledger/verify`
recomputes every digest and every link and returns `:entries` alongside `:ok?`,
so an empty ledger cannot be read as a sound one.

## 6. Feeding it something real

```clojure
(require '[harai.adapters :as a] '[harai.indicators :as ind])

(ind/indicator-set
 {:indicators (keep a/ti-record->indicator (:records ti-export))
  :collected-at-ms (:collectedAtMs ti-export)
  :source-id "threat-intelligence"})
```

`:collected-at-ms` must come from the export, not from `Date.now()`. Dating a
feed at the moment you loaded it makes every feed permanently fresh, which
removes the only defence against a feed that stopped updating.

## Exit codes

| code | meaning |
|---|---|
| 0 | examined something, found nothing |
| 1 | found something |
| 2 | **could not answer** — refused, partial, or the tool was misused |

`2` is deliberately neither of the others. A caller that only checks
`if exit == 0` cannot mistake an unanswered sweep for a clean one.
