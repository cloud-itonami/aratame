(ns aratame.taxonomy
  "The controlled vocabulary of the verdict plane.

  Two of these definitions carry the whole product, and both are about what is
  *not* representable:

  1. `verdicts` contains `:unmeasured`. A scan that could not run does not
     return the value a scan that ran and found nothing returns. Consumer
     antivirus collapses those two — a skipped scan and a clean scan both
     present as a green shield — and that collapse is the failure mode this
     repository exists to make impossible to express.

  2. `actions` does not contain `:delete`. Enforcement can report, quarantine
     or block. Destroying bytes is not in the codomain, so no policy, no rule
     and no future caller can ask for it. Reversal is `kotoba-lang/quarantine`'s
     job and stays there."
  (:require [macos-inventory.core :as inv]))

(def verdicts
  "Verdict values, ranked by how much authority to act they carry.

  `:unmeasured` outranks `:clean` deliberately: not knowing is a louder state
  than knowing there is nothing, because it is the one that needs an operator."
  {:malicious  {:rank 3 :label "Malicious"            :actionable? true}
   :suspicious {:rank 2 :label "Suspicious"           :actionable? false}
   :unmeasured {:rank 1 :label "Could not be judged"  :actionable? false}
   :clean      {:rank 0 :label "Nothing found"        :actionable? false}})

(defn rank [verdict]
  (get-in verdicts [verdict :rank] -1))

(def actions
  "Everything enforcement is allowed to propose. `:delete` is absent by design;
  see the namespace docstring."
  {:report     {:label "Record the verdict only"      :touches-subject? false}
   :quarantine {:label "Move into a restorable vault" :touches-subject? true}
   :block      {:label "Refuse execution / network"   :touches-subject? true}})

(def signal-kinds
  "Where an accusation came from. Two signals corroborate each other only when
  they differ in *kind* as well as in source — two feeds republishing one
  vendor's hash list are one observation wearing two names."
  {:indicator  {:label "Indicator match (hash / domain / address)"}
   :signature  {:label "Code-signing state"}
   :provenance {:label "How it arrived on the machine"}
   :heuristic  {:label "Structural rule over observed facts"}
   :reputation {:label "Third-party detection count"}})

(def signature-states
  "Re-exported from `macos-inventory.core`, which is the process that actually
  produces these keys from codesign/spctl output. Not copied: a copy drifts and
  the drift is silent."
  inv/signature-states)

(def tlp
  "Traffic Light Protocol, matching cloud-itonami/threat-intelligence's
  `Tlp` type. `:amber` and `:red` may inform a verdict but may not be cited in
  a disclosure whose audience is wider than the sharing class allows."
  {:white {:rank 0 :public? true}
   :green {:rank 1 :public? false}
   :amber {:rank 2 :public? false}
   :red   {:rank 3 :public? false}})

(def escalations
  "Outcomes that are neither a permission nor a refusal: the governor has no
  authority to act and no grounds to close the case, so a person decides."
  {:escalate/uncorroborated "Signals exist but do not corroborate each other"
   :escalate/suspicious     "The subject is suspicious; enforcement needs a person"})

(def refusals
  "Every reason the governor can refuse, as a closed set. Callers pin these
  literals in tests; a rename upstream is meant to break them."
  {:refuse/action-not-admitted  "The proposed action is not in the admitted set"
   :refuse/verdict-unmeasured   "Nothing may be enforced on a subject that was not judged"
   :refuse/no-corroboration     "A single source is not enough to touch a subject"
   :refuse/indicators-stale     "The indicator set is older than the policy floor"
   :refuse/protected-path       "The subject sits under a protected path"
   :refuse/platform-signed      "The subject is signed by the platform vendor"
   :refuse/tlp-disclosure       "The citation exceeds the sharing class of its evidence"
   :refuse/no-subject           "The proposal names no subject"})
