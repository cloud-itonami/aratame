(ns aratame.governor
  "The independent admission gate between a verdict and an action.

  It does not trust `:verdict/value`. It recounts corroboration from the
  signals the verdict carries, because a containment structure whose gate
  believes the thing it contains is decoration. Everything it can say is a
  literal from `aratame.taxonomy` — `refusals` and `escalations` are closed sets,
  and the tests pin the literals so that renaming one upstream breaks its
  callers instead of silently widening what is permitted.

  Deny by default: an action that matches no permit rule is refused."
  (:require [clojure.string :as str]
            [aratame.taxonomy :as tax]
            [aratame.verdict :as v]))

(def default-protected-prefixes
  "Paths nothing may be moved out of, whatever the verdict says. The system
  volume is here because a false positive there is not a cleanup, it is an
  unbootable machine; the credential paths are here because quarantining a key
  and quarantining a threat are indistinguishable to the person locked out."
  ["/System/" "/bin/" "/sbin/" "/usr/bin/" "/usr/sbin/" "/usr/lib/"
   "/Library/Apple/" "/private/var/db/" "/.ssh/" "/.gnupg/"])

(def default-policy
  {:policy/id                          "aratame.governor.v1"
   :protected-prefixes                 default-protected-prefixes
   :corroboration/floor                2
   :enforce/require-fresh-indicators   true
   :platform-signed-states             #{:apple-signed}})

(defn- protected? [path prefixes]
  (boolean (and path (some #(str/includes? path %) prefixes))))

(defn- refuse [reason detail]
  {:governor/decision :refuse :governor/reason reason
   :governor/message (get tax/refusals reason) :governor/detail detail})

(defn- escalate [reason detail]
  {:governor/decision :escalate :governor/reason reason
   :governor/message (get tax/escalations reason) :governor/detail detail})

(defn admit
  "`{:verdict … :action … :subject … :policy … :audience …}` -> decision map.

  `:audience` is `:operator` (default) or `:public`; a public citation of
  evidence shared under TLP:amber or stricter is refused rather than redacted,
  because a redacted citation still asserts the finding."
  [{:keys [verdict action subject policy audience]}]
  (let [policy   (merge default-policy policy)
        audience (or audience :operator)
        touches? (get-in tax/actions [action :touches-subject?])
        signals  (:verdict/signals verdict)
        recount  (count (v/independent signals))
        value    (:verdict/value verdict)
        stale?   (get-in verdict [:verdict/indicators :stale?])
        path     (:subject/path subject)]
    (cond
      (not (contains? tax/actions action))
      (refuse :refuse/action-not-admitted {:action action :admitted (set (keys tax/actions))})

      (nil? (:subject/id subject))
      (refuse :refuse/no-subject {})

      (and (= :public audience)
           (some #(not (get-in tax/tlp [(:signal/tlp %) :public?])) signals))
      (refuse :refuse/tlp-disclosure
              {:classes (vec (distinct (map :signal/tlp signals)))})

      (not touches?)
      {:governor/decision :permit :governor/reason nil
       :governor/action action :governor/corroboration recount}

      (= :unmeasured value)
      (refuse :refuse/verdict-unmeasured {:reason (:verdict/reason verdict)})

      (protected? path (:protected-prefixes policy))
      (refuse :refuse/protected-path {:path path})

      (contains? (:platform-signed-states policy) (:subject/signature subject))
      (refuse :refuse/platform-signed {:signature (:subject/signature subject)})

      (and stale? (:enforce/require-fresh-indicators policy))
      (refuse :refuse/indicators-stale
              {:age-days (get-in verdict [:verdict/indicators :age-days])})

      (< recount (:corroboration/floor policy))
      (if (seq signals)
        (escalate :escalate/uncorroborated {:corroboration recount
                                            :floor (:corroboration/floor policy)})
        (refuse :refuse/no-corroboration {:corroboration recount}))

      (= :suspicious value)
      (escalate :escalate/suspicious {:corroboration recount})

      (= :malicious value)
      {:governor/decision :permit :governor/reason nil
       :governor/action action :governor/corroboration recount}

      :else
      (refuse :refuse/no-corroboration {:verdict value :corroboration recount}))))
