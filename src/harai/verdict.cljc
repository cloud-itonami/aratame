(ns harai.verdict
  "The decision core: facts about a subject, plus an indicator set, plus a
  policy, produce a verdict. Pure — no clock, no filesystem, no network; the
  moment is passed in.

  The three rules that make this different from a scanner:

  * **A missing probe is not a clean result.** Required probes that did not
    answer end the computation at `:unmeasured`, naming each one.
  * **One accuser is not enough.** `:malicious` needs corroboration from
    signals that differ in *source* and in *kind*, so two mirrors of one feed
    cannot convict on their own.
  * **A stale indicator set cannot produce `:clean`.** It can still produce
    `:malicious` from evidence that does not depend on it (a revoked
    certificate is measured today regardless of feed age), but the absence of
    a hit in a stale set is not the absence of a threat."
  (:require [harai.indicators :as ind]
            [harai.taxonomy :as tax]))

(def default-policy
  {:policy/id                 "harai.default.v1"
   :required-probes           #{:probe/sha256 :probe/signature}
   :corroboration/floor       2
   :confidence/floor          800
   :indicators/max-age-days   7
   :reputation/detection-floor 5})

;; ---------------------------------------------------------------------------
;; probes
;; ---------------------------------------------------------------------------

(defn unanswered-probes
  "Required probes whose result is anything other than `:answered`, sorted so
  the reason is stable across runs. A probe absent from the map counts as
  unanswered — omission is the most common way a probe fails to run."
  [probes policy]
  (vec (sort (remove #(= :answered (get-in probes [% :probe/status]))
                     (:required-probes policy)))))

;; ---------------------------------------------------------------------------
;; signals
;; ---------------------------------------------------------------------------

(defn- signal [kind source-id id conf tlp evidence]
  {:signal/kind kind :signal/source-id source-id :signal/id id
   :signal/confidence-permille conf :signal/tlp (or tlp :white)
   :signal/evidence evidence})

(defn- indicator-signals [subject iset]
  (for [i (ind/lookup-subject iset subject)]
    (signal :indicator
            (or (:indicator/source-id i) (:set/source-id iset) "unattributed")
            :signal/indicator-hit
            (or (:indicator/confidence-permille i) 500)
            (:indicator/tlp i)
            {:indicator/key (:indicator/key i)
             :indicator/last-seen (:indicator/last-seen i)
             :indicator/description (:indicator/description i)})))

(defn- signature-signals [{:keys [subject/signature subject/path]}]
  (case signature
    :revoked [(signal :signature "codesign" :signal/certificate-revoked 900 :white
                      {:signature signature :path path})]
    :broken  [(signal :signature "codesign" :signal/signature-broken 800 :white
                      {:signature signature :path path})]
    []))

(defn- reputation-signals [{:keys [subject/detections subject/detection-source]} policy]
  (if (and (number? detections)
           (>= detections (:reputation/detection-floor policy)))
    [(signal :reputation (or detection-source "malware-sample") :signal/multi-engine-detection
             (min 1000 (* 100 detections)) :white {:detections detections})]
    []))

(defn- heuristic-signals [{:keys [subject/persistence subject/signature subject/hidden?]}]
  (cond-> []
    (and persistence (contains? #{:unsigned :adhoc} signature))
    (conj (signal :heuristic "harai.rules" :signal/unsigned-persistence 600 :white
                  {:persistence persistence :signature signature}))
    hidden?
    (conj (signal :heuristic "harai.rules" :signal/concealed-program 500 :white
                  {:hidden? true}))))

(defn- provenance-signals [{:keys [subject/quarantine-xattr subject/signature]}]
  (if (and quarantine-xattr (contains? #{:unsigned :broken :revoked :adhoc} signature))
    [(signal :provenance "com.apple.quarantine" :signal/downloaded-and-untrusted 400 :white
             {:quarantine-xattr quarantine-xattr :signature signature})]
    []))

(defn signals
  "Every accusation against the subject, from every source. Order is by
  descending confidence so corroboration selection is deterministic."
  [subject iset policy]
  (vec (sort-by (juxt (comp - :signal/confidence-permille) :signal/id (comp str :signal/source-id))
                (concat (indicator-signals subject iset)
                        (signature-signals subject)
                        (reputation-signals subject policy)
                        (heuristic-signals subject)
                        (provenance-signals subject)))))

(defn independent
  "The largest set of mutually independent signals this can pick greedily: a
  signal joins only when both its kind and its source are unused. Two feeds
  republishing one vendor's hash list share neither, so they count once."
  [signals]
  (:kept (reduce (fn [{:keys [kinds sources] :as acc} s]
                   (if (or (contains? kinds (:signal/kind s))
                           (contains? sources (:signal/source-id s)))
                     acc
                     (-> acc
                         (update :kinds conj (:signal/kind s))
                         (update :sources conj (:signal/source-id s))
                         (update :kept conj s))))
                 {:kinds #{} :sources #{} :kept []}
                 signals)))

;; ---------------------------------------------------------------------------
;; judgement
;; ---------------------------------------------------------------------------

(defn- unmeasured [subject reason extra]
  (merge {:verdict/value :unmeasured
          :verdict/reason reason
          :verdict/subject-id (:subject/id subject)
          :verdict/signals []}
         extra))

(defn judge
  "`{:subject … :probes … :indicator-set … :policy … :now-ms …}` -> verdict map.

  The returned map always carries `:verdict/reason`, a vector whose first
  element is a keyword literal that tests pin. Renaming one is meant to break
  its callers."
  [{:keys [subject probes indicator-set policy now-ms]}]
  (let [policy (merge default-policy policy)
        iset   (or indicator-set ind/empty-set)
        stale  (ind/staleness iset {:now-ms now-ms
                                    :max-age-days (:indicators/max-age-days policy)})
        base   {:verdict/policy-id (:policy/id policy)
                :verdict/at-ms now-ms
                :verdict/indicators {:set/count (:set/count iset)
                                     :set/rejected (:set/rejected iset)
                                     :stale? (:stale? stale)
                                     :age-days (:age-days stale)}}
        missing (unanswered-probes probes policy)]
    (cond
      (nil? (:subject/id subject))
      (unmeasured subject [:subject/unidentified] base)

      (seq missing)
      (unmeasured subject [:probe/unanswered missing]
                  (assoc base :verdict/missing-probes missing))

      :else
      (let [all   (signals subject iset policy)
            usable (if (:stale? stale)
                     (vec (remove #(= :indicator (:signal/kind %)) all))
                     all)
            indep (independent usable)
            top   (apply max 0 (map :signal/confidence-permille usable))
            n     (count indep)]
        (cond
          (and (>= n (:corroboration/floor policy))
               (>= top (:confidence/floor policy)))
          (merge base {:verdict/value :malicious
                       :verdict/reason [:corroborated n]
                       :verdict/subject-id (:subject/id subject)
                       :verdict/signals usable
                       :verdict/independent indep})

          (seq usable)
          (merge base {:verdict/value :suspicious
                       :verdict/reason (if (< n (:corroboration/floor policy))
                                         [:uncorroborated n]
                                         [:below-confidence-floor top])
                       :verdict/subject-id (:subject/id subject)
                       :verdict/signals usable
                       :verdict/independent indep})

          (:stale? stale)
          (unmeasured subject [:indicators/stale (:reason stale)] base)

          :else
          (merge base {:verdict/value :clean
                       :verdict/reason [:no-signal]
                       :verdict/subject-id (:subject/id subject)
                       :verdict/signals []}))))))
