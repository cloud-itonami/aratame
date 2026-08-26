(ns harai.indicators
  "The indicator set a verdict is computed against, and how old it is.

  An antivirus with a stale signature database returns the same 'nothing found'
  as one with a current database. So freshness is not metadata here — it is part
  of the answer. A set that cannot say when it was collected is stale, not
  fresh: an absent collection time is an unanswered question, and unanswered
  questions never resolve to the permissive value."
  (:require [clojure.string :as str]))

(def hash-types #{:md5 :sha1 :sha256})
(def indicator-types (into hash-types #{:ipv4 :ipv6 :domain :url :email :cve}))

(defn normalize-value
  "Canonical key for an indicator value. Hashes and domains are case-folded;
  a trailing root dot is dropped from domains. Values that are not strings are
  refused rather than coerced — a coerced key silently fails to match."
  [t v]
  (when (string? v)
    (let [v (str/trim v)]
      (cond
        (contains? hash-types t) (str/lower-case v)
        (= :domain t)            (str/replace (str/lower-case v) #"\.$" "")
        (= :email t)             (str/lower-case v)
        :else                    v))))

(defn- indexable [{:keys [indicator/type indicator/value] :as ind}]
  (when (and (contains? indicator-types type) (normalize-value type value))
    (assoc ind :indicator/key [type (normalize-value type value)])))

(defn indicator-set
  "Build a queryable set. `:set/collected-at-ms` is the moment the whole set was
  known current, not the moment any one indicator was first seen.

  `:set/rejected` counts inputs that could not be indexed. It is reported, never
  dropped: a loader that silently discards half its feed and a loader that read
  an empty feed produce the same index."
  [{:keys [indicators collected-at-ms source-id]}]
  (let [ok (keep indexable indicators)]
    {:set/source-id       source-id
     :set/collected-at-ms collected-at-ms
     :set/count           (count ok)
     :set/rejected        (- (count indicators) (count ok))
     :set/by-key          (reduce (fn [m ind] (update m (:indicator/key ind) (fnil conj []) ind))
                                  {} ok)}))

(def empty-set (indicator-set {:indicators [] :collected-at-ms nil :source-id nil}))

(defn staleness
  "`{:stale? bool :age-days n :reason kw}`. Never returns `:stale? false` for a
  set that cannot date itself."
  [iset {:keys [now-ms max-age-days]}]
  (let [c (:set/collected-at-ms iset)]
    (cond
      (nil? c)       {:stale? true :age-days nil :reason :indicators/no-collection-time}
      (nil? now-ms)  {:stale? true :age-days nil :reason :indicators/no-clock}
      :else (let [age (/ (- now-ms c) 86400000.0)]
              (if (> age (or max-age-days 0))
                {:stale? true  :age-days age :reason :indicators/older-than-floor}
                {:stale? false :age-days age :reason nil})))))

(defn lookup
  "Indicators matching one (type, value) pair. Empty vector when nothing
  matches — which is a match result, not a judgement."
  [iset t v]
  (get (:set/by-key iset) [t (normalize-value t v)] []))

(defn lookup-subject
  "Every indicator hit for a subject, across each identifier it carries."
  [iset {:keys [subject/sha256 subject/md5 subject/sha1
                subject/domains subject/addresses]}]
  (vec (concat (lookup iset :sha256 sha256)
               (lookup iset :md5 md5)
               (lookup iset :sha1 sha1)
               (mapcat #(lookup iset :domain %) domains)
               (mapcat #(lookup iset :ipv4 %) addresses))))
