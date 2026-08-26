(ns aratame.verdict-test
  "The decision core, tested for the thing it exists to prevent: an answer that
  looks like 'nothing found' when nothing was looked at.

  Every negative case here is paired with a control that differs in exactly the
  fact under test, because a test that only asserts the outcome counts a run
  that failed for an unrelated reason as a success."
  (:require [clojure.test :refer [deftest is testing]]
            [aratame.indicators :as ind]
            [aratame.verdict :as v]))

(def now 1756200000000)                      ; a fixed moment; nothing here reads a clock
(def day 86400000)

(defn iset
  "`{:collected-at-ms nil}` must mean *undated*, not *use the default* — the
  test for an undated set is worthless if the helper quietly dates it."
  [inds & [m]]
  (ind/indicator-set {:indicators inds
                      :collected-at-ms (get m :collected-at-ms (- now (* 2 day)))
                      :source-id "test-feed"}))

(def evil-hash "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

(defn hit [& [{:keys [source conf type value]}]]
  {:indicator/type (or type :sha256) :indicator/value (or value evil-hash)
   :indicator/confidence-permille (or conf 900)
   :indicator/tlp :white
   :indicator/source-id (or source "threat-intelligence")})

(def answered {:probe/sha256 {:probe/status :answered}
               :probe/signature {:probe/status :answered}})

(defn subject [& [m]]
  (merge {:subject/id (str "sha256:" evil-hash)
          :subject/sha256 evil-hash
          :subject/path "/Users/t/Downloads/thing"
          :subject/signature :dev-signed}
         m))

(defn judge [& [{:keys [subj probes indicators policy]}]]
  (v/judge {:subject (or subj (subject))
            :probes (if (nil? probes) answered probes)
            :indicator-set (or indicators (iset []))
            :policy policy
            :now-ms now}))

;; ---------------------------------------------------------------------------
;; the central invariant
;; ---------------------------------------------------------------------------

(deftest a-probe-that-did-not-run-is-not-a-clean-result
  (testing "a required probe with no result ends at :unmeasured, naming it"
    (let [r (judge {:probes {:probe/signature {:probe/status :answered}}})]
      (is (= :unmeasured (:verdict/value r)))
      (is (= [:probe/unanswered [:probe/sha256]] (:verdict/reason r)))))

  (testing "a probe that ran and failed is also unanswered"
    (let [r (judge {:probes (assoc answered :probe/sha256 {:probe/status :error
                                                           :probe/detail "EACCES"})})]
      (is (= :unmeasured (:verdict/value r)))
      (is (= [:probe/unanswered [:probe/sha256]] (:verdict/reason r)))))

  (testing "control — with every probe answered the same subject is judged"
    ;; If this were also :unmeasured the assertions above would be measuring
    ;; something other than the probe.
    (is (= :clean (:verdict/value (judge))))))

(deftest clean-is-reachable-only-with-a-fresh-set-and-every-probe
  (let [r (judge)]
    (is (= :clean (:verdict/value r)))
    (is (= [:no-signal] (:verdict/reason r)))
    (is (false? (get-in r [:verdict/indicators :stale?])))))

;; ---------------------------------------------------------------------------
;; corroboration
;; ---------------------------------------------------------------------------

(deftest one-accuser-cannot-convict
  (let [r (judge {:indicators (iset [(hit)])})]
    (is (= :suspicious (:verdict/value r)))
    (is (= [:uncorroborated 1] (:verdict/reason r)))))

(deftest two-feeds-carrying-one-observation-are-still-one-accuser
  (testing "same kind, different source names — independence needs both"
    (let [r (judge {:indicators (iset [(hit {:source "feed-a"})
                                       (hit {:source "feed-b"})])})]
      (is (= :suspicious (:verdict/value r)))
      (is (= [:uncorroborated 1] (:verdict/reason r)))))

  (testing "control — a second signal of a different kind does convict"
    (let [r (judge {:subj (subject {:subject/signature :revoked})
                    :indicators (iset [(hit {:source "feed-a"})])})]
      (is (= :malicious (:verdict/value r)))
      (is (= [:corroborated 2] (:verdict/reason r))))))

(deftest corroboration-still-needs-a-confident-signal
  (let [r (judge {:subj (subject {:subject/signature :unsigned
                                  :subject/persistence :launch-agent-user
                                  :subject/quarantine-xattr "0081;..."})
                  :indicators (iset [(hit {:conf 300})])})]
    (is (= :suspicious (:verdict/value r)))
    (is (= :below-confidence-floor (first (:verdict/reason r))))))

;; ---------------------------------------------------------------------------
;; freshness
;; ---------------------------------------------------------------------------

(deftest a-stale-set-cannot-say-clean
  (testing "old enough to be past the floor"
    (let [r (judge {:indicators (iset [] {:collected-at-ms (- now (* 30 day))})})]
      (is (= :unmeasured (:verdict/value r)))
      (is (= [:indicators/stale :indicators/older-than-floor] (:verdict/reason r)))))

  (testing "a set that cannot date itself is stale, not fresh"
    (let [r (judge {:indicators (iset [] {:collected-at-ms nil})})]
      (is (= :unmeasured (:verdict/value r)))
      (is (= [:indicators/stale :indicators/no-collection-time] (:verdict/reason r)))))

  (testing "control — the same empty set inside the floor is clean"
    (is (= :clean (:verdict/value (judge {:indicators (iset [] {:collected-at-ms (- now day)})}))))))

(deftest a-stale-set-does-not-suppress-measured-evidence
  (testing "a revoked certificate and a persistence heuristic still convict"
    (let [r (judge {:subj (subject {:subject/signature :revoked
                                    :subject/persistence :launch-daemon
                                    :subject/quarantine-xattr "0081;..."})
                    :indicators (iset [(hit)] {:collected-at-ms (- now (* 30 day))})})]
      (is (= :malicious (:verdict/value r)))
      (is (= [:corroborated 2] (:verdict/reason r)))
      (testing "and the indicator hit is not among the signals it convicted on"
        (is (empty? (filter #(= :indicator (:signal/kind %)) (:verdict/signals r))))))))

(deftest an-unidentified-subject-is-never-judged
  (let [r (judge {:subj (dissoc (subject) :subject/id)})]
    (is (= :unmeasured (:verdict/value r)))
    (is (= [:subject/unidentified] (:verdict/reason r)))))
