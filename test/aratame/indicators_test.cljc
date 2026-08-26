(ns aratame.indicators-test
  (:require [clojure.test :refer [deftest is testing]]
            [aratame.indicators :as ind]))

(def now 1756200000000)
(def day 86400000)

(deftest values-are-canonicalised-so-a-match-is-not-a-coincidence-of-case
  (is (= "abcdef" (ind/normalize-value :sha256 "ABCDEF")))
  (is (= "evil.example" (ind/normalize-value :domain "Evil.Example.")))
  (is (nil? (ind/normalize-value :sha256 12345))
      "a non-string value is refused, not coerced into a key that never matches"))

(deftest inputs-that-could-not-be-indexed-are-counted-not-dropped
  (let [s (ind/indicator-set {:indicators [{:indicator/type :sha256 :indicator/value "AA"}
                                           {:indicator/type :nonsense :indicator/value "x"}
                                           {:indicator/type :sha256 :indicator/value nil}]
                              :collected-at-ms now :source-id "t"})]
    (is (= 1 (:set/count s)))
    (is (= 2 (:set/rejected s))
        "a loader that silently discarded these would be indistinguishable from an empty feed")))

(deftest staleness-never-answers-fresh-when-it-does-not-know
  (let [s (ind/indicator-set {:indicators [] :collected-at-ms nil :source-id "t"})]
    (is (true? (:stale? (ind/staleness s {:now-ms now :max-age-days 7}))))
    (is (= :indicators/no-collection-time (:reason (ind/staleness s {:now-ms now :max-age-days 7})))))
  (testing "no clock is the same kind of unanswered question"
    (let [s (ind/indicator-set {:indicators [] :collected-at-ms now :source-id "t"})]
      (is (= :indicators/no-clock (:reason (ind/staleness s {:now-ms nil :max-age-days 7}))))))
  (testing "control — a dated set inside the floor is fresh"
    (let [s (ind/indicator-set {:indicators [] :collected-at-ms (- now day) :source-id "t"})]
      (is (false? (:stale? (ind/staleness s {:now-ms now :max-age-days 7})))))))

(deftest a-subject-is-looked-up-under-every-identifier-it-carries
  (let [s (ind/indicator-set {:indicators [{:indicator/type :sha256 :indicator/value "aa"}
                                           {:indicator/type :domain :indicator/value "evil.example"}]
                              :collected-at-ms now :source-id "t"})]
    (is (= 2 (count (ind/lookup-subject s {:subject/sha256 "AA"
                                           :subject/domains ["evil.example."]}))))
    (is (empty? (ind/lookup-subject s {:subject/sha256 "bb"})))))
