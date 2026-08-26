(ns aratame.ledger-test
  (:require [clojure.test :refer [deftest is testing]]
            [aratame.ledger :as l]))

(defn digest [s] (str "d" (hash s)))

(deftest the-chain-detects-both-a-rewrite-and-a-removal
  (let [es (-> []
               (l/append {:kind :verdict :at-ms 1 :payload {:subject/id "a"}} digest)
               (l/append {:kind :governor :at-ms 2 :payload {:subject/id "a"}} digest)
               (l/append {:kind :verdict :at-ms 3 :payload {:subject/id "b"}} digest))]
    (is (:ok? (l/verify es digest)))
    (is (= 3 (:entries (l/verify es digest))))

    (testing "a rewritten payload breaks its own digest"
      (let [tampered (assoc-in (vec es) [1 :ledger/payload :subject/id] "z")]
        (is (false? (:ok? (l/verify tampered digest))))
        (is (= :digest (:fault (first (:broken (l/verify tampered digest))))))))

    (testing "a removed entry leaves a hole the chain does not close"
      (let [holed (vec (concat [(nth es 0)] [(nth es 2)]))]
        (is (false? (:ok? (l/verify holed digest))))))))

(deftest an-empty-ledger-verifies-but-says-it-checked-nothing
  (let [r (l/verify [] digest)]
    (is (:ok? r))
    (is (= 0 (:entries r))
        "ok? alone would read as 'the ledger is sound' for a ledger that does not exist")))
