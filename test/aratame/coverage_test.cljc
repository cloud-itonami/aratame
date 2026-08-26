(ns aratame.coverage-test
  "A sweep that examined nothing must not be able to say it found nothing."
  (:require [clojure.test :refer [deftest is testing]]
            [aratame.coverage :as cov]))

(defn v [value] {:verdict/value value})

(deftest an-empty-sweep-is-refused-not-clean
  (let [s (cov/summarize [] {})]
    (is (= :refused (:coverage/answer s)))
    (is (= :coverage/no-evidence (:coverage/reason s)))
    (is (= 2 (cov/exit-code s)))
    (is (= "SCANNED\t0" (cov/evidence-line s))))
  (testing "control — one clean verdict is a complete sweep with exit 0"
    (let [s (cov/summarize [(v :clean)] {})]
      (is (= :complete (:coverage/answer s)))
      (is (= 0 (cov/exit-code s)))
      (is (= "SCANNED\t1" (cov/evidence-line s))))))

(deftest an-unjudged-subject-makes-the-sweep-partial-and-the-exit-code-two
  (let [s (cov/summarize [(v :clean) (v :unmeasured)] {})]
    (is (= :partial (:coverage/answer s)))
    (is (= 2 (cov/exit-code s))))
  (testing "control — replacing the unmeasured subject with a clean one gives exit 0"
    (is (= 0 (cov/exit-code (cov/summarize [(v :clean) (v :clean)] {}))))))

(deftest finding-something-outranks-not-knowing
  (is (= 1 (cov/exit-code (cov/summarize [(v :malicious) (v :unmeasured)] {}))))
  (is (= :malicious (:coverage/highest (cov/summarize [(v :clean) (v :malicious)] {})))))

(deftest the-offered-count-survives-so-a-shortfall-is-visible
  (let [s (cov/summarize [(v :clean)] {:subjects-offered 400})]
    (is (= 1 (:coverage/scanned s)))
    (is (= 400 (:coverage/offered s)))))
