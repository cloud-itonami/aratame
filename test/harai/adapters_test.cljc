(ns harai.adapters-test
  "The translations from the producers that already exist in this workspace."
  (:require [clojure.test :refer [deftest is testing]]
            [harai.adapters :as a]))

(deftest a-threat-intelligence-record-keeps-its-own-confidence-scale
  (let [rec {"indicatorType" "sha256" "value" "AB" "confidencePermille" 850
             "tlp" "amber" "source" "abuse.ch" "lastSeen" "2026-08-01"}
        i (a/ti-record->indicator rec)]
    (is (= :sha256 (:indicator/type i)))
    (is (= 850 (:indicator/confidence-permille i)))
    (is (= :amber (:indicator/tlp i)))
    (is (= "abuse.ch" (:indicator/source-id i))))
  (testing "keyword keys — the same record after edn round-tripping"
    (is (= :domain (:indicator/type (a/ti-record->indicator
                                     {:indicatorType "domain" :value "evil.example"}))))))

(deftest a-yabai-malware-sample-fans-out-into-the-identifiers-it-names
  (let [inds (a/malware-sample->indicators
            {:sha256 "aa" :md5 "bb" :family "Shlayer"
             :c2_domains ["c2.example"] :c2_ips ["203.0.113.9"]})]
    (is (= 4 (count inds)))
    (is (= #{:sha256 :md5 :domain :ipv4} (set (map :indicator/type inds))))
    (testing "the hash outranks the infrastructure it was hosted on"
      (let [by-type (into {} (map (juxt :indicator/type :indicator/confidence-permille) inds))]
        (is (> (:sha256 by-type) (:domain by-type)))))))

(deftest an-absent-detection-count-is-not-zero-detections
  (is (nil? (a/malware-sample->detections {:sha256 "aa"})))
  (is (= 0 (a/malware-sample->detections {:vt_detection_rate 0})))
  (is (= 12 (a/malware-sample->detections {"vt_detection_rate" 12}))))

(deftest a-misogi-fact-becomes-a-subject-without-losing-what-it-knew
  (let [s (a/misogi-fact->subject {:path "/Users/t/Library/LaunchAgents/x.plist"
                                   :program "/tmp/x"
                                   :persistence :launch-agent-user
                                   :signature :unsigned})]
    (is (= :launch-agent-user (:subject/persistence s)))
    (is (= :unsigned (:subject/signature s)))
    (is (true? (:subject/hidden? s)))
    (is (some? (:subject/id s))))
  (testing "a fact with no signature reads as :unknown, never as trusted"
    (is (= :unknown (:subject/signature (a/misogi-fact->subject {:path "/x"}))))))
